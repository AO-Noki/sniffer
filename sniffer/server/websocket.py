"""
Módulo de servidor WebSocket para o AO-Noki Sniffer.

Este módulo implementa um servidor WebSocket utilizando asyncio e websockets 
para distribuir os dados de tráfego em tempo real para aplicações cliente.
"""

import asyncio
import json
import logging
import os
import platform
import signal
import threading
import time
from typing import Dict, List, Any, Optional, Set, Callable

import websockets
# Importações condicionais para evitar erros do linter
try:
    from websockets.server import WebSocketServerProtocol, serve
except ImportError:
    # Para satisfazer o linter, definimos tipos stub
    WebSocketServerProtocol = object
    serve = object

from sniffer.config import CONFIG

# Configuração do logger
logger = logging.getLogger("sniffer.server.websocket")

# Valores padrão
DEFAULT_WS_HOST = "0.0.0.0"  # Alterar para 0.0.0.0 para disponibilizar em todos os dispositivos de rede
DEFAULT_WS_PORT = 8080  # Usar a porta padrão definida em config.py (WS_DEFAULT_PORT)


class WebSocketServer:
    """
    Implementação do servidor WebSocket para o AO-Noki Sniffer.
    
    Esta classe gerencia conexões de clientes e distribui dados de captura
    em tempo real usando WebSockets.
    """
    
    def __init__(self, host: Optional[str] = None, port: Optional[int] = None):
        """
        Inicializa o servidor WebSocket.
        
        Args:
            host: Host para o servidor (padrão: configuração ou 0.0.0.0)
            port: Porta para o servidor (padrão: configuração ou 8080)
        """
        # Usar as configurações do módulo config.py
        self.host = host or CONFIG.get("server", "host", DEFAULT_WS_HOST)
        self.port = port or CONFIG.get("server", "port", DEFAULT_WS_PORT)
        self.clients: Set[WebSocketServerProtocol] = set()
        self.server = None
        self.running = False
        self.lock = threading.Lock()
        self.server_thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        
        # Event loop dedicado para o servidor
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        
        # Status do sniffer e estatísticas
        self.status = {
            "active": False,
            "low_resource_mode": False,
            "connected_clients": 0,
            "packets_captured": 0,
            "photon_events": 0,
            "start_time": 0,
            "interface": "",
        }
        
        # Callbacks para eventos específicos
        self.callbacks: Dict[str, List[Callable]] = {
            "client_connected": [],
            "client_disconnected": [],
            "message_received": [],
        }
    
    async def _handler(self, websocket: WebSocketServerProtocol):
        """
        Manipula a conexão com um cliente WebSocket.
        
        Args:
            websocket: Conexão WebSocket do cliente
        """
        # Registrar o cliente
        self.clients.add(websocket)
        client_info = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
        logger.info(f"Cliente conectado: {client_info}")
        self.status["connected_clients"] = len(self.clients)
        
        # Informar aos callbacks sobre a nova conexão
        for callback in self.callbacks["client_connected"]:
            try:
                callback(client_info)
            except Exception as e:
                logger.error(f"Erro em callback de conexão: {e}")
        
        # Enviar o status atual para o novo cliente
        await self._send_status(websocket)
        
        try:
            # Lidar com mensagens do cliente
            async for message in websocket:
                try:
                    data = json.loads(message)
                    logger.debug(f"Mensagem recebida de {client_info}: {data}")
                    
                    # Informar aos callbacks sobre a mensagem recebida
                    for callback in self.callbacks["message_received"]:
                        try:
                            callback(client_info, data)
                        except Exception as e:
                            logger.error(f"Erro em callback de mensagem: {e}")
                    
                    # Processar comandos do cliente
                    if "command" in data:
                        await self._process_command(websocket, data)
                except json.JSONDecodeError:
                    logger.warning(f"Mensagem inválida recebida de {client_info}")
        except websockets.exceptions.ConnectionClosed as e:
            logger.info(f"Conexão fechada com {client_info}: {e}")
        finally:
            # Remover o cliente
            self.clients.remove(websocket)
            logger.info(f"Cliente desconectado: {client_info}")
            self.status["connected_clients"] = len(self.clients)
            
            # Informar aos callbacks sobre a desconexão
            for callback in self.callbacks["client_disconnected"]:
                try:
                    callback(client_info)
                except Exception as e:
                    logger.error(f"Erro em callback de desconexão: {e}")
    
    async def _process_command(self, websocket: WebSocketServerProtocol, data: Dict[str, Any]):
        """
        Processa comandos recebidos de clientes.
        
        Args:
            websocket: Conexão WebSocket do cliente
            data: Dados do comando recebido
        """
        command = data.get("command", "")
        client_info = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}"
        
        if command == "get_status":
            await self._send_status(websocket)
        elif command == "get_interfaces":
            # Implementar obtenção de interfaces
            pass
        else:
            logger.warning(f"Comando desconhecido de {client_info}: {command}")
            await websocket.send(json.dumps({
                "type": "error",
                "message": f"Comando desconhecido: {command}"
            }))
    
    async def _send_status(self, websocket: WebSocketServerProtocol):
        """
        Envia o status atual para um cliente específico.
        
        Args:
            websocket: Conexão WebSocket do cliente
        """
        await websocket.send(json.dumps({
            "type": "status",
            "data": self.status
        }))
    
    async def broadcast(self, message_type: str, data: Dict[str, Any]):
        """
        Envia dados para todos os clientes conectados.
        
        Args:
            message_type: Tipo da mensagem (status, packet, event, etc.)
            data: Dados a serem enviados
        """
        if not self.clients:
            return
        
        message = json.dumps({
            "type": message_type,
            "data": data
        })
        
        # Usando asyncio.gather para enviar para todos os clientes simultaneamente
        await asyncio.gather(
            *[client.send(message) for client in self.clients],
            return_exceptions=True
        )
    
    async def update_status(self, new_status: Dict[str, Any]):
        """
        Atualiza o status e envia para todos os clientes.
        
        Args:
            new_status: Novos dados de status
        """
        self.status.update(new_status)
        await self.broadcast("status", self.status)
    
    async def send_packet(self, packet_data: Dict[str, Any]):
        """
        Envia dados de um pacote capturado para todos os clientes.
        
        Args:
            packet_data: Dados do pacote capturado
        """
        await self.broadcast("packet", packet_data)
        self.status["packets_captured"] += 1
    
    async def send_event(self, event_data: Dict[str, Any]):
        """
        Envia dados de um evento do Photon para todos os clientes.
        
        Args:
            event_data: Dados do evento do Photon
        """
        await self.broadcast("event", event_data)
        self.status["photon_events"] += 1
    
    async def _server_main(self):
        """
        Função principal do servidor WebSocket.
        """
        logger.info(f"Iniciando servidor WebSocket em {self.host}:{self.port}")
        
        try:
            # Configurar manipulação de sinal apenas em sistemas não-Windows
            # O Windows não suporta add_signal_handler com ProactorEventLoop
            if platform.system().lower() != "windows":
                loop = asyncio.get_running_loop()
                for sig in (signal.SIGINT, signal.SIGTERM):
                    loop.add_signal_handler(
                        sig,
                        lambda: asyncio.create_task(self.stop_server())
                    )
            
            # Iniciar o servidor WebSocket
            async with serve(self._handler, self.host, self.port):
                self.running = True
                logger.info(f"Servidor WebSocket rodando em ws://{self.host}:{self.port}")
                
                # Manter o servidor rodando até ser interrompido
                while self.running and not self.stop_event.is_set():
                    await asyncio.sleep(0.5)
                
                logger.info("Servidor WebSocket finalizando loop principal")
        except Exception as e:
            logger.error(f"Erro no servidor WebSocket: {e}")
            self.running = False
    
    def start(self):
        """
        Inicia o servidor WebSocket em uma thread separada.
        """
        with self.lock:
            if self.server_thread and self.server_thread.is_alive():
                logger.warning("O servidor WebSocket já está em execução")
                return False
            
            # Limpar evento de parada
            self.stop_event.clear()
            
            # Criar novo loop de eventos
            self.loop = asyncio.new_event_loop()
            
            # Função para executar o servidor no loop de eventos
            def run_server():
                asyncio.set_event_loop(self.loop)
                try:
                    if self.loop:
                        self.loop.run_until_complete(self._server_main())
                        logger.debug("Loop do servidor finalizado")
                        self.loop.close()
                        logger.debug("Loop do servidor fechado")
                except Exception as e:
                    logger.error(f"Erro na thread do servidor: {e}")
                finally:
                    self.running = False
                    logger.info("Thread do servidor finalizada")
            
            # Iniciar o servidor em uma thread
            self.server_thread = threading.Thread(target=run_server, daemon=True)
            self.server_thread.start()
            
            # Aguardar servidor iniciar
            start_time = time.time()
            timeout = 5.0  # 5 segundos de timeout
            
            while not self.running:
                if time.time() - start_time > timeout:
                    logger.error("Timeout ao iniciar o servidor WebSocket")
                    return False
                
                if not self.server_thread.is_alive():
                    logger.error("Thread do servidor terminou prematuramente")
                    return False
                
                time.sleep(0.1)
            
            logger.info("Thread do servidor WebSocket iniciada")
            return True
    
    async def stop_server(self):
        """
        Para o servidor WebSocket de forma limpa.
        """
        logger.info("Parando servidor WebSocket...")
        
        # Sinalizar que o servidor deve parar
        self.stop_event.set()
        
        # Enviar mensagem de desconexão para todos os clientes
        if self.clients:
            try:
                await self.broadcast("system", {
                    "message": "Servidor está sendo desligado"
                })
            except Exception as e:
                logger.error(f"Erro ao notificar clientes sobre desligamento: {e}")
        
        # Fechar todas as conexões
        if self.clients:
            await asyncio.gather(
                *[client.close() for client in self.clients],
                return_exceptions=True
            )
            self.clients.clear()
        
        self.running = False
        logger.info("Servidor WebSocket parado")
    
    def stop(self):
        """
        Para o servidor WebSocket.
        """
        with self.lock:
            if not self.loop or not self.server_thread or not self.server_thread.is_alive():
                logger.warning("O servidor WebSocket não está em execução")
                return False
            
            # Sinalizar que o servidor deve parar
            self.stop_event.set()
            
            # Programar tarefa para parar o servidor
            try:
                asyncio.run_coroutine_threadsafe(self.stop_server(), self.loop)
            except Exception as e:
                logger.error(f"Erro ao programar parada do servidor: {e}")
            
            # Aguardar a thread terminar (com timeout)
            self.server_thread.join(timeout=5.0)
            
            # Verificar se a thread terminou
            if self.server_thread.is_alive():
                logger.warning("A thread do servidor WebSocket não terminou no tempo esperado")
                return False
            
            self.server_thread = None
            self.loop = None
            
            logger.info("Servidor WebSocket parado com sucesso")
            return True
    
    def is_running(self) -> bool:
        """
        Verifica se o servidor está em execução.
        
        Returns:
            True se o servidor estiver rodando, False caso contrário
        """
        with self.lock:
            has_thread = self.server_thread is not None
            thread_alive = self.server_thread is not None and self.server_thread.is_alive()
            
            # Para garantir uma resposta precisa, verificamos o estado da thread
            # e o flag de status interno
            if has_thread and thread_alive:
                # Verificar se o servidor já foi inicializado
                logger.debug(f"Status do servidor: thread={has_thread}, "
                            f"thread_alive={thread_alive}, running={self.running}")
                
                return self.running
            
            return False
    
    def register_callback(self, event_type: str, callback: Callable):
        """
        Registra um callback para um tipo de evento específico.
        
        Args:
            event_type: Tipo de evento (client_connected, client_disconnected, message_received)
            callback: Função de callback a ser chamada quando o evento ocorrer
        
        Returns:
            True se o callback foi registrado, False caso contrário
        """
        if event_type not in self.callbacks:
            logger.error(f"Tipo de evento inválido: {event_type}")
            return False
        
        self.callbacks[event_type].append(callback)
        return True
    
    def unregister_callback(self, event_type: str, callback: Callable) -> bool:
        """
        Remove um callback registrado.
        
        Args:
            event_type: Tipo de evento
            callback: Função de callback a ser removida
        
        Returns:
            True se o callback foi removido, False caso contrário
        """
        if event_type not in self.callbacks:
            logger.error(f"Tipo de evento inválido: {event_type}")
            return False
        
        try:
            self.callbacks[event_type].remove(callback)
            return True
        except ValueError:
            logger.warning(f"Callback não encontrado para o evento {event_type}")
            return False


# Função para criar uma instância do servidor com configurações padrão
def create_server(host: Optional[str] = None, port: Optional[int] = None) -> WebSocketServer:
    """
    Cria uma instância do servidor WebSocket com configurações padrão.
    
    Args:
        host: Host para o servidor (padrão: configuração ou 0.0.0.0)
        port: Porta para o servidor (padrão: configuração ou 8080)
    
    Returns:
        Instância do servidor WebSocket
    """
    return WebSocketServer(host, port) 