"""
Módulo principal para execução do AO-Noki Sniffer.

Este módulo é executado quando o pacote é chamado como um script:
`python -m sniffer`
"""

import logging
import os
import signal
import sys
import threading
import time
from typing import Dict, Any, List, Optional

from sniffer.config import CONFIG, WS_DEFAULT_HOST, WS_DEFAULT_PORT
from sniffer.platform import get_platform, is_platform_supported, get_system_info
from sniffer.server import WebSocketServer
from sniffer.utils.cli import parse_and_process_args

logger = logging.getLogger("sniffer")


class SnifferApp:
    """
    Aplicação principal do AO-Noki Sniffer.
    
    Esta classe é responsável por gerenciar a aplicação, incluindo
    inicialização, configuração e ciclo de vida dos componentes.
    """
    
    def __init__(self):
        """Inicializa a aplicação."""
        self.running = False
        self.websocket_server: Optional[WebSocketServer] = None
        self.capture_thread: Optional[threading.Thread] = None
        
        # Signal handlers para encerramento limpo
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Verificar plataforma
        self.platform = get_platform()
        self.system_info = get_system_info()
        
        if not is_platform_supported():
            logger.error(f"Plataforma não suportada: {self.platform}")
            sys.exit(1)
        
        logger.info(f"Plataforma detectada: {self.platform}")
        logger.debug(f"Informações do sistema: {self.system_info}")
    
    def _signal_handler(self, sig, frame):
        """
        Manipulador de sinais para encerramento limpo.
        
        Args:
            sig: Sinal recebido
            frame: Frame atual
        """
        logger.info(f"Sinal recebido: {sig}")
        self.shutdown()
    
    def start(self, mode: str = "default", args: Any = None):
        """
        Inicia a aplicação no modo especificado.
        
        Args:
            mode: Modo de execução (default, console, service)
            args: Argumentos de linha de comando
        """
        if self.running:
            logger.warning("A aplicação já está em execução")
            return
        
        logger.info(f"Iniciando AO-Noki Sniffer no modo: {mode}")
        
        # Garantir que o arquivo de configuração seja criado
        if not os.path.exists(CONFIG.config_file):
            logger.info("Criando arquivo de configuração padrão")
            CONFIG.save()
            
        # Inicializar WebSocket server
        ws_host = getattr(args, "host", CONFIG.get("server", "host", WS_DEFAULT_HOST))
        ws_port = getattr(args, "port", CONFIG.get("server", "port", WS_DEFAULT_PORT))
        self.websocket_server = WebSocketServer(host=ws_host, port=ws_port)
        
        if not self.websocket_server.start():
            logger.error("Falha ao iniciar o servidor WebSocket")
            return
        
        logger.info(f"Servidor WebSocket iniciado em {ws_host}:{ws_port}")
        
        # Iniciar modo de captura de pacotes
        # TODO: Implementar captura de pacotes
        
        self.running = True
        
        # Execução específica para cada modo
        if mode == "console":
            self._run_console_mode()
        elif mode == "service":
            self._run_service_mode()
        else:
            self._run_default_mode()
    
    def _run_console_mode(self):
        """Executa a aplicação no modo console."""
        logger.info("Executando em modo console")
        logger.info("Pressione Ctrl+C para encerrar")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Interrupção de teclado recebida")
            self.shutdown()
    
    def _run_service_mode(self):
        """Executa a aplicação no modo serviço."""
        logger.info("Executando em modo serviço")
        
        # Em modo serviço, simplesmente aguardamos sinais externos
        while self.running:
            time.sleep(1)
    
    def _run_default_mode(self):
        """Executa a aplicação no modo padrão (GUI)."""
        logger.info("Executando em modo padrão")
        
        # No modo padrão, iniciamos a interface gráfica
        # TODO: Implementar interface gráfica
        
        # Por enquanto, executamos como console
        self._run_console_mode()
    
    def shutdown(self):
        """Encerra a aplicação de forma limpa."""
        if not self.running:
            return
        
        logger.info("Encerrando AO-Noki Sniffer...")
        
        # Parar servidor WebSocket
        if self.websocket_server:
            logger.info("Parando servidor WebSocket...")
            self.websocket_server.stop()
            self.websocket_server = None
        
        # Parar thread de captura
        if self.capture_thread and self.capture_thread.is_alive():
            logger.info("Parando captura de pacotes...")
            # TODO: Implementar parada da captura
        
        self.running = False
        logger.info("AO-Noki Sniffer encerrado")


def main():
    """Função principal para execução do AO-Noki Sniffer."""
    # Processar argumentos de linha de comando
    result, args = parse_and_process_args()
    
    # Configurar nível de log
    if getattr(args, "debug", False):
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Modo de depuração ativado")
    
    # Verificar se deve encerrar após processamento de argumentos
    if result.get("exit", False):
        logger.info(result.get("message", ""))
        sys.exit(result.get("exit_code", 0))
    
    # Iniciar aplicação no modo especificado
    app = SnifferApp()
    app.start(mode=result.get("mode", "default"), args=args)


if __name__ == "__main__":
    main() 