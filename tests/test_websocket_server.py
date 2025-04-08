"""
Testes para o módulo server.websocket.

Este módulo contém testes para o servidor WebSocket do AO-Noki Sniffer.
"""

import asyncio
import json
import logging
import threading
import time
import unittest
from typing import Dict, Any, List
from unittest.mock import MagicMock, patch

import websockets

from sniffer.server.websocket import WebSocketServer, create_server


# Configuração de logging para testes
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("test_websocket")


class TestWebSocketServer(unittest.TestCase):
    """Testes para o servidor WebSocket."""
    
    def setUp(self):
        """Configuração para cada teste."""
        # Usar uma porta diferente para cada teste para evitar conflitos
        self.port = 8765
        self.host = "127.0.0.1"
        self.server = WebSocketServer(host=self.host, port=self.port)
        
        # Mock para callbacks
        self.client_connected_mock = MagicMock()
        self.client_disconnected_mock = MagicMock()
        self.message_received_mock = MagicMock()
        
        # Registrar callbacks mock
        self.server.register_callback("client_connected", self.client_connected_mock)
        self.server.register_callback("client_disconnected", self.client_disconnected_mock)
        self.server.register_callback("message_received", self.message_received_mock)
    
    def tearDown(self):
        """Limpeza após cada teste."""
        if self.server.is_running():
            self.server.stop()
    
    def test_server_creation(self):
        """Testa a criação do servidor."""
        self.assertEqual(self.server.host, self.host)
        self.assertEqual(self.server.port, self.port)
        self.assertFalse(self.server.is_running())
    
    def test_create_server_function(self):
        """Testa a função create_server."""
        server = create_server(host="localhost", port=8888)
        self.assertEqual(server.host, "localhost")
        self.assertEqual(server.port, 8888)
    
    def test_start_stop_server(self):
        """Testa iniciar e parar o servidor."""
        # Iniciar o servidor
        result = self.server.start()
        self.assertTrue(result)
        
        # Esperar um pouco para garantir que o servidor está rodando
        time.sleep(2.0)
        
        # Verificar se está em execução
        self.assertTrue(self.server.is_running())
        
        # Parar o servidor
        result = self.server.stop()
        self.assertTrue(result)
        
        # Esperar um pouco para garantir que o servidor parou
        time.sleep(0.5)
        
        # Verificar se está parado
        self.assertFalse(self.server.is_running())
    
    def test_register_unregister_callback(self):
        """Testa registrar e remover callbacks."""
        # Criar callback de teste
        test_callback = lambda x: None
        
        # Registrar callback
        result = self.server.register_callback("client_connected", test_callback)
        self.assertTrue(result)
        
        # Verificar se callback foi registrado
        self.assertIn(test_callback, self.server.callbacks["client_connected"])
        
        # Remover callback
        result = self.server.unregister_callback("client_connected", test_callback)
        self.assertTrue(result)
        
        # Verificar se callback foi removido
        self.assertNotIn(test_callback, self.server.callbacks["client_connected"])
        
        # Testar com tipo de evento inválido
        result = self.server.register_callback("invalid_event", test_callback)
        self.assertFalse(result)
        
        result = self.server.unregister_callback("invalid_event", test_callback)
        self.assertFalse(result)
        
        # Testar remover callback não registrado
        result = self.server.unregister_callback("client_connected", test_callback)
        self.assertFalse(result)


# Testes que precisam de um cliente WebSocket
@unittest.skipIf(True, "Testes de integração desativados por padrão")
class TestWebSocketServerWithClient(unittest.TestCase):
    """Testes de integração para o servidor WebSocket com cliente real."""
    
    def setUp(self):
        """Configuração para cada teste."""
        self.port = 8766
        self.host = "127.0.0.1"
        self.uri = f"ws://{self.host}:{self.port}"
        self.server = WebSocketServer(host=self.host, port=self.port)
        self.server.start()
        
        # Esperar um pouco para garantir que o servidor está rodando
        time.sleep(0.5)
        
        # Armazenar mensagens recebidas pelo cliente
        self.received_messages: List[Dict[str, Any]] = []
    
    def tearDown(self):
        """Limpeza após cada teste."""
        if self.server.is_running():
            self.server.stop()
    
    async def _connect_client(self):
        """Conecta um cliente WebSocket ao servidor."""
        async with websockets.connect(self.uri) as websocket:
            # Receber a mensagem de status inicial
            response = await websocket.recv()
            data = json.loads(response)
            self.received_messages.append(data)
            
            # Enviar um comando de status
            await websocket.send(json.dumps({"command": "get_status"}))
            
            # Receber resposta
            response = await websocket.recv()
            data = json.loads(response)
            self.received_messages.append(data)
            
            # Enviar comando inválido
            await websocket.send(json.dumps({"command": "unknown_command"}))
            
            # Receber resposta de erro
            response = await websocket.recv()
            data = json.loads(response)
            self.received_messages.append(data)
            
            # Aguardar um pouco antes de fechar
            await asyncio.sleep(0.5)
    
    def test_client_connection(self):
        """Testa conexão de cliente e troca de mensagens."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            # Executar o cliente
            loop.run_until_complete(self._connect_client())
            
            # Verificar mensagens recebidas
            self.assertEqual(len(self.received_messages), 3)
            
            # Verificar primeira mensagem (status inicial)
            self.assertEqual(self.received_messages[0]["type"], "status")
            
            # Verificar segunda mensagem (resposta ao comando get_status)
            self.assertEqual(self.received_messages[1]["type"], "status")
            
            # Verificar terceira mensagem (erro de comando desconhecido)
            self.assertEqual(self.received_messages[2]["type"], "error")
            self.assertIn("Comando desconhecido", self.received_messages[2]["message"])
        finally:
            loop.close()


if __name__ == "__main__":
    unittest.main() 