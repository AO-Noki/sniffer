"""
Testes para o módulo de decodificação do protocolo Photon.

Este módulo testa a funcionalidade do decodificador do protocolo Photon usado
para capturar e analisar o tráfego do jogo Albion Online.
"""

import unittest
import sys
import os
import struct
from unittest import mock
from typing import Dict, Any

# Adicionar o diretório raiz ao path para importação
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sniffer.photon import (
    PhotonHeader, 
    PhotonCommand, 
    PhotonMessage, 
    PhotonMessageType,
    PhotonCommandType
)
from sniffer.photon.decoder import (
    AlbionDecoder,
    PhotonCaptureHandler,
    start_albion_capture,
    stop_albion_capture
)

class TestPhotonHeader(unittest.TestCase):
    """Testes para a classe PhotonHeader."""
    
    def test_header_from_bytes(self):
        """Testa a decodificação de cabeçalho a partir de bytes."""
        # Criar dados de cabeçalho simulados
        # Formato: HBBIi (peer_id, crc_flag, cmd_count, timestamp, challenge)
        header_data = struct.pack("<HBBIi", 
                                  42,       # peer_id
                                  1,        # crc_enabled
                                  3,        # command_count
                                  12345678, # timestamp
                                  87654321  # challenge
                                 )
        
        # Decodificar o cabeçalho
        header = PhotonHeader.from_bytes(header_data)
        
        # Verificar os campos
        self.assertIsNotNone(header)
        self.assertEqual(header.peer_id, 42)
        self.assertTrue(header.crc_enabled)
        self.assertEqual(header.command_count, 3)
        self.assertEqual(header.timestamp, 12345678)
        self.assertEqual(header.challenge, 87654321)
    
    def test_header_invalid_data(self):
        """Testa a decodificação com dados inválidos."""
        # Dados muito curtos
        invalid_data = b"\x01\x02\x03"
        header = PhotonHeader.from_bytes(invalid_data)
        self.assertIsNone(header)

class TestPhotonCommand(unittest.TestCase):
    """Testes para a classe PhotonCommand."""
    
    def test_command_from_bytes_reliable(self):
        """Testa a decodificação de comando confiável a partir de bytes."""
        # Criar dados de comando confiável simulados
        # Formato: BBBBI (cmd_type, channel_id, flags, reserved, length)
        # Seguido pelo número de sequência (I) e dados
        command_type = PhotonCommandType.SEND_RELIABLE
        channel_id = 0
        flags = 0
        reserved = 0
        data = b"TestData"
        sequence_number = 123
        
        # O length deve ser o tamanho do payload + 4 bytes do sequence_number
        data_length = 4 + len(data)
        
        command_data = struct.pack("<BBBBI", 
                                   command_type,  # command_type
                                   channel_id,    # channel_id
                                   flags,         # flags
                                   reserved,      # reserved
                                   data_length    # length
                                  )
        command_data += struct.pack("<I", sequence_number)  # sequence_number
        command_data += data  # payload
        
        # Decodificar o comando
        command, consumed = PhotonCommand.from_bytes(command_data)
        
        # Verificar os campos
        self.assertIsNotNone(command)
        self.assertEqual(command.command_type, command_type)
        self.assertEqual(command.channel_id, channel_id)
        self.assertEqual(command.flags, flags)
        self.assertEqual(command.sequence_number, sequence_number)
        self.assertEqual(command.data, data)
        self.assertEqual(consumed, 8 + data_length)  # 8 bytes header + length
    
    def test_command_invalid_data(self):
        """Testa a decodificação com dados inválidos."""
        # Dados muito curtos
        invalid_data = b"\x01\x02\x03"
        command, consumed = PhotonCommand.from_bytes(invalid_data)
        self.assertIsNone(command)
        self.assertEqual(consumed, 0)

class TestPhotonMessage(unittest.TestCase):
    """Testes para a classe PhotonMessage."""
    
    def test_message_from_bytes_event(self):
        """Testa a decodificação de mensagem de evento a partir de bytes."""
        # Criar dados de mensagem de evento simulados
        # Formato: byte (msg_type), byte (code), parâmetros
        msg_type = PhotonMessageType.EVENT_DATA
        code = 10  # Código de evento arbitrário
        
        # Parâmetros simples (hashtable com um par chave-valor)
        # 0x68 = hashtable, 0x01 = contagem, 0x01 = chave, 0x02 = tipo (byte), 0x42 = valor
        parameters = b"\x68\x01\x01\x02\x42"
        
        message_data = bytes([msg_type, code]) + parameters
        
        # Decodificar a mensagem
        message = PhotonMessage.from_bytes(message_data)
        
        # Verificar os campos
        self.assertIsNotNone(message)
        self.assertEqual(message.msg_type, msg_type)
        self.assertEqual(message.code, code)
        self.assertIn(1, message.parameters)  # A chave 1 deve existir
        self.assertEqual(message.parameters[1], 0x42)  # O valor deve ser 0x42
    
    def test_message_from_bytes_operation(self):
        """Testa a decodificação de mensagem de operação a partir de bytes."""
        # Criar dados de mensagem de operação simulados
        msg_type = PhotonMessageType.OPERATION_REQUEST
        code = 5  # Código de operação arbitrário
        
        # Parâmetro simples (valor do tipo byte)
        parameters = b"\x02\x37"  # Tipo byte, valor 0x37
        
        message_data = bytes([msg_type, code]) + parameters
        
        # Decodificar a mensagem
        message = PhotonMessage.from_bytes(message_data)
        
        # Verificar os campos
        self.assertIsNotNone(message)
        self.assertEqual(message.msg_type, msg_type)
        self.assertEqual(message.code, code)
        self.assertIn(1, message.parameters)  # A chave 1 deve existir (padrão)
        self.assertEqual(message.parameters[1], 0x37)  # O valor deve ser 0x37
    
    def test_message_invalid_data(self):
        """Testa a decodificação com dados inválidos."""
        # Dados muito curtos
        invalid_data = b"\x01"
        message = PhotonMessage.from_bytes(invalid_data)
        self.assertIsNone(message)

class TestAlbionDecoder(unittest.TestCase):
    """Testes para a classe AlbionDecoder."""
    
    def setUp(self):
        """Configuração para os testes."""
        self.decoder = AlbionDecoder()
        self.test_callback_called = False
        self.callback_data = None
    
    def test_callback_operation(self):
        """Testa o registro e execução de callback para operações."""
        # Função de callback para o teste
        def test_callback(data):
            self.test_callback_called = True
            self.callback_data = data
        
        # Registrar o callback
        self.decoder.add_callback("operation", test_callback)
        
        # Criar dados de operação simulados
        operation_data = {
            "type": "operation_request",
            "OperationCode": 5,
            "Parameters": {1: 123, 2: "test"},
            "timestamp": 12345678
        }
        
        # Acionar o decodificador
        result = self.decoder.decode_operation(operation_data)
        
        # Verificar se o callback foi chamado
        self.assertTrue(self.test_callback_called)
        self.assertIsNotNone(self.callback_data)
        
        # Verificar se o resultado foi processado corretamente
        self.assertIn("OperationName", result)

class TestPhotonCaptureHandler(unittest.TestCase):
    """Testes para a classe PhotonCaptureHandler."""
    
    def setUp(self):
        """Configuração para os testes."""
        self.handler = PhotonCaptureHandler()
    
    def test_enable_disable(self):
        """Testa a ativação e desativação do handler."""
        # Inicialmente ativo
        self.assertTrue(self.handler.enabled)
        
        # Desativar
        self.handler.disable()
        self.assertFalse(self.handler.enabled)
        
        # Ativar novamente
        self.handler.enable()
        self.assertTrue(self.handler.enabled)
    
    def test_debug_mode(self):
        """Testa a ativação e desativação do modo de depuração."""
        # Inicialmente desativado
        self.assertFalse(self.handler.debug_mode)
        
        # Ativar
        self.handler.enable_debug()
        self.assertTrue(self.handler.debug_mode)
        
        # Desativar novamente
        self.handler.disable_debug()
        self.assertFalse(self.handler.debug_mode)
    
    def test_packet_processing(self):
        """Testa o processamento básico de pacotes."""
        # Pacote não UDP
        non_udp_packet = {
            "protocol": "TCP",
            "src_ip": "192.168.1.1",
            "src_port": 5056,
            "dst_ip": "192.168.1.2",
            "dst_port": 5056,
            "payload": b"\x00\x01\x02\x03"
        }
        
        # O handler não deve processar pacotes não UDP
        initial_count = self.handler.stats["total_packets"]
        self.handler.handle_packet(non_udp_packet)
        self.assertEqual(self.handler.stats["total_packets"], initial_count + 1)
        self.assertEqual(self.handler.stats["valid_packets"], 0)
        
        # Pacote UDP, mas não na porta correta
        wrong_port_packet = {
            "protocol": "UDP",
            "src_ip": "192.168.1.1",
            "src_port": 1234,  # Porta errada
            "dst_ip": "192.168.1.2",
            "dst_port": 4321,  # Porta errada
            "payload": b"\x00\x01\x02\x03"
        }
        
        # O handler não deve processar pacotes em portas não monitoradas
        self.handler.handle_packet(wrong_port_packet)
        self.assertEqual(self.handler.stats["valid_packets"], 0)
    
    def test_capture_handler_functions(self):
        """Testa as funções auxiliares do módulo."""
        # Testes para a ativação e desativação diretamente no handler
        handler = self.handler
        self.assertTrue(handler.enabled)
        
        handler.disable()
        self.assertFalse(handler.enabled)
        
        handler.enable()
        self.assertTrue(handler.enabled)
        
        # Também testar as funções relacionadas ao modo de depuração
        self.assertFalse(handler.debug_mode)
        handler.enable_debug()
        self.assertTrue(handler.debug_mode)
        handler.disable_debug()
        self.assertFalse(handler.debug_mode)
        
        # Verificar limpeza de estatísticas
        handler.stats["total_packets"] = 100
        handler.clear_stats()
        self.assertEqual(handler.stats["total_packets"], 0)

if __name__ == "__main__":
    unittest.main() 