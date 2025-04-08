"""
Pacote para processamento e análise de tráfego do protocolo Photon.

Este pacote contém módulos para:
- Captura e decodificação de pacotes do protocolo Photon
- Processamento de eventos específicos do jogo Albion Online
- Análise e extração de dados de jogadores, itens e mercado
"""

# Bibliotecas padrão
import struct
import time
import collections
import logging
from typing import Dict, List, Optional, Any, Tuple, Set, Union, Callable

# Expor componentes principais
from .decoder import (
    AlbionOperationCode,
    AlbionEventCode,
    AlbionEventParameters,
    AlbionDecoder,
    PhotonCaptureHandler
)

from .events import (
    EventProcessor,
    PlayerEventProcessor,
    CombatEventProcessor,
    ItemEventProcessor,
    EconomyEventProcessor,
    EventManager,
    process_albion_event,
    add_event_callback,
    enable_event_processing,
    disable_event_processing,
    event_manager
)

# Configuração do logger do pacote
logger = logging.getLogger("sniffer.photon")
logger.setLevel(logging.INFO)

# Versão do pacote
__version__ = "0.1.0"

# Constantes para tipos de comandos Photon
class PhotonCommandType:
    ACKNOWLEDGE = 1
    CONNECT = 2
    VERIFY_CONNECT = 3
    DISCONNECT = 4
    PING = 5
    SEND_RELIABLE = 6
    SEND_UNRELIABLE = 7
    SEND_RELIABLE_FRAGMENT = 8

# Constantes para tipos de mensagens Photon
class PhotonMessageType:
    OPERATION_REQUEST = 2
    OPERATION_RESPONSE = 3
    EVENT_DATA = 4
    
# Classes para representar os componentes do protocolo Photon
class PhotonHeader:
    """Representa o cabeçalho de um pacote Photon."""
    
    def __init__(self, peer_id: int, crc_enabled: bool, command_count: int, 
                 timestamp: int, challenge: int):
        """
        Inicializa um cabeçalho Photon.
        
        Args:
            peer_id: ID do peer na sessão
            crc_enabled: Flag indicando se CRC está habilitado
            command_count: Número de comandos no pacote
            timestamp: Timestamp do pacote
            challenge: Valor de desafio para autenticação
        """
        self.peer_id = peer_id
        self.crc_enabled = crc_enabled
        self.command_count = command_count
        self.timestamp = timestamp
        self.challenge = challenge
    
    @classmethod
    def from_bytes(cls, data: bytes) -> Optional['PhotonHeader']:
        """
        Decodifica um cabeçalho Photon a partir de bytes.
        
        Args:
            data: Bytes contendo o cabeçalho
            
        Returns:
            Objeto PhotonHeader ou None se a decodificação falhar
        """
        if len(data) < 12:  # Cabeçalho Photon tem 12 bytes
            logger.warning(f"Dados insuficientes para cabeçalho Photon: {len(data)} bytes")
            return None
        
        try:
            # Formato: HBBIi (short, byte, byte, uint, int)
            peer_id, crc_flag, cmd_count, timestamp, challenge = struct.unpack("<HBBIi", data[:12])
            return cls(
                peer_id=peer_id,
                crc_enabled=bool(crc_flag & 0x01),
                command_count=cmd_count,
                timestamp=timestamp,
                challenge=challenge
            )
        except struct.error as e:
            logger.error(f"Erro ao decodificar cabeçalho Photon: {e}")
            return None
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Converte o cabeçalho para um dicionário.
        
        Returns:
            Dicionário com os campos do cabeçalho
        """
        return {
            "peer_id": self.peer_id,
            "crc_enabled": self.crc_enabled,
            "command_count": self.command_count,
            "timestamp": self.timestamp,
            "challenge": self.challenge
        }

class PhotonCommand:
    """Representa um comando Photon."""
    
    def __init__(self, command_type: int, channel_id: int, flags: int, 
                 reserved: int, length: int, sequence_number: int, data: bytes):
        """
        Inicializa um comando Photon.
        
        Args:
            command_type: Tipo do comando
            channel_id: Canal de comunicação
            flags: Flags de controle
            reserved: Byte reservado
            length: Comprimento do comando
            sequence_number: Número de sequência para comandos confiáveis
            data: Dados do comando
        """
        self.command_type = command_type
        self.channel_id = channel_id
        self.flags = flags
        self.reserved = reserved
        self.length = length
        self.sequence_number = sequence_number
        self.data = data
    
    @classmethod
    def from_bytes(cls, data: bytes) -> Tuple[Optional['PhotonCommand'], int]:
        """
        Decodifica um comando Photon a partir de bytes.
        
        Args:
            data: Bytes contendo o comando
            
        Returns:
            Tupla (objeto PhotonCommand, bytes consumidos) ou (None, 0) se falhar
        """
        if len(data) < 12:  # Cabeçalho do comando tem pelo menos 12 bytes
            logger.warning(f"Dados insuficientes para comando Photon: {len(data)} bytes")
            return None, 0
        
        try:
            # Formato: BBBBI (byte, byte, byte, byte, uint, uint)
            cmd_type, channel_id, flags, reserved, length = struct.unpack("<BBBBI", data[:8])
            
            # Verificar se temos dados suficientes
            if len(data) < 8 + length:
                logger.warning(f"Dados truncados para comando Photon: {len(data)} bytes, esperados {8 + length}")
                return None, 0
            
            sequence_number = 0
            command_data = b""
            
            # Processar o restante conforme o tipo de comando
            if cmd_type in [PhotonCommandType.SEND_RELIABLE, 
                          PhotonCommandType.SEND_RELIABLE_FRAGMENT]:
                # Esses comandos têm um número de sequência confiável
                if len(data) < 12:
                    logger.warning("Dados insuficientes para comando confiável")
                    return None, 0
                
                sequence_number = struct.unpack("<I", data[8:12])[0]
                command_data = data[12:8+length]
                
                return cls(
                    command_type=cmd_type,
                    channel_id=channel_id,
                    flags=flags,
                    reserved=reserved,
                    length=length,
                    sequence_number=sequence_number,
                    data=command_data
                ), 8 + length
            
            else:
                # Outros comandos não têm número de sequência
                command_data = data[8:8+length]
                
                return cls(
                    command_type=cmd_type,
                    channel_id=channel_id,
                    flags=flags,
                    reserved=reserved,
                    length=length,
                    sequence_number=0,
                    data=command_data
                ), 8 + length
                
        except struct.error as e:
            logger.error(f"Erro ao decodificar comando Photon: {e}")
            return None, 0

class PhotonMessage:
    """Representa uma mensagem do protocolo Photon."""
    
    def __init__(self, msg_type: int, code: int, parameters: Dict, return_code: int = 0, 
                 debug_message: str = ""):
        """
        Inicializa uma mensagem Photon.
        
        Args:
            msg_type: Tipo da mensagem (operation, response, event)
            code: Código da operação ou evento
            parameters: Parâmetros da mensagem
            return_code: Código de retorno (para respostas)
            debug_message: Mensagem de depuração (para respostas)
        """
        self.msg_type = msg_type
        self.code = code
        self.parameters = parameters
        self.return_code = return_code
        self.debug_message = debug_message
    
    @classmethod
    def from_bytes(cls, data: bytes) -> Optional['PhotonMessage']:
        """
        Decodifica uma mensagem Photon a partir de bytes.
        
        Args:
            data: Bytes contendo a mensagem
            
        Returns:
            Objeto PhotonMessage ou None se a decodificação falhar
        """
        if len(data) < 2:  # Pelo menos o tipo da mensagem é necessário
            logger.warning(f"Dados insuficientes para mensagem Photon: {len(data)} bytes")
            return None
        
        try:
            # O primeiro byte é o tipo da mensagem
            msg_type = data[0]
            
            if msg_type == PhotonMessageType.OPERATION_REQUEST:
                # Operação: [type(1), operationCode(1), parameters]
                if len(data) < 2:
                    return None
                
                code = data[1]
                parameters = cls._decode_parameters(data[2:])
                
                return cls(msg_type, code, parameters)
                
            elif msg_type == PhotonMessageType.OPERATION_RESPONSE:
                # Resposta: [type(1), operationCode(1), returnCode(2), parameters, debugMessage]
                if len(data) < 4:
                    return None
                
                code = data[1]
                return_code = struct.unpack("<h", data[2:4])[0]
                
                # Decodificar parâmetros e mensagem de debug
                parameters = {}
                debug_message = ""
                
                if len(data) > 4:
                    # Verificar se há parâmetros
                    if data[4] != 0:  # 0 indica ausência de parâmetros
                        parameters = cls._decode_parameters(data[4:])
                        
                        # Encontrar posição da mensagem de debug após parâmetros
                        # (isso é um pouco complexo e depende do formato exato)
                        # Simplificação: procurar por um byte nulo seguido por um short
                        for i in range(5, len(data) - 3):
                            if data[i] == 0 and data[i+1] in (1, 2, 3):  # Tipos comuns para strings
                                str_len = data[i+2]
                                if i + 3 + str_len <= len(data):
                                    debug_message = data[i+3:i+3+str_len].decode('utf-8', errors='ignore')
                                break
                
                return cls(msg_type, code, parameters, return_code, debug_message)
                
            elif msg_type == PhotonMessageType.EVENT_DATA:
                # Evento: [type(1), eventCode(1), parameters]
                if len(data) < 2:
                    return None
                
                code = data[1]
                parameters = cls._decode_parameters(data[2:])
                
                return cls(msg_type, code, parameters)
                
            else:
                logger.warning(f"Tipo de mensagem Photon desconhecido: {msg_type}")
                return None
                
        except Exception as e:
            logger.error(f"Erro ao decodificar mensagem Photon: {e}")
            return None
    
    @staticmethod
    def _decode_parameters(data: bytes) -> Dict[int, Any]:
        """
        Decodifica parâmetros de uma mensagem Photon.
        
        Args:
            data: Bytes contendo os parâmetros
            
        Returns:
            Dicionário com os parâmetros decodificados
        """
        if not data or len(data) < 1:
            return {}
        
        parameters = {}
        
        try:
            # O primeiro byte indica o tipo do parâmetro
            param_type = data[0]
            
            # Se o tipo for 0, não há parâmetros
            if param_type == 0:
                return {}
                
            # Se o tipo for hashtable (campo 0x68), decodificar chaves e valores
            if param_type == 0x68:  # Hashtable
                # Hashtable: [0x68, count, key1, value1, key2, value2, ...]
                if len(data) < 3:
                    return {}
                
                count = data[1]
                offset = 2
                
                for _ in range(count):
                    if offset + 2 > len(data):
                        break
                        
                    # Chave (normalmente um byte)
                    key = data[offset]
                    offset += 1
                    
                    # Valor (depende do tipo)
                    value_type = data[offset]
                    offset += 1
                    
                    value, consumed = PhotonMessage._decode_value(data[offset:], value_type)
                    offset += consumed
                    
                    parameters[key] = value
            
            # Se for outro tipo, tratar como um único parâmetro
            else:
                value, _ = PhotonMessage._decode_value(data[1:], param_type)
                parameters[1] = value  # Usar 1 como chave padrão
            
            return parameters
                
        except Exception as e:
            logger.error(f"Erro ao decodificar parâmetros Photon: {e}")
            return {}
    
    @staticmethod
    def _decode_value(data: bytes, value_type: int) -> Tuple[Any, int]:
        """
        Decodifica um valor com base no seu tipo.
        
        Args:
            data: Bytes contendo o valor
            value_type: Tipo do valor
            
        Returns:
            Tupla (valor decodificado, bytes consumidos)
        """
        try:
            # Tipos comuns no protocolo Photon
            if value_type == 0x00:  # Null
                return None, 0
                
            elif value_type == 0x01:  # Bool
                return data[0] != 0, 1
                
            elif value_type == 0x02:  # Byte
                return data[0], 1
                
            elif value_type == 0x03:  # Short
                return struct.unpack("<h", data[:2])[0], 2
                
            elif value_type == 0x04:  # Int
                return struct.unpack("<i", data[:4])[0], 4
                
            elif value_type == 0x05:  # Long
                return struct.unpack("<q", data[:8])[0], 8
                
            elif value_type == 0x06:  # Float
                return struct.unpack("<f", data[:4])[0], 4
                
            elif value_type == 0x07:  # Double
                return struct.unpack("<d", data[:8])[0], 8
                
            elif value_type == 0x08:  # String (8-bit length)
                if len(data) < 1:
                    return "", 0
                    
                str_len = data[0]
                if len(data) < 1 + str_len:
                    return "", 1
                    
                return data[1:1+str_len].decode('utf-8', errors='ignore'), 1 + str_len
                
            elif value_type == 0x09:  # String (16-bit length)
                if len(data) < 2:
                    return "", 0
                    
                str_len = struct.unpack("<H", data[:2])[0]
                if len(data) < 2 + str_len:
                    return "", 2
                    
                return data[2:2+str_len].decode('utf-8', errors='ignore'), 2 + str_len
                
            elif value_type == 0x0A:  # String (32-bit length)
                if len(data) < 4:
                    return "", 0
                    
                str_len = struct.unpack("<I", data[:4])[0]
                if len(data) < 4 + str_len:
                    return "", 4
                    
                return data[4:4+str_len].decode('utf-8', errors='ignore'), 4 + str_len
                
            elif value_type == 0x0D:  # ByteArray (com comprimento de 32 bits)
                if len(data) < 4:
                    return b"", 0
                    
                array_len = struct.unpack("<I", data[:4])[0]
                if len(data) < 4 + array_len:
                    return b"", 4
                    
                return data[4:4+array_len], 4 + array_len
                
            elif value_type in (0x10, 0x18, 0x19, 0x1A):  # Array/Dictionary
                # Por simplicidade, apenas retornar os bytes brutos
                # Em uma implementação completa, esses tipos teriam sua própria decodificação
                return data, len(data)
                
            else:
                # Tipo desconhecido, retornar os bytes brutos
                logger.warning(f"Tipo de valor Photon desconhecido: 0x{value_type:02x}")
                return data, len(data)
                
        except Exception as e:
            logger.error(f"Erro ao decodificar valor Photon: {e}")
            return None, 0
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Converte a mensagem para um dicionário.
        
        Returns:
            Dicionário com os campos da mensagem
        """
        result = {
            "type": self.msg_type,
            "code": self.code,
            "parameters": self.parameters
        }
        
        if self.msg_type == PhotonMessageType.OPERATION_RESPONSE:
            result["return_code"] = self.return_code
            result["debug_message"] = self.debug_message
            
        return result

# Funções de ajuda para processar mensagens Photon
_photon_callbacks = []

def add_photon_message_callback(callback: Callable[[Dict[str, Any]], None]) -> None:
    """
    Adiciona uma função de callback para mensagens Photon decodificadas.
    
    Args:
        callback: Função que será chamada com a mensagem decodificada.
    """
    global _photon_callbacks
    _photon_callbacks.append(callback)

def photon_decoder(message: PhotonMessage) -> Dict[str, Any]:
    """
    Processa uma mensagem Photon e notifica os callbacks.
    
    Args:
        message: Objeto PhotonMessage a processar.
        
    Returns:
        Dicionário com os dados da mensagem processada.
    """
    message_data = message.to_dict()
    
    # Notificar callbacks
    for callback in _photon_callbacks:
        try:
            callback(message_data)
        except Exception as e:
            logger.error(f"Erro ao executar callback para mensagem Photon: {e}")
    
    return message_data 