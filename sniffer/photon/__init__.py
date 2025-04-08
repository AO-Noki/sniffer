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
                
            elif cmd_type == PhotonCommandType.SEND_UNRELIABLE:
                # Comando não confiável
                command_data = data[8:8+length]
                
                return cls(
                    command_type=cmd_type,
                    channel_id=channel_id,
                    flags=flags,
                    reserved=reserved,
                    length=length,
                    sequence_number=0,  # Não tem número de sequência
                    data=command_data
                ), 8 + length
                
            else:
                # Outros tipos de comandos
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
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Converte o comando para um dicionário.
        
        Returns:
            Dicionário com os campos do comando
        """
        return {
            "type": self.command_type,
            "type_name": self._get_command_type_name(),
            "channel_id": self.channel_id,
            "flags": self.flags,
            "length": self.length,
            "sequence_number": self.sequence_number,
            "data_length": len(self.data)
        }
    
    def _get_command_type_name(self) -> str:
        """Retorna o nome do tipo de comando."""
        command_names = {
            PhotonCommandType.ACKNOWLEDGE: "Acknowledge",
            PhotonCommandType.CONNECT: "Connect",
            PhotonCommandType.VERIFY_CONNECT: "VerifyConnect",
            PhotonCommandType.DISCONNECT: "Disconnect",
            PhotonCommandType.PING: "Ping",
            PhotonCommandType.SEND_RELIABLE: "SendReliable",
            PhotonCommandType.SEND_UNRELIABLE: "SendUnreliable",
            PhotonCommandType.SEND_RELIABLE_FRAGMENT: "SendReliableFragment"
        }
        return command_names.get(self.command_type, f"Unknown({self.command_type})")

class FragmentInfo:
    """Informações sobre um fragmento de mensagem."""
    
    def __init__(self, sequence_number: int, fragment_count: int, fragment_number: int,
                 total_length: int, fragment_offset: int, data: bytes):
        """
        Inicializa as informações de um fragmento.
        
        Args:
            sequence_number: Número de sequência da mensagem completa
            fragment_count: Número total de fragmentos
            fragment_number: Número deste fragmento (0-indexed)
            total_length: Tamanho total da mensagem completa
            fragment_offset: Posição deste fragmento na mensagem completa
            data: Conteúdo do fragmento
        """
        self.sequence_number = sequence_number
        self.fragment_count = fragment_count
        self.fragment_number = fragment_number
        self.total_length = total_length
        self.fragment_offset = fragment_offset
        self.data = data
    
    @classmethod
    def from_command(cls, command: PhotonCommand) -> Optional['FragmentInfo']:
        """
        Extrai informações de fragmento de um comando SendReliableFragment.
        
        Args:
            command: Objeto PhotonCommand do tipo SendReliableFragment
            
        Returns:
            Objeto FragmentInfo ou None se a extração falhar
        """
        if command.command_type != PhotonCommandType.SEND_RELIABLE_FRAGMENT:
            logger.warning(f"Tentativa de extrair fragmento de comando não fragmentado: {command.command_type}")
            return None
        
        try:
            # Cabeçalho de fragmento: IIII (uint, uint, uint, uint)
            if len(command.data) < 16:
                logger.warning(f"Dados insuficientes para cabeçalho de fragmento: {len(command.data)} bytes")
                return None
                
            seq_number = command.sequence_number
            frag_count, frag_number, total_length, frag_offset = struct.unpack("<IIII", command.data[:16])
            frag_data = command.data[16:]
            
            return cls(
                sequence_number=seq_number,
                fragment_count=frag_count,
                fragment_number=frag_number,
                total_length=total_length,
                fragment_offset=frag_offset,
                data=frag_data
            )
        except struct.error as e:
            logger.error(f"Erro ao decodificar cabeçalho de fragmento: {e}")
            return None
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Converte as informações do fragmento para um dicionário.
        
        Returns:
            Dicionário com os campos do fragmento
        """
        return {
            "sequence_number": self.sequence_number,
            "fragment_count": self.fragment_count,
            "fragment_number": self.fragment_number,
            "total_length": self.total_length,
            "fragment_offset": self.fragment_offset,
            "data_length": len(self.data)
        }

class PhotonMessage:
    """Representa uma mensagem Photon decodificada."""
    
    def __init__(self, message_type: int, payload: bytes):
        """
        Inicializa uma mensagem Photon.
        
        Args:
            message_type: Tipo da mensagem
            payload: Conteúdo da mensagem
        """
        self.message_type = message_type
        self.payload = payload
        self.decoded_content = None
    
    @classmethod
    def from_reliable_data(cls, data: bytes) -> Optional['PhotonMessage']:
        """
        Decodifica uma mensagem a partir de dados de comando confiável.
        
        Args:
            data: Bytes contendo a mensagem
            
        Returns:
            Objeto PhotonMessage ou None se a decodificação falhar
        """
        if len(data) < 2:  # Precisamos de pelo menos 1 byte para tipo
            logger.warning(f"Dados insuficientes para mensagem Photon: {len(data)} bytes")
            return None
        
        try:
            message_type = data[0]
            return cls(message_type=message_type, payload=data[1:])
        except Exception as e:
            logger.error(f"Erro ao decodificar mensagem Photon: {e}")
            return None
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Converte a mensagem para um dicionário.
        
        Returns:
            Dicionário com os campos da mensagem
        """
        result = {
            "type": self.message_type,
            "type_name": self._get_message_type_name(),
            "payload_length": len(self.payload)
        }
        
        # Adicionar conteúdo decodificado, se disponível
        if self.decoded_content:
            result["content"] = self.decoded_content
            
        return result
    
    def _get_message_type_name(self) -> str:
        """Retorna o nome do tipo de mensagem."""
        message_names = {
            PhotonMessageType.OPERATION_REQUEST: "OperationRequest",
            PhotonMessageType.OPERATION_RESPONSE: "OperationResponse",
            PhotonMessageType.EVENT_DATA: "EventData"
        }
        return message_names.get(self.message_type, f"Unknown({self.message_type})")

class FragmentBuffer:
    """Gerencia fragmentos recebidos e reconstrói mensagens completas."""
    
    def __init__(self, max_age_seconds: int = 30):
        """
        Inicializa o buffer de fragmentos.
        
        Args:
            max_age_seconds: Tempo máximo (em segundos) para manter fragmentos no buffer
        """
        self.fragments = {}  # Dict[sequence_number, Dict[fragment_number, FragmentInfo]]
        self.fragment_timestamps = {}  # Dict[sequence_number, timestamp]
        self.max_age_seconds = max_age_seconds
    
    def add_fragment(self, fragment: FragmentInfo) -> Optional[bytes]:
        """
        Adiciona um fragmento ao buffer e tenta reconstruir a mensagem completa.
        
        Args:
            fragment: Informações do fragmento a adicionar
            
        Returns:
            Dados da mensagem completa reconstruída, ou None se ainda faltar fragmentos
        """
        seq_num = fragment.sequence_number
        
        # Inicializar entrada para esta sequência, se necessário
        if seq_num not in self.fragments:
            self.fragments[seq_num] = {}
            self.fragment_timestamps[seq_num] = time.time()
        
        # Adicionar este fragmento
        self.fragments[seq_num][fragment.fragment_number] = fragment
        
        # Verificar se temos todos os fragmentos
        if len(self.fragments[seq_num]) == fragment.fragment_count:
            # Reconstruir a mensagem completa
            result = self._reconstruct_message(seq_num, fragment.total_length)
            
            # Liberar memória
            del self.fragments[seq_num]
            del self.fragment_timestamps[seq_num]
            
            return result
        
        return None
    
    def _reconstruct_message(self, sequence_number: int, total_length: int) -> bytes:
        """
        Reconstrói uma mensagem completa a partir de seus fragmentos.
        
        Args:
            sequence_number: Número de sequência da mensagem
            total_length: Tamanho total esperado da mensagem
            
        Returns:
            Dados reconstruídos da mensagem completa
        """
        # Criar buffer para a mensagem completa
        result = bytearray(total_length)
        
        # Preencher com dados de cada fragmento
        for frag_num, fragment in self.fragments[sequence_number].items():
            start = fragment.fragment_offset
            end = start + len(fragment.data)
            result[start:end] = fragment.data
        
        return bytes(result)
    
    def cleanup_old_fragments(self) -> int:
        """
        Remove fragmentos antigos do buffer.
        
        Returns:
            Número de sequências removidas
        """
        current_time = time.time()
        sequences_to_remove = []
        
        # Identificar sequências antigas
        for seq_num, timestamp in self.fragment_timestamps.items():
            if current_time - timestamp > self.max_age_seconds:
                sequences_to_remove.append(seq_num)
        
        # Remover sequências antigas
        for seq_num in sequences_to_remove:
            del self.fragments[seq_num]
            del self.fragment_timestamps[seq_num]
        
        return len(sequences_to_remove)

class PhotonDecoder:
    """Decodificador principal para o protocolo Photon."""
    
    def __init__(self):
        """Inicializa o decodificador Photon."""
        self.fragment_buffer = FragmentBuffer()
        self.callbacks = []
    
    def add_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        Adiciona uma função de callback para processar mensagens decodificadas.
        
        Args:
            callback: Função que será chamada com a mensagem como argumento.
        """
        self.callbacks.append(callback)
    
    def decode_packet(self, packet_data: bytes) -> Optional[Dict[str, Any]]:
        """
        Decodifica um pacote Photon completo.
        
        Args:
            packet_data: Bytes do pacote UDP contendo tráfego Photon
            
        Returns:
            Dicionário com informações decodificadas, ou None se falhar
        """
        # Limpar fragmentos antigos periodicamente
        self.fragment_buffer.cleanup_old_fragments()
        
        try:
            # Decodificar cabeçalho Photon
            header = PhotonHeader.from_bytes(packet_data)
            if not header:
                return None
            
            result = {
                "timestamp": time.time(),
                "header": header.to_dict(),
                "commands": []
            }
            
            # Posição atual nos dados
            pos = 12  # Após o cabeçalho
            
            # Decodificar comandos
            for i in range(header.command_count):
                if pos >= len(packet_data):
                    break
                
                command, bytes_read = PhotonCommand.from_bytes(packet_data[pos:])
                if not command:
                    break
                
                pos += bytes_read
                command_data = command.to_dict()
                result["commands"].append(command_data)
                
                # Processar comando conforme seu tipo
                self._process_command(command, result)
            
            # Chamar callbacks se tiverem mensagens decodificadas
            if "messages" in result:
                for callback in self.callbacks:
                    try:
                        callback(result)
                    except Exception as e:
                        logger.error(f"Erro ao chamar callback para pacote Photon: {e}")
            
            return result
            
        except Exception as e:
            logger.error(f"Erro ao decodificar pacote Photon: {e}")
            return None
    
    def _process_command(self, command: PhotonCommand, result: Dict[str, Any]) -> None:
        """
        Processa um comando Photon e atualiza o resultado.
        
        Args:
            command: Comando a processar
            result: Dicionário de resultado a atualizar
        """
        # Inicializar lista de mensagens no resultado, se necessário
        if "messages" not in result:
            result["messages"] = []
        
        # Processar conforme o tipo de comando
        if command.command_type == PhotonCommandType.SEND_RELIABLE:
            # Mensagem confiável - decodificar diretamente
            message = PhotonMessage.from_reliable_data(command.data)
            if message:
                result["messages"].append(message.to_dict())
        
        elif command.command_type == PhotonCommandType.SEND_RELIABLE_FRAGMENT:
            # Fragmento de mensagem confiável - processar no buffer
            fragment = FragmentInfo.from_command(command)
            if fragment:
                # Adicionar ao buffer e verificar se a mensagem está completa
                complete_message_data = self.fragment_buffer.add_fragment(fragment)
                if complete_message_data:
                    # Temos uma mensagem completa - decodificar
                    message = PhotonMessage.from_reliable_data(complete_message_data)
                    if message:
                        result["messages"].append(message.to_dict())
        
        elif command.command_type == PhotonCommandType.SEND_UNRELIABLE:
            # Mensagem não confiável - decodificar diretamente
            message = PhotonMessage.from_reliable_data(command.data)
            if message:
                result["messages"].append(message.to_dict())

# Criando um decodificador global para uso em todo o sistema
photon_decoder = PhotonDecoder()

def decode_photon_packet(packet_data: bytes) -> Optional[Dict[str, Any]]:
    """
    Função auxiliar para decodificar um pacote Photon.
    
    Args:
        packet_data: Bytes do pacote contendo tráfego Photon
        
    Returns:
        Dicionário com informações decodificadas, ou None se falhar
    """
    return photon_decoder.decode_packet(packet_data)

def add_photon_message_callback(callback: Callable[[Dict[str, Any]], None]) -> None:
    """
    Adiciona um callback para mensagens Photon decodificadas.
    
    Args:
        callback: Função a ser chamada quando uma mensagem for decodificada.
    """
    photon_decoder.add_callback(callback) 