"""
Decodificador especializado para o protocolo Photon usado no Albion Online.

Este módulo implementa:
- Decodificação das operações do jogo
- Filtragem de eventos específicos
- Extração de informações de jogadores
- Análise de dados de combate e mercado
"""

# Bibliotecas padrão
import enum
import struct
import time
import logging
import binascii
from typing import Dict, List, Optional, Any, Tuple, Set, Union, Callable

# Imports locais
from ..config import CONFIG

# Importar apenas classes que não causam dependência circular
# As classes PhotonMessageType, PhotonCommand, etc. serão acessadas diretamente
# via módulo para evitar importação circular

# Configuração do logger
logger = logging.getLogger("sniffer.photon.decoder")

# Enums para códigos de operação e eventos do Albion
class AlbionOperationCode(enum.IntEnum):
    """Códigos de operação usados pelo cliente Albion Online."""
    
    JOIN = 1
    CREATE_ACCOUNT = 2
    LOGIN = 3
    SEND_CRASH_REPORT = 4
    CRYPTO_KEY_EXCHANGE = 5
    MOVE = 10
    CAST_HIT_REQUEST = 11
    CANCEL_CAST = 12
    CHANNEL_GET = 13
    AUCTION_GET_OFFERS = 14
    BUY_GOLD = 15
    BUY_REALM_GOLD = 16
    CALL_PLAYER = 17
    GET_GAME_SERVER_BY_CLUSTER = 18
    GET_ACTIVE_MAINTENANCE = 19
    GET_GAME_INFO = 20
    # ... outros códigos omitidos para brevidade ...
    
    @classmethod
    def get_name(cls, code: int) -> str:
        """Obtém o nome da operação pelo código."""
        try:
            return cls(code).name
        except ValueError:
            return f"UNKNOWN_OPERATION_{code}"


class AlbionEventCode(enum.IntEnum):
    """Códigos de evento enviados pelo servidor Albion Online."""
    
    LEAVE = 1
    JOIN = 2
    TIMEOUT = 3
    UPDATE_SILVER = 4
    UPDATE_FAME = 5
    CHARACTER_EQUIPMENT_CHANGED = 6
    HEALTH_UPDATE = 7
    DEAD = 8
    CHAT = 9
    NEW_CHARACTER = 12
    PLAYER_JOINED = 20
    # ... outros códigos omitidos para brevidade ...
    
    @classmethod
    def get_name(cls, code: int) -> str:
        """Obtém o nome do evento pelo código."""
        try:
            return cls(code).name
        except ValueError:
            return f"UNKNOWN_EVENT_{code}"


# Mapeamento de parâmetros conhecidos de eventos
class AlbionEventParameters:
    """Mapeamento de parâmetros conhecidos para eventos específicos."""
    
    # Dicionário com os parâmetros para cada tipo de evento
    PARAMETERS = {
        AlbionEventCode.CHAT: {
            1: "Channel",
            2: "Message",
            3: "SenderName",
            4: "SenderObjectId"
        },
        AlbionEventCode.PLAYER_JOINED: {
            1: "PlayerId",
            2: "PlayerName",
            3: "GuildName",
            4: "AllianceName",
            5: "GuildId",
            6: "AllianceId",
            7: "EquipmentItems",
            8: "Bag"
        },
        # ... outros eventos omitidos para brevidade ...
    }
    
    @classmethod
    def get_parameter_name(cls, event_code: int, param_code: int) -> str:
        """
        Obtém o nome do parâmetro para um código de evento específico.
        
        Args:
            event_code: Código do evento
            param_code: Código do parâmetro
            
        Returns:
            Nome do parâmetro ou código genérico se desconhecido
        """
        if event_code in cls.PARAMETERS and param_code in cls.PARAMETERS[event_code]:
            return cls.PARAMETERS[event_code][param_code]
        return f"Parameter_{param_code}"


class AlbionDecoder:
    """
    Decodificador para pacotes do protocolo Photon específicos do Albion Online.
    
    Esta classe processa pacotes do protocolo Photon e extrai informações
    específicas da implementação do Albion Online.
    """
    
    def __init__(self):
        """Inicializa o decodificador."""
        self.callbacks = {
            "operation": [],
            "event": [],
            "packet": []
        }
        self.debug_mode = False  # Valor padrão para debug_mode
        
    def add_callback(self, callback_type: str, callback: Callable) -> None:
        """
        Adiciona uma função de callback para processamento de pacotes.
        
        Args:
            callback_type: Tipo de callback ('operation', 'event', ou 'packet')
            callback: Função a ser chamada quando um item do tipo especificado for processado
        """
        if callback_type in self.callbacks:
            self.callbacks[callback_type].append(callback)
            logger.debug(f"Callback adicionado para {callback_type}")
        else:
            logger.warning(f"Tipo de callback desconhecido: {callback_type}")
    
    def decode_operation(self, operation_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decodifica dados de operação específicos do Albion.
        
        Args:
            operation_data: Dados da operação Photon
            
        Returns:
            Dados da operação decodificados com nomes amigáveis
        """
        result = operation_data.copy()
        
        # Decodifica o código da operação
        if "OperationCode" in result:
            code = result["OperationCode"]
            result["OperationName"] = AlbionOperationCode.get_name(code)
            
            # Processamento específico por tipo de operação
            if code == AlbionOperationCode.MOVE:
                if "Parameters" in result and 1 in result["Parameters"]:
                    # Decodificação específica para movimento
                    position_data = result["Parameters"].get(1)
                    if position_data and isinstance(position_data, bytes):
                        try:
                            x, y = struct.unpack("<ff", position_data)
                            result["Parameters"][1] = {"X": x, "Y": y}
                        except struct.error:
                            pass
            
        # Executa callbacks
        for callback in self.callbacks["operation"]:
            try:
                callback(result)
            except Exception as e:
                logger.error(f"Erro ao executar callback de operação: {e}")
        
        return result
    
    def decode_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Decodifica dados de evento específicos do Albion.
        
        Args:
            event_data: Dados do evento Photon
            
        Returns:
            Dados do evento decodificados com nomes amigáveis
        """
        result = event_data.copy()
        
        # Decodifica o código do evento
        if "Code" in result:
            code = result["Code"]
            result["EventName"] = AlbionEventCode.get_name(code)
            
            # Processa os parâmetros do evento
            if "Parameters" in result:
                params = {}
                for param_code, value in result["Parameters"].items():
                    param_name = AlbionEventParameters.get_parameter_name(code, param_code)
                    params[param_name] = value
                result["NamedParameters"] = params
        
        # Executa callbacks
        for callback in self.callbacks["event"]:
            try:
                callback(result)
            except Exception as e:
                logger.error(f"Erro ao executar callback de evento: {e}")
        
        return result
    
    def process_photon_message(self, message_data: Dict[str, Any]) -> None:
        """
        Processa uma mensagem Photon para extrair dados específicos do Albion Online.
        
        Args:
            message_data: Dados da mensagem Photon
        """
        # Implementação para processar mensagens Photon e chamar os decodificadores apropriados
        # Este método será chamado pelo sistema de captura para cada mensagem recebida
        logger.debug(f"Processando mensagem Photon: {message_data.get('type', 'Unknown')}")
        
        # Aqui implementaremos o processamento baseado no tipo de mensagem
        # Por enquanto, apenas registramos a recepção da mensagem
        
        # Executa callbacks para pacotes
        for callback in self.callbacks["packet"]:
            try:
                callback(message_data)
            except Exception as e:
                logger.error(f"Erro ao executar callback de pacote: {e}")

class PhotonCaptureHandler:
    """
    Handler para captura e processamento de pacotes do protocolo Photon.
    
    Esta classe é responsável por:
    - Receber pacotes capturados da camada de rede
    - Identificar pacotes relacionados ao protocolo Photon
    - Decodificar os cabeçalhos e os comandos
    - Extrair as mensagens e encaminhá-las para processamento
    """
    
    def __init__(self, decoder: Optional[AlbionDecoder] = None):
        """
        Inicializa o handler de captura.
        
        Args:
            decoder: Instância do AlbionDecoder para processar os pacotes.
                    Se None, uma nova instância será criada.
        """
        self.decoder = decoder or AlbionDecoder()
        self.debug_mode = False
        self.enabled = True
        self.port_filter = CONFIG.get("network", "albion_port", 5056)
        self.fragment_buffer = {}  # Buffer para mensagens fragmentadas
        self.packet_count = 0
        self.last_stats_time = time.time()
        self.stats = {
            "total_packets": 0,
            "valid_packets": 0,
            "invalid_packets": 0,
            "operations": 0,
            "events": 0,
            "fragments": 0,
            "reassembled": 0
        }
        
        logger.info(f"PhotonCaptureHandler inicializado (porta: {self.port_filter})")
    
    def enable_debug(self) -> None:
        """Ativa o modo de depuração."""
        self.debug_mode = True
        logger.setLevel(logging.DEBUG)
        logger.debug("Modo de depuração ativado")
    
    def disable_debug(self) -> None:
        """Desativa o modo de depuração."""
        self.debug_mode = False
        logger.setLevel(logging.INFO)
        logger.info("Modo de depuração desativado")
    
    def enable(self) -> None:
        """Ativa o processamento de pacotes."""
        self.enabled = True
        logger.info("Processamento de pacotes ativado")
    
    def disable(self) -> None:
        """Desativa o processamento de pacotes."""
        self.enabled = False
        logger.info("Processamento de pacotes desativado")
    
    def handle_packet(self, packet_data: Dict[str, Any]) -> None:
        """
        Processa um pacote capturado pela camada de rede.
        
        Args:
            packet_data: Dicionário com dados do pacote capturado pela pcaptura.
        """
        if not self.enabled:
            return
        
        self.stats["total_packets"] += 1
        
        # Verificar se o pacote é do protocolo UDP na porta do Albion
        if packet_data.get("protocol") != "UDP":
            return
        
        src_port = packet_data.get("src_port")
        dst_port = packet_data.get("dst_port")
        
        # Verificar se este pacote é do Albion Online (porta padrão 5056)
        if src_port != self.port_filter and dst_port != self.port_filter:
            return
        
        payload = packet_data.get("payload")
        if not payload or len(payload) < 12:
            self.stats["invalid_packets"] += 1
            if self.debug_mode:
                logger.debug(f"Pacote inválido (payload muito curto): {len(payload) if payload else 0} bytes")
            return
        
        try:
            # Tentar decodificar o cabeçalho Photon
            from . import PhotonHeader, PhotonCommand
            
            header = PhotonHeader.from_bytes(payload)
            if not header:
                self.stats["invalid_packets"] += 1
                if self.debug_mode:
                    logger.debug("Falha ao decodificar cabeçalho Photon")
                return
            
            self.stats["valid_packets"] += 1
            
            # Verificar se o pacote tem comandos
            if header.command_count <= 0:
                return
            
            # Processar os comandos
            offset = 12  # Tamanho do cabeçalho
            commands_processed = 0
            
            while commands_processed < header.command_count and offset < len(payload):
                command, consumed = PhotonCommand.from_bytes(payload[offset:])
                
                if not command or consumed == 0:
                    break
                
                offset += consumed
                commands_processed += 1
                
                # Processar o comando conforme seu tipo
                self._process_command(command, packet_data)
            
            # Registrar estatísticas periodicamente
            current_time = time.time()
            if current_time - self.last_stats_time >= 10.0:
                if self.debug_mode:
                    self._log_stats()
                self.last_stats_time = current_time
                
        except Exception as e:
            logger.error(f"Erro ao processar pacote: {e}")
            if self.debug_mode:
                import traceback
                logger.debug(traceback.format_exc())
    
    def _process_command(self, command: Any, packet_data: Dict[str, Any]) -> None:
        """
        Processa um comando Photon.
        
        Args:
            command: Objeto PhotonCommand para processar
            packet_data: Dados originais do pacote
        """
        from . import PhotonCommandType
        
        try:
            # Verificar o tipo do comando
            if command.command_type == PhotonCommandType.SEND_RELIABLE:
                # Comandos confiáveis contêm mensagens completas
                self._extract_messages(command.data, packet_data)
                
            elif command.command_type == PhotonCommandType.SEND_RELIABLE_FRAGMENT:
                # Comandos fragmentados precisam ser remontados
                self.stats["fragments"] += 1
                self._handle_fragment(command, packet_data)
                
            elif self.debug_mode and command.command_type in [
                PhotonCommandType.ACKNOWLEDGE,
                PhotonCommandType.CONNECT,
                PhotonCommandType.DISCONNECT,
                PhotonCommandType.PING,
                PhotonCommandType.VERIFY_CONNECT
            ]:
                # Registrar outros tipos de comandos em modo de depuração
                logger.debug(f"Comando Photon: Tipo={command.command_type}, Canal={command.channel_id}, Seq={command.sequence_number}")
                
        except Exception as e:
            logger.error(f"Erro ao processar comando: {e}")
            if self.debug_mode:
                import traceback
                logger.debug(traceback.format_exc())
    
    def _handle_fragment(self, command: Any, packet_data: Dict[str, Any]) -> None:
        """
        Processa um comando fragmentado.
        
        Args:
            command: Objeto PhotonCommand com fragmento
            packet_data: Dados originais do pacote
        """
        try:
            # Os primeiros 4 bytes do comando fragmentado contêm a flag de 
            # posição (start/finish) e o número de sequência global
            if len(command.data) < 8:
                if self.debug_mode:
                    logger.debug(f"Fragmento inválido (muito curto): {len(command.data)} bytes")
                return
            
            # Extrair informações do fragmento
            start_seq, total_length = struct.unpack("<II", command.data[:8])
            is_start = (start_seq & 0x80000000) != 0
            is_finish = (start_seq & 0x40000000) != 0
            fragment_seq = start_seq & 0x3FFFFFFF
            
            # Dados atuais do fragmento
            fragment_data = command.data[8:]
            
            # Chave única para este conjunto de fragmentos
            fragment_key = f"{command.channel_id}_{fragment_seq}"
            
            if is_start:
                # Iniciar um novo conjunto de fragmentos
                self.fragment_buffer[fragment_key] = {
                    "total_length": total_length,
                    "received_length": len(fragment_data),
                    "fragments": {0: fragment_data},
                    "timestamp": time.time()
                }
                if self.debug_mode:
                    logger.debug(f"Iniciando fragmento {fragment_key}: {len(fragment_data)}/{total_length} bytes")
            
            elif fragment_key in self.fragment_buffer:
                # Continuar um conjunto existente
                buffer = self.fragment_buffer[fragment_key]
                fragment_offset = buffer["received_length"]
                buffer["fragments"][fragment_offset] = fragment_data
                buffer["received_length"] += len(fragment_data)
                
                if self.debug_mode:
                    logger.debug(f"Continuando fragmento {fragment_key}: {buffer['received_length']}/{buffer['total_length']} bytes")
                
                # Verificar se completamos a mensagem fragmentada
                if is_finish or buffer["received_length"] >= buffer["total_length"]:
                    if self.debug_mode:
                        logger.debug(f"Fragmento {fragment_key} completo: {buffer['received_length']} bytes")
                    
                    # Remontar os fragmentos em ordem
                    offsets = sorted(buffer["fragments"].keys())
                    complete_data = b"".join(buffer["fragments"][offset] for offset in offsets)
                    
                    # Processar a mensagem completa
                    self.stats["reassembled"] += 1
                    self._extract_messages(complete_data, packet_data)
                    
                    # Remover do buffer
                    del self.fragment_buffer[fragment_key]
            
            else:
                # Fragmento solto - descartar
                if self.debug_mode:
                    logger.debug(f"Fragmento solto recebido: canal={command.channel_id}, seq={fragment_seq}")
        
        except Exception as e:
            logger.error(f"Erro ao processar fragmento: {e}")
            if self.debug_mode:
                import traceback
                logger.debug(traceback.format_exc())
    
    def _extract_messages(self, data: bytes, packet_data: Dict[str, Any]) -> None:
        """
        Extrai e processa mensagens Photon de dados brutos.
        
        Args:
            data: Bytes contendo uma ou mais mensagens
            packet_data: Dados originais do pacote
        """
        from . import PhotonMessageType, PhotonMessage
        
        offset = 0
        
        try:
            while offset < len(data):
                # Verificar se temos bytes suficientes para o cabeçalho da mensagem (2 bytes)
                if offset + 2 > len(data):
                    break
                
                # Ler o tamanho da mensagem
                msg_size = struct.unpack("<H", data[offset:offset+2])[0]
                offset += 2
                
                # Verificar se temos bytes suficientes para a mensagem completa
                if offset + msg_size > len(data):
                    if self.debug_mode:
                        logger.debug(f"Mensagem truncada: {msg_size} bytes declarados, {len(data) - offset} disponíveis")
                    break
                
                # Extrair a mensagem
                message_data = data[offset:offset+msg_size]
                offset += msg_size
                
                # Decodificar a mensagem
                message = PhotonMessage.from_bytes(message_data)
                if not message:
                    continue
                
                # Processar a mensagem com base no tipo
                if message.msg_type == PhotonMessageType.OPERATION_REQUEST:
                    self.stats["operations"] += 1
                    operation_data = {
                        "type": "operation_request",
                        "OperationCode": message.code,
                        "Parameters": message.parameters,
                        "timestamp": time.time(),
                        "source": {
                            "ip": packet_data.get("src_ip"),
                            "port": packet_data.get("src_port")
                        }
                    }
                    self.decoder.decode_operation(operation_data)
                    
                elif message.msg_type == PhotonMessageType.OPERATION_RESPONSE:
                    self.stats["operations"] += 1
                    operation_data = {
                        "type": "operation_response",
                        "OperationCode": message.code,
                        "Parameters": message.parameters,
                        "ReturnCode": message.return_code,
                        "DebugMessage": message.debug_message,
                        "timestamp": time.time(),
                        "source": {
                            "ip": packet_data.get("src_ip"),
                            "port": packet_data.get("src_port")
                        }
                    }
                    self.decoder.decode_operation(operation_data)
                    
                elif message.msg_type == PhotonMessageType.EVENT_DATA:
                    self.stats["events"] += 1
                    event_data = {
                        "type": "event_data",
                        "code": message.code,
                        "parameters": message.parameters,
                        "timestamp": time.time(),
                        "source": {
                            "ip": packet_data.get("src_ip"),
                            "port": packet_data.get("src_port")
                        }
                    }
                    self.decoder.decode_event(event_data)
                    
                else:
                    if self.debug_mode:
                        logger.debug(f"Mensagem Photon desconhecida: Tipo={message.msg_type}, Código={message.code}")
                    
        except Exception as e:
            logger.error(f"Erro ao extrair mensagens: {e}")
            if self.debug_mode:
                import traceback
                logger.debug(traceback.format_exc())
    
    def _log_stats(self) -> None:
        """Registra estatísticas sobre os pacotes processados."""
        logger.debug(
            f"Estatísticas: {self.stats['total_packets']} pacotes totais, "
            f"{self.stats['valid_packets']} válidos, "
            f"{self.stats['invalid_packets']} inválidos, "
            f"{self.stats['operations']} operações, "
            f"{self.stats['events']} eventos, "
            f"{self.stats['fragments']} fragmentos, "
            f"{self.stats['reassembled']} remontados"
        )
    
    def clear_stats(self) -> None:
        """Reinicia as estatísticas de captura."""
        self.stats = {
            "total_packets": 0,
            "valid_packets": 0,
            "invalid_packets": 0,
            "operations": 0,
            "events": 0,
            "fragments": 0,
            "reassembled": 0
        }
        self.last_stats_time = time.time()
        logger.debug("Estatísticas de captura reiniciadas")

# Singleton para uso global
capture_handler = PhotonCaptureHandler()

def start_albion_capture() -> None:
    """Inicia a captura de mensagens do Albion Online."""
    global capture_handler
    capture_handler.enable()

def stop_albion_capture() -> None:
    """Para a captura de mensagens do Albion Online."""
    global capture_handler
    capture_handler.disable()

def enable_debug_mode() -> None:
    """Ativa o modo de depuração para a captura."""
    global capture_handler
    capture_handler.enable_debug()

def disable_debug_mode() -> None:
    """Desativa o modo de depuração para a captura."""
    global capture_handler
    capture_handler.disable_debug()

def get_capture_stats() -> Dict[str, int]:
    """Retorna estatísticas da captura atual."""
    global capture_handler
    return capture_handler.stats.copy()

def clear_capture_stats() -> None:
    """Limpa as estatísticas de captura."""
    global capture_handler
    capture_handler.clear_stats()

# Singleton para uso global
albion_decoder = AlbionDecoder() 