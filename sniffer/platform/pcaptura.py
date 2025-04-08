"""
Módulo para captura de pacotes usando pcap.

Este módulo fornece classes e funções para captura de pacotes de rede
usando pcap (Npcap/WinPcap no Windows, libpcap no Linux/macOS).
"""

import os
import sys
import time
import logging
import tempfile
import threading
import asyncio
from typing import Dict, List, Tuple, Optional, Any, Callable, Union, Set
from urllib.request import urlretrieve

# Importação condicional para as bibliotecas pcap
try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Configurar logger
logger = logging.getLogger("sniffer.platform.pcaptura")

class PcapError(Exception):
    """Exceção base para erros relacionados ao pcap."""
    pass

class PcapNotFoundError(PcapError):
    """Exceção levantada quando o pcap não é encontrado."""
    pass

class PcapCaptureError(PcapError):
    """Exceção levantada quando ocorre um erro durante a captura."""
    pass

class PacketHandler:
    """Classe base para manipuladores de pacotes."""
    
    def __init__(self):
        """Inicializa o manipulador de pacotes."""
        self.callbacks = []
        
    def add_callback(self, callback: Callable[[Dict], None]) -> None:
        """
        Adiciona uma função de callback para ser chamada quando um pacote for recebido.
        
        Args:
            callback: Função que será chamada com o pacote como argumento.
        """
        self.callbacks.append(callback)
        
    def process_packet(self, packet: Any) -> None:
        """
        Processa um pacote e chama todos os callbacks registrados.
        
        Args:
            packet: Pacote a ser processado.
        """
        # Converter o pacote para um formato genérico (dict)
        packet_dict = self._convert_packet(packet)
        
        # Chamar todos os callbacks registrados
        for callback in self.callbacks:
            try:
                callback(packet_dict)
            except Exception as e:
                logger.error(f"Erro ao chamar callback para pacote: {e}")
    
    def _convert_packet(self, packet: Any) -> Dict[str, Any]:
        """
        Converte um pacote para um formato genérico (dicionário).
        
        Args:
            packet: Pacote a ser convertido.
            
        Returns:
            Dicionário representando o pacote.
        """
        # Implementação padrão - deve ser sobrescrita por subclasses
        return {"raw": packet}

class ScapyPacketHandler(PacketHandler):
    """Manipulador de pacotes que usa Scapy."""
    
    def _convert_packet(self, packet: scapy.Packet) -> Dict[str, Any]:
        """
        Converte um pacote Scapy para um formato genérico (dicionário).
        
        Args:
            packet: Pacote Scapy a ser convertido.
            
        Returns:
            Dicionário representando o pacote.
        """
        result = {
            "timestamp": time.time(),
            "layers": {},
            "raw": bytes(packet) if packet else b''
        }
        
        # Adicionar informações sobre cada camada do pacote
        if hasattr(packet, 'layers'):
            for layer in packet.layers():
                layer_name = layer.__name__
                layer_fields = {}
                
                # Extrair campos da camada atual
                if hasattr(packet, 'fields'):
                    for field, value in packet.fields.items():
                        if isinstance(value, bytes):
                            # Converter bytes para formato hexadecimal
                            layer_fields[field] = value.hex()
                        else:
                            # Usar o valor diretamente
                            layer_fields[field] = value
                
                result["layers"][layer_name] = layer_fields
                
                # Se for uma camada UDP, verificar se é o Photon (porta 5056, 5055, ou 5058)
                if layer_name == "UDP" and hasattr(packet, "dport"):
                    if packet.dport in [5055, 5056, 5058]:
                        result["is_photon"] = True
                        result["photon_port"] = packet.dport
        
        return result

class PcapManager:
    """
    Gerenciador de captura de pacotes usando pcap.
    
    Esta classe abstrai o uso do pcap para diferentes plataformas,
    fornecendo uma interface unificada para captura de pacotes.
    """
    
    def __init__(self):
        """Inicializa o gerenciador de captura."""
        self.sniffer = None
        self.capture_thread = None
        self.stop_event = threading.Event()
        self.packet_handler = ScapyPacketHandler() if SCAPY_AVAILABLE else PacketHandler()
        self.capturing = False
        self.interface = None
        self.filter = None
        
        # Verificar se as bibliotecas necessárias estão disponíveis
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy não está disponível. A captura de pacotes pode não funcionar corretamente.")
    
    def get_available_interfaces(self) -> List[Dict[str, str]]:
        """
        Retorna uma lista de interfaces de rede disponíveis para captura.
        
        Returns:
            Lista de dicionários com informações sobre as interfaces.
        """
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy não está disponível. Não é possível listar interfaces.")
            return []
        
        try:
            # Usar o Scapy para listar as interfaces
            interfaces = []
            for iface_name in scapy.get_if_list():
                try:
                    # Obter informações da interface
                    mac = scapy.get_if_hwaddr(iface_name)
                    ip = scapy.get_if_addr(iface_name)
                    
                    interfaces.append({
                        "name": iface_name,
                        "description": iface_name,  # O Scapy não fornece descrição
                        "mac": mac,
                        "ip": ip
                    })
                except Exception as e:
                    logger.debug(f"Erro ao obter informações da interface {iface_name}: {e}")
            
            return interfaces
        except Exception as e:
            logger.error(f"Erro ao listar interfaces: {e}")
            return []
    
    def start_capture(self, interface: str, filter_str: str = "", async_mode: bool = False) -> bool:
        """
        Inicia a captura de pacotes em uma interface específica.
        
        Args:
            interface: Nome ou índice da interface para captura.
            filter_str: String de filtro BPF (Berkeley Packet Filter).
            async_mode: Se True, a captura é executada em um thread separado.
            
        Returns:
            True se a captura foi iniciada com sucesso, False caso contrário.
        """
        if not SCAPY_AVAILABLE:
            logger.error("Scapy não está disponível. Não é possível iniciar a captura.")
            return False
        
        if self.capturing:
            logger.warning("Captura já está em andamento. Pare a captura atual antes de iniciar uma nova.")
            return False
        
        try:
            self.interface = interface
            self.filter = filter_str
            
            # Iniciar captura em modo síncrono ou assíncrono
            if async_mode:
                self.stop_event.clear()
                self.capture_thread = threading.Thread(
                    target=self._capture_thread,
                    args=(interface, filter_str),
                    daemon=True
                )
                self.capture_thread.start()
            else:
                # Para modo síncrono, iniciamos o sniffer diretamente
                self.sniffer = scapy.AsyncSniffer(
                    iface=interface,
                    filter=filter_str,
                    prn=self.packet_handler.process_packet,
                    store=False
                )
                self.sniffer.start()
            
            self.capturing = True
            logger.info(f"Captura iniciada na interface {interface}" + 
                       (f" com filtro '{filter_str}'" if filter_str else ""))
            return True
        except Exception as e:
            logger.error(f"Erro ao iniciar captura: {e}")
            self.capturing = False
            return False
    
    def _capture_thread(self, interface: str, filter_str: str) -> None:
        """
        Função de thread para captura assíncrona.
        
        Args:
            interface: Nome ou índice da interface para captura.
            filter_str: String de filtro BPF.
        """
        try:
            self.sniffer = scapy.AsyncSniffer(
                iface=interface,
                filter=filter_str,
                prn=self.packet_handler.process_packet,
                store=False
            )
            self.sniffer.start()
            
            # Aguardar sinal para parar
            while not self.stop_event.is_set():
                time.sleep(0.1)
                
            # Parar o sniffer quando solicitado
            if self.sniffer:
                self.sniffer.stop()
                
        except Exception as e:
            logger.error(f"Erro no thread de captura: {e}")
        finally:
            self.capturing = False
            logger.info("Thread de captura encerrado")
    
    def stop_capture(self) -> bool:
        """
        Para a captura em andamento.
        
        Returns:
            True se a captura foi parada com sucesso, False caso contrário.
        """
        if not self.capturing:
            logger.warning("Nenhuma captura em andamento para parar.")
            return False
        
        try:
            if self.capture_thread and self.capture_thread.is_alive():
                # Para captura assíncrona
                self.stop_event.set()
                self.capture_thread.join(timeout=2.0)
                
                if self.capture_thread.is_alive():
                    logger.warning("Thread de captura não encerrou no tempo esperado.")
            
            # Para captura síncrona
            if self.sniffer:
                self.sniffer.stop()
                self.sniffer = None
            
            self.capturing = False
            logger.info("Captura parada com sucesso")
            return True
        except Exception as e:
            logger.error(f"Erro ao parar captura: {e}")
            return False
    
    def add_packet_callback(self, callback: Callable[[Dict], None]) -> None:
        """
        Adiciona uma função de callback para processar pacotes capturados.
        
        Args:
            callback: Função que será chamada para cada pacote capturado.
        """
        self.packet_handler.add_callback(callback)
    
    def is_capturing(self) -> bool:
        """
        Verifica se a captura está em andamento.
        
        Returns:
            True se a captura está em andamento, False caso contrário.
        """
        return self.capturing
    
    def get_capture_stats(self) -> Dict[str, Any]:
        """
        Retorna estatísticas sobre a captura atual.
        
        Returns:
            Dicionário com estatísticas da captura.
        """
        if not self.capturing or not self.sniffer:
            return {
                "active": False,
                "packets": 0,
                "interface": None,
                "filter": None,
                "uptime": 0
            }
        
        # Estatísticas básicas
        stats = {
            "active": self.capturing,
            "interface": self.interface,
            "filter": self.filter,
            "packets": getattr(self.sniffer, "packets_captured", 0),
            "uptime": getattr(self.sniffer, "running_time", 0)
        }
        
        return stats


# Função para detecção e instalação do Npcap ou equivalente
class PcapInstaller:
    """Classe para instalação do pcap em diferentes plataformas."""
    
    NPCAP_URL = "https://npcap.com/dist/npcap-1.75.exe"
    
    @staticmethod
    def check_pcap_installed() -> bool:
        """
        Verifica se o pcap está instalado no sistema.
        
        Returns:
            True se o pcap está instalado, False caso contrário.
        """
        # Verificar a disponibilidade do Scapy
        if not SCAPY_AVAILABLE:
            return False
        
        # Tentar obter a lista de interfaces
        try:
            interfaces = scapy.get_if_list()
            return len(interfaces) > 0
        except Exception:
            return False
    
    @staticmethod
    def install_pcap() -> bool:
        """
        Instala o pcap no sistema, se possível.
        
        Returns:
            True se a instalação foi bem-sucedida, False caso contrário.
        """
        platform_system = sys.platform
        
        if platform_system == 'win32':
            return PcapInstaller._install_npcap()
        elif platform_system in ['linux', 'linux2']:
            logger.warning("Instalação automática do libpcap não implementada para Linux.")
            return False
        elif platform_system == 'darwin':
            logger.warning("Instalação automática do libpcap não implementada para macOS.")
            return False
        else:
            logger.error(f"Plataforma não suportada: {platform_system}")
            return False
    
    @staticmethod
    def _install_npcap() -> bool:
        """
        Instala o Npcap no Windows.
        
        Returns:
            True se a instalação foi bem-sucedida, False caso contrário.
        """
        try:
            import ctypes
            
            logger.info("Baixando instalador do Npcap...")
            temp_dir = tempfile.gettempdir()
            installer_path = os.path.join(temp_dir, "npcap_installer.exe")
            
            # Baixar o instalador
            urlretrieve(PcapInstaller.NPCAP_URL, installer_path)
            
            logger.info(f"Instalador baixado para {installer_path}")
            
            # Verificar se temos privilégios de administrador
            if not ctypes.windll.shell32.IsUserAnAdmin():
                logger.warning("Privilégios de administrador são necessários para instalar o Npcap.")
                
                # Tentar elevar privilégios e executar o instalador
                ctypes.windll.shell32.ShellExecuteW(
                    None, "runas", installer_path, 
                    "/S /winpcap_mode=yes", None, 1
                )
                logger.info("Solicitação de elevação de privilégios para instalar Npcap.")
                return False  # Não sabemos se a instalação terá êxito
            
            # Se já estamos como administrador, executar diretamente
            import subprocess
            logger.info("Iniciando instalação do Npcap...")
            subprocess.run([installer_path, "/S", "/winpcap_mode=yes"], check=True)
            
            logger.info("Npcap instalado com sucesso.")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao instalar Npcap: {e}")
            return False


# Classe para captura específica do protocolo Photon
class PhotonCapture:
    """Classe para captura de pacotes do protocolo Photon."""
    
    def __init__(self, pcap_manager: Optional[PcapManager] = None):
        """
        Inicializa o capturador de pacotes Photon.
        
        Args:
            pcap_manager: Gerenciador de pcap a ser usado.
                          Se None, um novo gerenciador será criado.
        """
        self.pcap_manager = pcap_manager or PcapManager()
        self.photon_callbacks = []
        
        # Registrar callback para filtragem de pacotes Photon
        self.pcap_manager.add_packet_callback(self._filter_photon_packet)
    
    def add_photon_callback(self, callback: Callable[[Dict], None]) -> None:
        """
        Adiciona um callback para pacotes Photon.
        
        Args:
            callback: Função a ser chamada quando um pacote Photon for capturado.
        """
        self.photon_callbacks.append(callback)
    
    def _filter_photon_packet(self, packet: Dict[str, Any]) -> None:
        """
        Filtra pacotes Photon e chama os callbacks registrados.
        
        Args:
            packet: Pacote a ser filtrado.
        """
        # Verificar se é um pacote Photon
        if packet.get("is_photon", False):
            # Chamar todos os callbacks de Photon registrados
            for callback in self.photon_callbacks:
                try:
                    callback(packet)
                except Exception as e:
                    logger.error(f"Erro ao chamar callback para pacote Photon: {e}")
    
    def start_capture(self, interface: str, async_mode: bool = True) -> bool:
        """
        Inicia a captura de pacotes Photon.
        
        Args:
            interface: Interface de rede para captura.
            async_mode: Se True, a captura é feita em um thread separado.
            
        Returns:
            True se a captura foi iniciada com sucesso, False caso contrário.
        """
        # Configurar filtro BPF para capturar apenas UDP nas portas do Photon
        photon_filter = "udp and (port 5055 or port 5056 or port 5058)"
        
        return self.pcap_manager.start_capture(
            interface=interface,
            filter_str=photon_filter,
            async_mode=async_mode
        )
    
    def stop_capture(self) -> bool:
        """
        Para a captura de pacotes Photon.
        
        Returns:
            True se a captura foi parada com sucesso, False caso contrário.
        """
        return self.pcap_manager.stop_capture()
    
    def is_capturing(self) -> bool:
        """
        Verifica se a captura está em andamento.
        
        Returns:
            True se a captura está em andamento, False caso contrário.
        """
        return self.pcap_manager.is_capturing()
    
    def get_available_interfaces(self) -> List[Dict[str, str]]:
        """
        Retorna uma lista de interfaces de rede disponíveis para captura.
        
        Returns:
            Lista de dicionários com informações sobre as interfaces.
        """
        return self.pcap_manager.get_available_interfaces() 