"""
Módulo de captura de pacotes para o AO-Noki Sniffer.

Este módulo fornece classes para captura de pacotes usando pcap.
Implementa captura de pacotes específicos do protocolo Photon.
"""

import logging
import time
import threading
from typing import Dict, Any, List, Optional, Callable, Set

logger = logging.getLogger("sniffer.platform.pcaptura")

# Tentar importar pcap
try:
    import scapy.all as scapy
    scapy_available = True
except ImportError:
    logger.warning("Scapy não está disponível. A captura de pacotes será limitada.")
    scapy_available = False

class PacketHandler:
    """
    Classe base para manipulação de pacotes.
    
    Esta classe define a interface para manipuladores de pacotes.
    Implementações concretas devem estender esta classe.
    """
    
    def handle_packet(self, packet: Any) -> Dict[str, Any]:
        """
        Processa um pacote capturado.
        
        Args:
            packet: Dados do pacote capturado
            
        Returns:
            Dicionário com os dados do pacote processado
        """
        raise NotImplementedError("Método abstrato deve ser implementado em classe concreta")
    
    def _convert_packet(self, raw_packet: Any) -> Dict[str, Any]:
        """
        Converte um pacote bruto para o formato padrão.
        
        Args:
            raw_packet: Pacote no formato nativo da biblioteca de captura
            
        Returns:
            Dicionário com os dados do pacote no formato padrão
        """
        raise NotImplementedError("Método abstrato deve ser implementado em classe concreta")


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
    
    def handle_packet(self, packet: scapy.Packet) -> Dict[str, Any]:
        """
        Processa um pacote capturado pelo Scapy.
        
        Args:
            packet: Pacote capturado pelo Scapy
            
        Returns:
            Dicionário com os dados do pacote processado
        """
        return self._convert_packet(packet)


class PcapManager:
    """
    Gerenciador de captura de pacotes usando pcap.
    
    Esta classe fornece métodos para iniciar e parar a captura de pacotes,
    bem como para adicionar callbacks para processamento de pacotes.
    """
    
    def __init__(self, packet_handler: Optional[PacketHandler] = None):
        """
        Inicializa o gerenciador de captura.
        
        Args:
            packet_handler: Manipulador de pacotes opcional
        """
        self.packet_handler = packet_handler or ScapyPacketHandler()
        self.sniffer = None
        self.running = False
        self.sniffer_thread: Optional[threading.Thread] = None
        self.callbacks: List[Callable[[Dict[str, Any]], None]] = []
        
        # Verificar disponibilidade da biblioteca
        if not scapy_available:
            logger.error("Scapy não está disponível. A captura de pacotes não funcionará.")
    
    def add_packet_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        Adiciona um callback para processamento de pacotes.
        
        Args:
            callback: Função a ser chamada para cada pacote
        """
        self.callbacks.append(callback)
    
    def _handle_packet(self, packet: Any) -> None:
        """
        Manipula um pacote capturado.
        
        Args:
            packet: Pacote capturado no formato nativo da biblioteca
        """
        try:
            # Converter usando o manipulador de pacotes
            packet_data = self.packet_handler.handle_packet(packet)
            
            # Chamar todos os callbacks registrados
            for callback in self.callbacks:
                try:
                    callback(packet_data)
                except Exception as e:
                    logger.error(f"Erro em callback de pacote: {e}")
        
        except Exception as e:
            logger.error(f"Erro ao processar pacote: {e}")
    
    def _sniffer_loop(self, interface: str, filter_str: str) -> None:
        """
        Loop principal do sniffer.
        
        Args:
            interface: Interface de rede para captura
            filter_str: Filtro BPF para captura
        """
        if not scapy_available:
            logger.error("Scapy não está disponível. Loop de captura não iniciado.")
            return
        
        try:
            logger.info(f"Iniciando captura na interface {interface} com filtro '{filter_str}'")
            
            # Usar Scapy para captura
            self.running = True
            scapy.sniff(
                iface=interface,
                filter=filter_str,
                store=False,
                prn=self._handle_packet,
                stop_filter=lambda _: not self.running
            )
            
            logger.info("Captura encerrada")
            
        except Exception as e:
            logger.error(f"Erro no loop de captura: {e}")
            self.running = False
    
    def start_capture(self, interface: str = "", filter_str: str = "", async_mode: bool = True) -> bool:
        """
        Inicia a captura de pacotes.
        
        Args:
            interface: Interface de rede para captura (vazio para auto-detecção)
            filter_str: Filtro BPF para captura (vazio para capturar tudo)
            async_mode: Se True, a captura é feita em um thread separado
            
        Returns:
            True se a captura foi iniciada com sucesso, False caso contrário
        """
        if not scapy_available:
            logger.error("Scapy não está disponível. Captura não iniciada.")
            return False
        
        if self.running:
            logger.warning("Captura já está em execução")
            return False
        
        try:
            # Se interface não foi especificada, tentar detectar
            if not interface:
                interfaces = self.get_available_interfaces()
                if not interfaces:
                    logger.error("Nenhuma interface disponível para captura")
                    return False
                
                # Usar a primeira interface disponível
                interface = interfaces[0]["name"]
                logger.info(f"Interface auto-detectada: {interface}")
            
            # Iniciar captura
            if async_mode:
                self.sniffer_thread = threading.Thread(
                    target=self._sniffer_loop,
                    args=(interface, filter_str),
                    daemon=True
                )
                self.sniffer_thread.start()
                logger.debug(f"Thread de captura iniciada: {self.sniffer_thread.name}")
                return True
            else:
                # Modo síncrono (bloqueia até encerrar)
                self._sniffer_loop(interface, filter_str)
                return True
            
        except Exception as e:
            logger.error(f"Erro ao iniciar captura: {e}")
            return False
    
    def stop_capture(self) -> bool:
        """
        Para a captura de pacotes.
        
        Returns:
            True se a captura foi parada com sucesso, False caso contrário
        """
        if not self.running:
            logger.warning("Captura não está em execução")
            return False
        
        try:
            # Sinalizar para o loop de captura parar
            self.running = False
            
            # Aguardar a thread terminar (máximo 5 segundos)
            if self.sniffer_thread and self.sniffer_thread.is_alive():
                self.sniffer_thread.join(timeout=5.0)
                
                # Se a thread não terminou, forçar encerramento
                if self.sniffer_thread.is_alive():
                    logger.warning("Thread de captura não encerrou normalmente")
                
            logger.info("Captura parada com sucesso")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao parar captura: {e}")
            return False
    
    def is_capturing(self) -> bool:
        """
        Verifica se a captura está em andamento.
        
        Returns:
            True se a captura está em andamento, False caso contrário
        """
        return self.running and (self.sniffer_thread is None or self.sniffer_thread.is_alive())
    
    def get_available_interfaces(self) -> List[Dict[str, str]]:
        """
        Retorna uma lista de interfaces de rede disponíveis para captura.
        
        Returns:
            Lista de dicionários com informações sobre as interfaces
        """
        interfaces = []
        
        if not scapy_available:
            logger.error("Scapy não está disponível. Não é possível listar interfaces.")
            return interfaces
        
        try:
            # Usar Scapy para listar interfaces
            if_list = scapy.get_if_list()
            
            for iface in if_list:
                try:
                    # Obter MAC address
                    mac = scapy.get_if_hwaddr(iface)
                    # Obter IP (se disponível)
                    ip = scapy.get_if_addr(iface)
                    
                    interfaces.append({
                        "name": iface,
                        "mac": mac,
                        "ip": ip
                    })
                except Exception as e:
                    logger.warning(f"Erro ao obter informações da interface {iface}: {e}")
            
            return interfaces
            
        except Exception as e:
            logger.error(f"Erro ao listar interfaces: {e}")
            return interfaces


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
        self.photon_callbacks: List[Callable[[Dict[str, Any]], None]] = []
        
        # Registrar callback para filtragem de pacotes Photon
        self.pcap_manager.add_packet_callback(self._filter_photon_packet)
    
    def add_photon_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
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