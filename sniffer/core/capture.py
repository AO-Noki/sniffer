"""
Módulo de captura de pacotes para o AO-Noki Sniffer.

Este módulo é responsável por gerenciar a captura de tráfego de rede,
especificamente focado no protocolo Photon usado pelo Albion Online.
"""

import logging
import threading
import time
from typing import Dict, Any, Optional, List, Callable

from sniffer.config import CONFIG
from sniffer.photon import PhotonCaptureHandler
from sniffer.platform.pcaptura import PhotonCapture

logger = logging.getLogger("sniffer.core.capture")

class PacketCaptureManager:
    """
    Gerenciador de captura de pacotes.
    
    Esta classe é responsável por:
    - Gerenciar a captura de pacotes de rede
    - Filtrar e processar pacotes do protocolo Photon
    - Distribuir os pacotes capturados para os handlers registrados
    """
    
    def __init__(self):
        """Inicializa o gerenciador de captura."""
        self.capture: Optional[PhotonCapture] = None
        self.handler: Optional[PhotonCaptureHandler] = None
        self.capture_thread: Optional[threading.Thread] = None
        self.running = False
        self.callbacks: List[Callable[[Dict[str, Any]], None]] = []
        
        # Configurações
        self.interface = CONFIG.get("network", "interface", "auto")
        self.port = CONFIG.get("network", "port", 5056)
        self.protocol = CONFIG.get("network", "protocol", "UDP")
        
        logger.info(f"PacketCaptureManager inicializado (interface: {self.interface}, porta: {self.port})")
    
    def add_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        Adiciona um callback para receber pacotes capturados.
        
        Args:
            callback: Função a ser chamada quando um pacote for capturado
        """
        self.callbacks.append(callback)
        logger.debug(f"Callback adicionado: {callback.__name__}")
    
    def remove_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        Remove um callback registrado.
        
        Args:
            callback: Função a ser removida
        """
        if callback in self.callbacks:
            self.callbacks.remove(callback)
            logger.debug(f"Callback removido: {callback.__name__}")
    
    def _handle_packet(self, packet: Dict[str, Any]) -> None:
        """
        Manipula um pacote capturado.
        
        Args:
            packet: Dados do pacote capturado
        """
        if not self.running:
            return
        
        try:
            # Processar o pacote com o handler Photon
            if self.handler:
                self.handler.handle_packet(packet)
            
            # Notificar callbacks
            for callback in self.callbacks:
                try:
                    callback(packet)
                except Exception as e:
                    logger.error(f"Erro em callback de pacote: {e}")
        
        except Exception as e:
            logger.error(f"Erro ao processar pacote: {e}")
    
    def start(self) -> bool:
        """
        Inicia a captura de pacotes.
        
        Returns:
            True se a captura foi iniciada com sucesso, False caso contrário
        """
        if self.running:
            logger.warning("A captura já está em execução")
            return False
        
        try:
            # Inicializar capturador Photon
            self.capture = PhotonCapture()
            self.handler = PhotonCaptureHandler()
            
            # Registrar callback para processamento de pacotes
            self.capture.add_photon_callback(self._handle_packet)
            
            # Iniciar captura em modo assíncrono
            if not self.capture.start_capture(self.interface, async_mode=True):
                logger.error("Falha ao iniciar captura")
                return False
            
            self.running = True
            logger.info(f"Captura iniciada na interface {self.interface}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao iniciar captura: {e}")
            return False
    
    def stop(self) -> bool:
        """
        Para a captura de pacotes.
        
        Returns:
            True se a captura foi parada com sucesso, False caso contrário
        """
        if not self.running:
            logger.warning("A captura já está parada")
            return False
        
        try:
            if self.capture:
                self.capture.stop_capture()
            
            self.running = False
            logger.info("Captura parada")
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
        if not self.running or not self.capture:
            return False
        return self.capture.is_capturing() or False
    
    def get_available_interfaces(self) -> List[Dict[str, str]]:
        """
        Retorna uma lista de interfaces de rede disponíveis para captura.
        
        Returns:
            Lista de dicionários com informações sobre as interfaces
        """
        if self.capture:
            return self.capture.get_available_interfaces()
        return [] 