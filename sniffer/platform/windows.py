"""
Módulo de suporte específico para plataforma Windows.

Este módulo implementa as funcionalidades específicas para Windows, incluindo:
- Captura de pacotes usando Npcap/WinPcap
- Instalação e gestão de serviços do Windows
- Detecção e configuração de interfaces de rede
- Gestão de recursos do sistema
"""

import os
import sys
import subprocess
import ctypes
import logging
import winreg
from typing import List, Dict, Optional, Tuple, Union, Any, Callable, Mapping
import asyncio
import platform

# Importações locais
from .pcaptura import PcapManager as BasePcapManager
from .pcaptura import PcapInstaller, PhotonCapture, SCAPY_AVAILABLE

# Configuração do logger
logger = logging.getLogger("sniffer.platform.windows")

class WindowsServiceManager:
    """Gerenciador de serviços para o Windows."""
    
    SERVICE_NAME = "AONokiSniffer"
    DISPLAY_NAME = "AO-Noki Photon Sniffer"
    SERVICE_DESCRIPTION = "Captura e analisa pacotes do protocolo Photon para jogos online."
    
    def __init__(self):
        self.service_path = os.path.abspath(sys.argv[0])
        self.is_admin = self._check_admin()
    
    def _check_admin(self) -> bool:
        """Verifica se o processo atual possui privilégios de administrador."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception as e:
            logger.warning(f"Falha ao verificar privilégios de administrador: {e}")
            return False
    
    def install_service(self) -> bool:
        """Instala o aplicativo como um serviço do Windows."""
        if not self._check_admin():
            logger.error("Privilégios de administrador são necessários para instalar o serviço.")
            return False
        
        try:
            # Usamos sc.exe para instalar o serviço
            cmd = [
                "sc", "create", self.SERVICE_NAME,
                "binPath=", f'"{self.service_path}" -service',
                "start=", "auto",
                "DisplayName=", self.DISPLAY_NAME
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            
            # Adicionar descrição ao serviço
            description_cmd = [
                "sc", "description", self.SERVICE_NAME, 
                f'"{self.SERVICE_DESCRIPTION}"'
            ]
            subprocess.run(description_cmd, capture_output=True, text=True, check=True)
            
            # Configurar opções de recuperação (reiniciar após falha)
            recovery_cmd = [
                "sc", "failure", self.SERVICE_NAME,
                "reset=", "86400",  # Reset após 24 horas
                "actions=", "restart/60000/restart/120000/restart/300000"  # Tentar reiniciar 3x
            ]
            subprocess.run(recovery_cmd, capture_output=True, text=True, check=True)
            
            logger.info(f"Serviço '{self.SERVICE_NAME}' instalado com sucesso.")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Falha ao instalar serviço: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Erro ao instalar serviço: {e}")
            return False
    
    def uninstall_service(self) -> bool:
        """Remove o serviço do sistema."""
        if not self._check_admin():
            logger.error("Privilégios de administrador são necessários para desinstalar o serviço.")
            return False
        
        try:
            # Primeiro paramos o serviço se estiver em execução
            stop_cmd = ["sc", "stop", self.SERVICE_NAME]
            subprocess.run(stop_cmd, capture_output=True, text=True)
            
            # Agora removemos o serviço
            delete_cmd = ["sc", "delete", self.SERVICE_NAME]
            result = subprocess.run(delete_cmd, capture_output=True, text=True, check=True)
            
            logger.info(f"Serviço '{self.SERVICE_NAME}' removido com sucesso.")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Falha ao remover serviço: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Erro ao remover serviço: {e}")
            return False
    
    def start_service(self) -> bool:
        """Inicia o serviço instalado."""
        if not self._check_admin():
            logger.error("Privilégios de administrador são necessários para iniciar o serviço.")
            return False
        
        try:
            cmd = ["sc", "start", self.SERVICE_NAME]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info(f"Serviço '{self.SERVICE_NAME}' iniciado com sucesso.")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Falha ao iniciar serviço: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Erro ao iniciar serviço: {e}")
            return False
    
    def stop_service(self) -> bool:
        """Para o serviço em execução."""
        if not self._check_admin():
            logger.error("Privilégios de administrador são necessários para parar o serviço.")
            return False
        
        try:
            cmd = ["sc", "stop", self.SERVICE_NAME]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            logger.info(f"Serviço '{self.SERVICE_NAME}' parado com sucesso.")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Falha ao parar serviço: {e.stderr}")
            return False
        except Exception as e:
            logger.error(f"Erro ao parar serviço: {e}")
            return False
    
    def get_service_status(self) -> Optional[str]:
        """Verifica o status atual do serviço."""
        try:
            cmd = ["sc", "query", self.SERVICE_NAME]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode != 0:
                return None  # Serviço não existe
            
            output = result.stdout
            
            if "RUNNING" in output:
                return "running"
            elif "STOPPED" in output:
                return "stopped"
            elif "START_PENDING" in output:
                return "starting"
            elif "STOP_PENDING" in output:
                return "stopping"
            else:
                return "unknown"
                
        except Exception as e:
            logger.error(f"Erro ao verificar status do serviço: {e}")
            return None

class WindowsPcapManager:
    """Gerenciador de captura de pacotes para Windows usando Npcap/WinPcap."""
    
    def __init__(self):
        """Inicializa o gerenciador de pacotes Windows."""
        # Verificar se o Npcap/WinPcap está instalado
        self.is_npcap_installed = self._check_npcap_installed()
        self.is_winpcap_installed = self._check_winpcap_installed() if not self.is_npcap_installed else False
        
        # Inicializar o gerenciador de captura
        self.pcap_manager = None
        if SCAPY_AVAILABLE:
            self.pcap_manager = BasePcapManager()
        
        # Verificar se a captura está disponível
        self.capture_available = SCAPY_AVAILABLE and (self.is_npcap_installed or self.is_winpcap_installed)
        
        # Inicializar o capturador Photon quando disponível
        self.photon_capture = None
        if self.capture_available and self.pcap_manager:
            self.photon_capture = PhotonCapture(self.pcap_manager)
    
    def _check_npcap_installed(self) -> bool:
        """Verifica se o Npcap está instalado no sistema."""
        try:
            # Verificar registro do Windows
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap") as key:
                return True
        except WindowsError:
            return False
    
    def _check_winpcap_installed(self) -> bool:
        """Verifica se o WinPcap está instalado no sistema."""
        try:
            # Verificar registro do Windows
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WinPcap") as key:
                return True
        except WindowsError:
            return False
    
    def get_network_interfaces(self) -> List[Dict[str, str]]:
        """
        Obtém a lista de interfaces de rede disponíveis para captura.
        
        Returns:
            Lista de dicionários com informações sobre as interfaces.
        """
        if self.capture_available and self.pcap_manager:
            # Usar o gerenciador pcap para obter interfaces
            return self.pcap_manager.get_available_interfaces()
        
        # Fallback para usar ipconfig se o pcap não estiver disponível
        interfaces = []
        
        try:
            # Obter interfaces via ipconfig
            cmd = ["ipconfig", "/all"]
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='cp850')
            
            if result.returncode == 0:
                output = result.stdout
                sections = output.split("\n\n")
                
                for section in sections:
                    if "Adaptador" in section or "Ethernet" in section or "Wi-Fi" in section:
                        lines = section.split("\n")
                        interface_name = lines[0].strip(":")
                        
                        interface_info = {
                            "name": interface_name,
                            "description": interface_name,
                            "mac": "Desconhecido",
                            "ip": "Desconhecido"
                        }
                        
                        for line in lines:
                            if "Descrição" in line:
                                interface_info["description"] = line.split(":")[1].strip()
                            elif "Endereço Físico" in line or "Physical Address" in line:
                                interface_info["mac"] = line.split(":")[1].strip()
                            elif "Endereço IPv4" in line or "IPv4 Address" in line:
                                interface_info["ip"] = line.split(":")[1].strip().replace("(Preferencial)", "").strip()
                        
                        interfaces.append(interface_info)
            
            return interfaces
        except Exception as e:
            logger.error(f"Erro ao obter interfaces de rede: {e}")
            return []
    
    def start_capture(self, interface: str, filter_str: str = "", async_mode: bool = True) -> bool:
        """
        Inicia a captura de pacotes na interface especificada.
        
        Args:
            interface: Nome ou índice da interface para captura.
            filter_str: Filtro de pacotes (formato BPF).
            async_mode: Se True, a captura é feita em um thread separado.
            
        Returns:
            True se a captura foi iniciada com sucesso, False caso contrário.
        """
        if not self.capture_available or not self.pcap_manager:
            logger.error("Captura de pacotes não disponível. Npcap/WinPcap não instalado ou Scapy não disponível.")
            return False
        
        return self.pcap_manager.start_capture(interface, filter_str, async_mode)
    
    def start_photon_capture(self, interface: str, async_mode: bool = True) -> bool:
        """
        Inicia a captura de pacotes Photon na interface especificada.
        
        Args:
            interface: Nome ou índice da interface para captura.
            async_mode: Se True, a captura é feita em um thread separado.
            
        Returns:
            True se a captura foi iniciada com sucesso, False caso contrário.
        """
        if not self.capture_available or not self.photon_capture:
            logger.error("Captura de pacotes Photon não disponível.")
            return False
        
        return self.photon_capture.start_capture(interface, async_mode)
    
    def stop_capture(self) -> bool:
        """
        Para a captura de pacotes em andamento.
        
        Returns:
            True se a captura foi parada com sucesso, False caso contrário.
        """
        if not self.capture_available or not self.pcap_manager:
            return False
        
        if self.pcap_manager.is_capturing():
            return self.pcap_manager.stop_capture()
        
        return True
    
    def add_packet_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        Adiciona uma função de callback para processar pacotes capturados.
        
        Args:
            callback: Função que será chamada para cada pacote capturado.
        """
        if self.capture_available and self.pcap_manager:
            self.pcap_manager.add_packet_callback(callback)
    
    def add_photon_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """
        Adiciona uma função de callback para processar pacotes Photon capturados.
        
        Args:
            callback: Função que será chamada para cada pacote Photon capturado.
        """
        if self.capture_available and self.photon_capture:
            self.photon_capture.add_photon_callback(callback)
    
    def is_capturing(self) -> bool:
        """
        Verifica se a captura está em andamento.
        
        Returns:
            True se a captura está em andamento, False caso contrário.
        """
        if not self.capture_available or not self.pcap_manager:
            return False
        
        return self.pcap_manager.is_capturing()
    
    def download_npcap_installer(self, target_path: str) -> bool:
        """
        Baixa o instalador do Npcap para o caminho especificado.
        
        Args:
            target_path: Caminho onde o instalador será salvo
            
        Returns:
            bool: True se o download for bem-sucedido, False caso contrário
        """
        try:
            import urllib.request
            
            # URL do instalador do Npcap
            npcap_url = "https://npcap.com/dist/npcap-1.75.exe"
            
            logger.info(f"Baixando Npcap de {npcap_url} para {target_path}")
            urllib.request.urlretrieve(npcap_url, target_path)
            
            return os.path.exists(target_path)
        except Exception as e:
            logger.error(f"Erro ao baixar instalador do Npcap: {e}")
            return False
    
    def install_npcap(self, installer_path: Optional[str] = None) -> bool:
        """
        Instala o Npcap se não estiver presente no sistema.
        
        Args:
            installer_path: Caminho para o instalador do Npcap, se já estiver baixado
            
        Returns:
            bool: True se a instalação foi bem-sucedida, False caso contrário
        """
        # Se o Npcap já estiver instalado, não fazer nada
        if self.is_npcap_installed:
            logger.info("Npcap já está instalado.")
            return True
        
        # Usar o instalador do módulo pcaptura
        result = PcapInstaller.install_pcap()
        
        # Atualizar status de instalação se foi bem sucedido
        if result:
            self.is_npcap_installed = True
            
            # Inicializar o gerenciador de captura e o Photon se não estiver inicializado
            if not self.pcap_manager and SCAPY_AVAILABLE:
                self.pcap_manager = BasePcapManager()
                self.photon_capture = PhotonCapture(self.pcap_manager)
                self.capture_available = True
        
        return result

class WindowsSystemInfo:
    """Fornece informações sobre o sistema Windows."""
    
    @staticmethod
    def get_windows_version() -> Mapping[str, Union[str, int]]:
        """Obtém informações detalhadas sobre a versão do Windows."""
        try:
            version_info = platform.win32_ver()
            version = platform.version()
            
            # Obter informações adicionais do sistema operacional
            system_info = {
                "version": version,
                "release": version_info[0],
                "build": version_info[1],
                "service_pack": version_info[2],
                "processor": platform.processor(),
                "architecture": platform.architecture()[0],
                "machine": platform.machine(),
                "system": platform.system()
            }
            
            return system_info
        except Exception as e:
            logger.error(f"Erro ao obter informações do sistema: {e}")
            return {"error": str(e)}
    
    @staticmethod
    def is_compatible() -> bool:
        """Verifica se o sistema é compatível com o sniffer."""
        try:
            # Verificar versão do Windows (Windows 7 ou superior)
            win_ver = platform.win32_ver()[0]
            major_version = int(win_ver.split('.')[0]) if '.' in win_ver else int(win_ver)
            
            # Windows 7 é versão 6.1, Windows 8 é 6.2/6.3, Windows 10 é 10.0
            return major_version >= 6
        except Exception as e:
            logger.error(f"Erro ao verificar compatibilidade: {e}")
            return False
    
    @staticmethod
    async def monitor_system_resources() -> Mapping[str, Union[float, str]]:
        """
        Monitora recursos do sistema em tempo real.
        
        Returns:
            Dict com informações de CPU, memória e disco.
        """
        try:
            # Usando wmic para obter informações (versão assíncrona)
            cpu_cmd = "wmic cpu get LoadPercentage"
            memory_cmd = "wmic OS get FreePhysicalMemory,TotalVisibleMemorySize"
            
            # Executar os comandos de forma assíncrona
            cpu_proc = await asyncio.create_subprocess_shell(
                cpu_cmd, 
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            cpu_stdout, _ = await cpu_proc.communicate()
            
            memory_proc = await asyncio.create_subprocess_shell(
                memory_cmd, 
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            memory_stdout, _ = await memory_proc.communicate()
            
            # Processar saída de CPU
            cpu_output = cpu_stdout.decode().strip().split('\n')
            cpu_percent = float(cpu_output[1].strip()) if len(cpu_output) > 1 else 0.0
            
            # Processar saída de memória
            memory_output = memory_stdout.decode().strip().split('\n')
            if len(memory_output) > 1:
                memory_values = memory_output[1].split()
                if len(memory_values) >= 2:
                    free_memory = float(memory_values[0]) / 1024  # Converter para MB
                    total_memory = float(memory_values[1]) / 1024  # Converter para MB
                    memory_used_percent = ((total_memory - free_memory) / total_memory) * 100
                else:
                    free_memory = total_memory = memory_used_percent = 0.0
            else:
                free_memory = total_memory = memory_used_percent = 0.0
            
            return {
                "cpu_percent": cpu_percent,
                "memory_percent": memory_used_percent,
                "memory_free_mb": free_memory,
                "memory_total_mb": total_memory
            }
        except Exception as e:
            logger.error(f"Erro ao monitorar recursos do sistema: {e}")
            return {
                "cpu_percent": 0.0,
                "memory_percent": 0.0,
                "memory_free_mb": 0.0,
                "memory_total_mb": 0.0,
                "error": str(e)
            }

# Função para verificar se está rodando como serviço do Windows
def is_running_as_service() -> bool:
    """Verifica se o aplicativo está rodando como um serviço do Windows."""
    try:
        # No Windows, os serviços não tem um console interativo
        return not sys.stdin.isatty()
    except (AttributeError, IOError):
        # Se ocorrer erro ao acessar stdin, provavelmente é um serviço
        return True

# Função para obter privilégios de administrador, se necessário
def request_admin_privileges() -> bool:
    """
    Solicita privilégios de administrador se o programa não estiver 
    rodando com esses privilégios.
    
    Returns:
        bool: True se já possui privilégios ou a solicitação foi feita,
              False se não foi possível solicitar.
    """
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            return True
            
        # Se não tiver privilégios, tentar reexecutar como administrador
        script = os.path.abspath(sys.argv[0])
        params = ' '.join(sys.argv[1:])
        
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1
        )
        
        # Retorna True para indicar que a solicitação foi feita
        # O programa original deve ser encerrado após chamar esta função
        return True
        
    except Exception as e:
        logger.error(f"Erro ao solicitar privilégios de administrador: {e}")
        return False 