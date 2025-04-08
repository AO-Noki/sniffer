"""
Módulo de plataforma para o AO-Noki Sniffer.

Este módulo fornece classes e funções para interagir com
recursos específicos da plataforma do sistema operacional.
"""

import logging
import platform
import sys
import os
import subprocess
import re
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger("sniffer.platform")

# Tentativa de importar dependências opcionais
try:
    import distro  # type: ignore # noqa: F401 - Disponível apenas em algumas plataformas
    HAS_DISTRO = True
except ImportError:
    HAS_DISTRO = False
    logger.debug("Módulo 'distro' não disponível. Funcionalidade limitada.")

# Dicionário de plataformas suportadas
SUPPORTED_PLATFORMS = {
    "windows": ["Windows", "win32"],
    "linux": ["Linux"],
    "darwin": ["Darwin", "macOS"]
}

# Mapeamento de nomes de plataforma
PLATFORM_NAMES = {
    "win32": "windows",
    "linux": "linux",
    "darwin": "darwin"
}

def get_platform() -> str:
    """
    Detecta a plataforma atual.
    
    Returns:
        String com o nome normalizado da plataforma
    """
    system = platform.system().lower()
    
    if system == "windows" or system == "win32":
        return "windows"
    elif system == "linux":
        return "linux"
    elif system == "darwin":
        return "darwin"
    else:
        return "unknown"

def get_system_info() -> Dict[str, str]:
    """
    Obtém informações detalhadas sobre o sistema.
    
    Returns:
        Dicionário com informações do sistema
    """
    system_info = {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "is_64bits": "Yes" if sys.maxsize > 2**32 else "No"
    }
    
    platform_name = get_platform()
    
    # Detalhes específicos para Windows
    if platform_name == "windows":
        win_ver = platform.win32_ver()
        system_info.update({
            "win_version": win_ver[0],
            "win_edition": win_ver[1],
            "win_sp": win_ver[2],
            "win_build": win_ver[3],
        })
    
    # Detalhes específicos para Linux
    elif platform_name == "linux":
        try:
            # Usar o módulo distro se disponível
            if HAS_DISTRO:
                system_info.update({
                    "linux_distro": distro.name(),
                    "linux_version": distro.version(),
                    "linux_id": distro.id(),
                })
            else:
                # Alternativa simples se 'distro' não estiver disponível
                system_info.update({
                    "linux_distro": "Unknown",
                    "linux_version": "Unknown",
                    "linux_id": "Unknown",
                })
        except Exception as e:
            logger.warning(f"Erro ao obter informações do Linux: {e}")
            
    # Detalhes específicos para macOS
    elif platform_name == "darwin":
        mac_ver = platform.mac_ver()
        system_info.update({
            "macos_version": mac_ver[0],
            "macos_build": mac_ver[2],
        })
    
    return system_info

def is_platform_supported() -> bool:
    """
    Verifica se a plataforma atual é suportada.
    
    Returns:
        True se a plataforma for suportada, False caso contrário
    """
    current_platform = get_platform()
    
    if current_platform in SUPPORTED_PLATFORMS:
        logger.info(f"Plataforma {current_platform} é suportada.")
        return True
    else:
        logger.warning(f"Plataforma {current_platform} não é suportada oficialmente.")
        return False

def check_admin() -> bool:
    """
    Verifica se o aplicativo está sendo executado com privilégios de administrador.
    
    Returns:
        True se o aplicativo está rodando como administrador, False caso contrário
    """
    platform_name = get_platform()
    
    if platform_name == "windows":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception as e:
            logger.error(f"Erro ao verificar privilégios de administrador no Windows: {e}")
            return False
    elif platform_name == "linux" or platform_name == "darwin":
        try:
            # Métodos diferentes para verificar privilégios em sistemas Unix
            if sys.platform != "win32":
                try:
                    # Método 1: Usar os.geteuid() se disponível (Linux/macOS)
                    return os.geteuid() == 0
                except AttributeError:
                    # Método 2: Usar comando id se geteuid não estiver disponível
                    result = subprocess.run(['id', '-u'], 
                                          capture_output=True, 
                                          text=True, 
                                          shell=True,
                                          check=False)
                    return result.stdout.strip() == '0'
            else:
                return False
        except Exception as e:
            logger.error(f"Erro ao verificar privilégios de superusuário: {e}")
            return False
    else:
        logger.warning(f"Verificação de privilégios não implementada para plataforma {platform_name}")
        return False

def is_service_installed(service_name: str) -> bool:
    """
    Verifica se um serviço está instalado no sistema.
    
    Args:
        service_name: Nome do serviço a verificar
        
    Returns:
        True se o serviço estiver instalado, False caso contrário
    """
    platform_name = get_platform()
    
    if platform_name == "windows":
        try:
            process = subprocess.run(
                ["sc", "query", service_name], 
                capture_output=True, 
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            
            # Se o serviço não existe, o SC retorna um código diferente de zero
            if process.returncode != 0:
                return False
                
            # Verifica na saída se o serviço está instalado
            service_exist_pattern = re.compile(r"SERVICE_NAME:\s+" + service_name, re.IGNORECASE)
            return bool(service_exist_pattern.search(process.stdout))
        except Exception as e:
            logger.error(f"Erro ao verificar se o serviço está instalado: {e}")
            return False
    elif platform_name == "linux":
        try:
            # Verifica usando systemctl
            process = subprocess.run(
                ["systemctl", "list-unit-files", f"{service_name}.service"], 
                capture_output=True, 
                text=True
            )
            return process.returncode == 0 and service_name in process.stdout
        except Exception as e:
            logger.error(f"Erro ao verificar serviço no Linux: {e}")
            return False
    elif platform_name == "darwin":
        try:
            # Verifica usando launchctl
            process = subprocess.run(
                ["launchctl", "list", service_name], 
                capture_output=True, 
                text=True
            )
            return process.returncode == 0
        except Exception as e:
            logger.error(f"Erro ao verificar serviço no macOS: {e}")
            return False
    else:
        logger.warning(f"Verificação de serviço não implementada para plataforma {platform_name}")
        return False

def install_service(service_name: str, binary_path: str, display_name: str) -> bool:
    """
    Instala o aplicativo como um serviço do sistema.
    
    Args:
        service_name: Nome do serviço
        binary_path: Caminho para o executável do serviço
        display_name: Nome de exibição do serviço
        
    Returns:
        True se o serviço foi instalado com sucesso, False caso contrário
    """
    platform_name = get_platform()
    
    if platform_name == "windows":
        try:
            # Verificar se o serviço já está instalado
            if is_service_installed(service_name):
                logger.info(f"Serviço '{service_name}' já está instalado.")
                return True
            
            # Comando para criar o serviço
            service_cmd = [
                "sc", "create", service_name, 
                "binPath=", f'"{binary_path}" -service',
                "DisplayName=", display_name,
                "start=", "auto",
                "type=", "own"
            ]
            
            process = subprocess.run(
                service_cmd, 
                capture_output=True, 
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            
            if process.returncode != 0:
                logger.error(f"Erro ao criar serviço: {process.stderr}")
                return False
            
            logger.info(f"Serviço '{service_name}' instalado com sucesso.")
            return True
        except Exception as e:
            logger.error(f"Erro ao instalar serviço no Windows: {e}")
            return False
    elif platform_name == "linux":
        try:
            # Verificar se o serviço já existe
            if is_service_installed(service_name):
                logger.info(f"Serviço '{service_name}' já está instalado.")
                return True
            
            # Criar arquivo de serviço systemd
            service_file = f"""[Unit]
Description={display_name}
After=network.target

[Service]
ExecStart={binary_path} -service
Restart=on-failure
User=root
Group=root

[Install]
WantedBy=multi-user.target
"""
            try:
                # Gravar arquivo de serviço
                service_path = f"/etc/systemd/system/{service_name}.service"
                with open(service_path, 'w') as f:
                    f.write(service_file)
                
                # Recarregar daemon, habilitar e iniciar serviço
                subprocess.run(["systemctl", "daemon-reload"], check=True)
                subprocess.run(["systemctl", "enable", f"{service_name}.service"], check=True)
                
                logger.info(f"Serviço '{service_name}' instalado com sucesso.")
                return True
            except Exception as e:
                logger.error(f"Erro ao criar arquivo de serviço systemd: {e}")
                return False
        except Exception as e:
            logger.error(f"Erro ao instalar serviço no Linux: {e}")
            return False
    elif platform_name == "darwin":
        try:
            # Verificar se o serviço já existe
            if is_service_installed(service_name):
                logger.info(f"Serviço '{service_name}' já está instalado.")
                return True
            
            # Criar arquivo plist
            plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{service_name}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary_path}</string>
        <string>-service</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"""
            try:
                # Gravar arquivo plist
                plist_path = f"/Library/LaunchDaemons/{service_name}.plist"
                with open(plist_path, 'w') as f:
                    f.write(plist_content)
                
                # Definir permissões e carregar o serviço
                subprocess.run(["chmod", "644", plist_path], check=True)
                subprocess.run(["launchctl", "load", plist_path], check=True)
                
                logger.info(f"Serviço '{service_name}' instalado com sucesso.")
                return True
            except Exception as e:
                logger.error(f"Erro ao criar arquivo plist: {e}")
                return False
        except Exception as e:
            logger.error(f"Erro ao instalar serviço no macOS: {e}")
            return False
    else:
        logger.warning(f"Instalação de serviço não implementada para plataforma {platform_name}")
        return False

def uninstall_service(service_name: str) -> bool:
    """
    Remove o serviço do sistema.
    
    Args:
        service_name: Nome do serviço a remover
        
    Returns:
        True se o serviço foi removido com sucesso, False caso contrário
    """
    platform_name = get_platform()
    
    if platform_name == "windows":
        try:
            # Verificar se o serviço está instalado
            if not is_service_installed(service_name):
                logger.info(f"Serviço '{service_name}' não está instalado.")
                return True
            
            # Parar o serviço primeiro (se estiver em execução)
            stop_cmd = ["sc", "stop", service_name]
            subprocess.run(
                stop_cmd, 
                capture_output=True, 
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            
            # Comando para remover o serviço
            delete_cmd = ["sc", "delete", service_name]
            process = subprocess.run(
                delete_cmd, 
                capture_output=True, 
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            
            if process.returncode != 0:
                logger.error(f"Erro ao remover serviço: {process.stderr}")
                return False
            
            logger.info(f"Serviço '{service_name}' removido com sucesso.")
            return True
        except Exception as e:
            logger.error(f"Erro ao remover serviço no Windows: {e}")
            return False
    elif platform_name == "linux":
        try:
            # Verificar se o serviço está instalado
            if not is_service_installed(service_name):
                logger.info(f"Serviço '{service_name}' não está instalado.")
                return True
            
            # Parar e desabilitar o serviço
            subprocess.run(["systemctl", "stop", f"{service_name}.service"], check=False)
            subprocess.run(["systemctl", "disable", f"{service_name}.service"], check=False)
            
            # Remover arquivo de serviço
            service_path = f"/etc/systemd/system/{service_name}.service"
            if os.path.exists(service_path):
                os.remove(service_path)
            
            # Recarregar daemon
            subprocess.run(["systemctl", "daemon-reload"], check=False)
            
            logger.info(f"Serviço '{service_name}' removido com sucesso.")
            return True
        except Exception as e:
            logger.error(f"Erro ao remover serviço no Linux: {e}")
            return False
    elif platform_name == "darwin":
        try:
            # Verificar se o serviço está instalado
            if not is_service_installed(service_name):
                logger.info(f"Serviço '{service_name}' não está instalado.")
                return True
            
            # Caminho do arquivo plist
            plist_path = f"/Library/LaunchDaemons/{service_name}.plist"
            
            # Descarregar o serviço
            subprocess.run(["launchctl", "unload", plist_path], check=False)
            
            # Remover arquivo plist
            if os.path.exists(plist_path):
                os.remove(plist_path)
            
            logger.info(f"Serviço '{service_name}' removido com sucesso.")
            return True
        except Exception as e:
            logger.error(f"Erro ao remover serviço no macOS: {e}")
            return False
    else:
        logger.warning(f"Remoção de serviço não implementada para plataforma {platform_name}")
        return False

# Importações condicionais específicas da plataforma
current_platform = get_platform()

if current_platform == "windows":
    # Importações específicas para Windows
    try:
        # Qualquer inicialização específica do Windows pode ser feita aqui
        pass
    except ImportError as e:
        logger.error(f"Erro ao importar módulos específicos para Windows: {e}")

# Definição da classe PcapManager - será substituída pelo import real quando disponível
class PcapManager:
    """Classe padrão do PcapManager quando o módulo real não está disponível"""
    def __init__(self, *args, **kwargs):
        logger.warning("Usando versão de fallback do PcapManager. Funcionalidade de captura limitada.")

# Tenta importar o PcapManager real se estiver disponível
try:
    # Importação do módulo pcaptura se existir
    # Em sistemas de produção, este import deve ser configurado corretamente
    from .pcaptura import PcapManager as RealPcapManager  # type: ignore # noqa: F401 - Módulo opcional
    PcapManager = RealPcapManager  # type: ignore
    logger.debug("Módulo pcaptura importado com sucesso.")
except ImportError as e:
    # O PcapManager fallback já foi definido acima
    logger.warning(f"Módulo de captura de pacotes não encontrado: {e}") 