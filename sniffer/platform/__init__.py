"""
Módulo de abstração de plataforma para o AO-Noki Sniffer.

Este módulo fornece uma interface unificada para funcionalidades específicas 
de cada sistema operacional suportado, incluindo:
- Windows (primária)
- Linux (futura implementação)
- macOS (futura implementação)
- Android (futura implementação)
"""

import os
import sys
import platform
import logging
from typing import Dict, Any, Optional, List, Union

# Configurar logger
logger = logging.getLogger("sniffer.platform")

# Identificar a plataforma atual
CURRENT_PLATFORM = platform.system().lower()

# Carregar módulo específico para a plataforma
if CURRENT_PLATFORM == "windows":
    from .windows import (
        WindowsServiceManager,
        WindowsPcapManager,
        WindowsSystemInfo,
        is_running_as_service,
        request_admin_privileges
    )
    
    # Classes e funções específicas para Windows
    ServiceManager = WindowsServiceManager
    PcapManager = WindowsPcapManager
    SystemInfo = WindowsSystemInfo
    
    # Funções auxiliares para Windows
    check_service_status = lambda: ServiceManager().get_service_status()
    is_service = is_running_as_service
    request_admin = request_admin_privileges

# Futuramente implementaremos outras plataformas
elif CURRENT_PLATFORM == "linux":
    # Implementação futura
    logger.warning("Suporte a Linux ainda não implementado completamente")
    
    # Classes provisórias para Linux
    class ServiceManager:
        def __init__(self): pass
        def install_service(self): return False
        def uninstall_service(self): return False
        def start_service(self): return False
        def stop_service(self): return False
        def get_service_status(self): return None
    
    class PcapManager:
        def __init__(self): pass
        def get_network_interfaces(self): return []
    
    class SystemInfo:
        @staticmethod
        def is_compatible(): return False
        
    # Funções auxiliares para Linux
    check_service_status = lambda: None
    is_service = lambda: False
    request_admin = lambda: False

elif CURRENT_PLATFORM == "darwin":  # macOS
    # Implementação futura
    logger.warning("Suporte a macOS ainda não implementado completamente")
    
    # Classes provisórias para macOS
    class ServiceManager:
        def __init__(self): pass
        def install_service(self): return False
        def uninstall_service(self): return False
        def start_service(self): return False
        def stop_service(self): return False
        def get_service_status(self): return None
    
    class PcapManager:
        def __init__(self): pass
        def get_network_interfaces(self): return []
    
    class SystemInfo:
        @staticmethod
        def is_compatible(): return False
        
    # Funções auxiliares para macOS
    check_service_status = lambda: None
    is_service = lambda: False
    request_admin = lambda: False

else:
    logger.error(f"Plataforma não suportada: {CURRENT_PLATFORM}")
    
    # Classes genéricas para plataformas não suportadas
    class ServiceManager:
        def __init__(self): pass
        def install_service(self): return False
        def uninstall_service(self): return False
        def start_service(self): return False
        def stop_service(self): return False
        def get_service_status(self): return None
    
    class PcapManager:
        def __init__(self): pass
        def get_network_interfaces(self): return []
    
    class SystemInfo:
        @staticmethod
        def is_compatible(): return False
        
    # Funções auxiliares para plataformas não suportadas
    check_service_status = lambda: None
    is_service = lambda: False
    request_admin = lambda: False

# Funções gerais independentes de plataforma
def get_platform() -> str:
    """Retorna o nome da plataforma atual."""
    return CURRENT_PLATFORM

def is_platform_supported() -> bool:
    """Verifica se a plataforma atual é suportada pelo sniffer."""
    return CURRENT_PLATFORM in ["windows", "linux", "darwin"]

def get_system_info() -> Dict[str, Any]:
    """Retorna informações gerais sobre o sistema."""
    return {
        "platform": CURRENT_PLATFORM,
        "python_version": platform.python_version(),
        "os_version": platform.version(),
        "architecture": platform.architecture()[0],
        "processor": platform.processor(),
        "hostname": platform.node(),
        "supported": is_platform_supported(),
        "compatible": SystemInfo.is_compatible() if is_platform_supported() else False
    } 