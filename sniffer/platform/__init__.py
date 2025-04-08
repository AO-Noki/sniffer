"""
Detector de plataforma e adaptadores específicos para cada sistema operacional.

Este módulo detecta automaticamente a plataforma atual e importa as classes
e funções apropriadas para cada sistema operacional.
"""

import sys
import logging
import platform
from typing import Dict, Any, Optional, cast

# Importar classe base
from sniffer.platform.common import SystemInfo as BaseSystemInfo

logger = logging.getLogger("sniffer.platform")

# Detectar sistema operacional atual
current_platform: str = "unknown"
if sys.platform.startswith("win"):
    current_platform = "windows"
    from sniffer.platform.windows import (
        WindowsServiceManager as ServiceManager,
        WindowsPcapManager as PcapManager,
        WindowsSystemInfo as SystemInfo,
        is_running_as_service
    )
    _platform_get_system_info = SystemInfo.get_windows_version
    from sniffer.platform.pcaptura import PcapInstaller
    logger.info("Sistema operacional Windows detectado")
elif sys.platform.startswith("linux"):
    current_platform = "linux"
    # Importar classes Linux quando disponíveis
    logger.warning("Suporte ao Linux está em desenvolvimento")
    from sniffer.platform.common import SystemInfo
    _system_info = SystemInfo()
    _platform_get_system_info = _system_info.get_system_info
elif sys.platform.startswith("darwin"):
    current_platform = "macos"
    # Importar classes macOS quando disponíveis
    logger.warning("Suporte ao macOS está em desenvolvimento")
    from sniffer.platform.common import SystemInfo
    _system_info = SystemInfo()
    _platform_get_system_info = _system_info.get_system_info
else:
    current_platform = "unknown"
    logger.warning(f"Sistema operacional não suportado: {sys.platform}")
    from sniffer.platform.common import SystemInfo
    _system_info = SystemInfo()
    _platform_get_system_info = _system_info.get_system_info

# Definir funções de interface comum
def get_platform() -> str:
    """Retorna o nome da plataforma atual."""
    return current_platform

def get_system_info() -> Dict[str, Any]:
    """Retorna informações sobre o sistema operacional atual."""
    info = cast(Dict[str, Any], _platform_get_system_info())
    # Garantir que a chave 'platform' esteja presente
    if 'platform' not in info:
        info['platform'] = current_platform
    return info

def is_platform_supported() -> bool:
    """Verifica se a plataforma atual é suportada."""
    return current_platform in ["windows", "linux", "macos"]

def is_service() -> bool:
    """Verifica se a aplicação está rodando como serviço."""
    if current_platform == "windows":
        return is_running_as_service()
    # Em outras plataformas, verificar como apropriado
    return False

# Exportação de símbolos para simplificar o uso
__all__ = [
    "get_platform",
    "get_system_info",
    "is_platform_supported",
    "is_service",
    "SystemInfo",  # Adicionar explicitamente a classe SystemInfo
]

# Adicionar classes específicas da plataforma quando disponíveis
if "ServiceManager" in globals():
    __all__.append("ServiceManager")
if "PcapManager" in globals():
    __all__.append("PcapManager")
if "PcapInstaller" in globals():
    __all__.append("PcapInstaller") 