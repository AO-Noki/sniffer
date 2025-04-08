"""
AO-Noki Sniffer - Ferramenta para captura e análise de tráfego do protocolo Photon.

Este é o módulo principal do AO-Noki Sniffer, responsável por fornecer a interface
para captura, análise e visualização de tráfego de rede do protocolo Photon.
"""

import logging
import sys
from typing import Dict, Any, Optional

# Configuração básica de logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)

# Importar componentes principais
from sniffer.platform import get_platform, is_platform_supported, get_system_info
from sniffer.server import WebSocketServer, create_server
from sniffer.config import CONFIG, get_config

# Configuração específica para o pacote
logger = logging.getLogger("sniffer")

__version__ = "0.1.0"
__author__ = "AO-Noki Team"

# Exportar classes e funções importantes
__all__ = [
    "get_platform",
    "is_platform_supported", 
    "get_system_info",
    "WebSocketServer",
    "create_server",
    "CONFIG",
    "get_config"
] 