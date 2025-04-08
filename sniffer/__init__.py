"""
AO-Noki Sniffer - Ferramenta de captura e análise de pacotes Photon

Este pacote implementa um sniffer de rede especializado para capturar 
e analisar pacotes do protocolo Photon utilizado em jogos online.
"""

__version__ = "0.1.0"
__author__ = "AO-Noki"
__description__ = "Ferramenta de captura e análise de pacotes Photon"

# Importações padrão que devem estar disponíveis no pacote principal
from sniffer.platform import get_platform, is_platform_supported, get_system_info 