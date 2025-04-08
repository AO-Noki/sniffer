"""
Classes e funções comuns para todas as plataformas suportadas.

Este módulo contém implementações genéricas que podem ser usadas
por todos os sistemas operacionais suportados pelo AO-Noki Sniffer.
"""

import platform
import sys
import os
import logging
from typing import Dict, Any, Optional, List, Union

logger = logging.getLogger("sniffer.platform.common")

class SystemInfo:
    """
    Classe para obter informações do sistema e verificar compatibilidade.
    """
    
    def __init__(self):
        self.platform = self._detect_platform()
        
    def _detect_platform(self) -> str:
        """Detecta a plataforma atual."""
        if sys.platform.startswith("win"):
            return "windows"
        elif sys.platform.startswith("linux"):
            return "linux"
        elif sys.platform.startswith("darwin"):
            return "macos"
        else:
            return "unknown"
    
    def get_system_info(self) -> Dict[str, Any]:
        """Retorna informações gerais sobre o sistema."""
        return {
            "platform": self.platform,
            "python_version": platform.python_version(),
            "os_version": platform.version(),
            "architecture": platform.architecture()[0],
            "processor": platform.processor(),
            "hostname": platform.node(),
            "supported": self.is_supported(),
            "compatible": self.is_compatible()
        }
    
    def is_supported(self) -> bool:
        """Verifica se a plataforma atual é suportada pelo sniffer."""
        return self.platform in ["windows", "linux", "macos"]
    
    def is_compatible(self) -> bool:
        """
        Verifica se o sistema atual é compatível com os requisitos mínimos.
        
        Requisitos mínimos:
        - Python 3.8 ou superior
        - Windows 7 SP1 ou superior (para Windows)
        - Ubuntu 18.04 ou superior (para Linux)
        - macOS 10.14 ou superior (para macOS)
        """
        # Verificar versão do Python
        python_major, python_minor = sys.version_info[:2]
        if python_major < 3 or (python_major == 3 and python_minor < 8):
            logger.warning(f"Python {python_major}.{python_minor} não é compatível. Mínimo: Python 3.8")
            return False
            
        # Verificar sistema operacional
        if self.platform == "windows":
            # No Windows, verificamos a versão via platform.version()
            # que retorna algo como "10.0.19041"
            try:
                version = platform.version().split('.')
                major_version = int(version[0])
                if major_version < 6:  # Windows Vista ou inferior
                    logger.warning(f"Windows versão {major_version} não é compatível. Mínimo: Windows 7 (6.1)")
                    return False
                elif major_version == 6 and float(version[1]) < 1:  # Windows Vista
                    logger.warning(f"Windows versão {major_version}.{version[1]} não é compatível. Mínimo: Windows 7 (6.1)")
                    return False
            except (IndexError, ValueError):
                logger.warning(f"Não foi possível determinar a versão do Windows: {platform.version()}")
                return False
                
        elif self.platform == "linux":
            # Para Linux, precisaríamos verificar a distribuição específica
            # Este é um placeholder para implementação futura
            return True
            
        elif self.platform == "macos":
            # Para macOS, precisaríamos verificar a versão do macOS
            # Este é um placeholder para implementação futura
            return True
            
        else:
            # Plataforma desconhecida/não suportada
            logger.warning(f"Plataforma desconhecida: {self.platform}")
            return False
            
        # Se chegou até aqui, o sistema é compatível
        return True
        
    def check_dependencies(self) -> Dict[str, bool]:
        """
        Verifica se as dependências necessárias estão instaladas.
        
        Retorna um dicionário com o nome da dependência e um booleano
        indicando se está instalada.
        """
        dependencies = {}
        
        # Dependências comuns para todas as plataformas
        try:
            import psutil
            dependencies["psutil"] = True
        except ImportError:
            dependencies["psutil"] = False
            
        try:
            import scapy
            dependencies["scapy"] = True
        except ImportError:
            dependencies["scapy"] = False
            
        # Dependências específicas por plataforma
        if self.platform == "windows":
            # Verificar Npcap/WinPcap
            # Placeholder - implementação real está em WindowsPcapManager
            dependencies["npcap_or_winpcap"] = False
            
        return dependencies 