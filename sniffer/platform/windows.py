"""
Módulo específico para Windows do AO-Noki Sniffer.

Este módulo fornece funções e classes específicas para operações no Windows,
como verificação de privilégios, gerenciamento de serviços, e interação com o sistema.
"""

import logging
import os
import sys
import subprocess
import ctypes
from typing import Dict, Any, Optional, Tuple

logger = logging.getLogger("sniffer.platform.windows")

def check_admin() -> bool:
    """
    Verifica se o processo atual tem privilégios de administrador.
    
    Returns:
        True se o processo tem privilégios de administrador, False caso contrário
    """
    try:
        # Verificar se estamos no Windows
        if os.name != 'nt':
            return False
        
        # Verificar se temos privilégios de administrador
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception as e:
        logger.error(f"Erro ao verificar privilégios de administrador: {e}")
        return False

def is_service_installed(service_name: str) -> bool:
    """
    Verifica se um serviço está instalado no Windows.
    
    Args:
        service_name: Nome do serviço a ser verificado
        
    Returns:
        True se o serviço está instalado, False caso contrário
    """
    try:
        # Usar SC.exe para verificar se o serviço existe
        result = subprocess.run(
            ["sc", "query", service_name],
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        # Verificar se o comando foi bem-sucedido
        return result.returncode == 0 and "NOME_DO_SERVIÇO" in result.stdout
    except Exception as e:
        logger.error(f"Erro ao verificar serviço {service_name}: {e}")
        return False

def install_service(service_name: str, binary_path: str, display_name: Optional[str] = None) -> bool:
    """
    Instala um serviço no Windows.
    
    Args:
        service_name: Nome do serviço a ser instalado
        binary_path: Caminho para o executável do serviço
        display_name: Nome de exibição do serviço (opcional)
        
    Returns:
        True se o serviço foi instalado com sucesso, False caso contrário
    """
    try:
        # Verificar se temos privilégios de administrador
        if not check_admin():
            logger.error("Privilégios de administrador são necessários para instalar um serviço")
            return False
        
        # Usar nome de exibição ou o nome do serviço
        display_name = display_name or service_name
        
        # Instalar o serviço
        cmd = [
            "sc", "create", service_name,
            "binPath=", f"\"{binary_path}\"",
            "DisplayName=", display_name,
            "start=", "auto",
            "type=", "own"
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if result.returncode != 0:
            logger.error(f"Erro ao instalar serviço: {result.stderr}")
            return False
        
        # Configurar recuperação automática
        recovery_cmd = [
            "sc", "failure", service_name,
            "reset=", "86400",  # 1 dia em segundos
            "actions=", "restart/60000/restart/60000/restart/60000"  # Reiniciar após 1 minuto, até 3 tentativas
        ]
        
        subprocess.run(
            recovery_cmd,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        # Iniciar o serviço
        start_cmd = ["sc", "start", service_name]
        subprocess.run(
            start_cmd,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        logger.info(f"Serviço {service_name} instalado com sucesso")
        return True
        
    except Exception as e:
        logger.error(f"Erro ao instalar serviço {service_name}: {e}")
        return False

def uninstall_service(service_name: str) -> bool:
    """
    Remove um serviço do Windows.
    
    Args:
        service_name: Nome do serviço a ser removido
        
    Returns:
        True se o serviço foi removido com sucesso, False caso contrário
    """
    try:
        # Verificar se temos privilégios de administrador
        if not check_admin():
            logger.error("Privilégios de administrador são necessários para remover um serviço")
            return False
        
        # Verificar se o serviço existe
        if not is_service_installed(service_name):
            logger.warning(f"Serviço {service_name} não está instalado")
            return True
        
        # Parar o serviço se estiver em execução
        stop_cmd = ["sc", "stop", service_name]
        subprocess.run(
            stop_cmd,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        # Remover o serviço
        delete_cmd = ["sc", "delete", service_name]
        result = subprocess.run(
            delete_cmd,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if result.returncode != 0:
            logger.error(f"Erro ao remover serviço: {result.stderr}")
            return False
        
        logger.info(f"Serviço {service_name} removido com sucesso")
        return True
        
    except Exception as e:
        logger.error(f"Erro ao remover serviço {service_name}: {e}")
        return False 