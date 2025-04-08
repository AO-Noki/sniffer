"""
Módulo para processamento de argumentos de linha de comando.

Este módulo é responsável por analisar e processar os argumentos de linha
de comando passados para o aplicativo.
"""

import os
import sys
import argparse
import logging
import ctypes
from typing import Dict, List, Optional, Any, Tuple

# Importações locais
from sniffer.platform import (
    get_platform,
    check_admin,
    is_service_installed,
    install_service as platform_install_service,
    uninstall_service as platform_uninstall_service
)

# Configurar logger
logger = logging.getLogger("sniffer.utils.cli")

def request_admin() -> bool:
    """
    Verifica se o script está sendo executado com privilégios de administrador.
    
    Returns:
        True se o script está sendo executado como administrador,
        False caso contrário.
    """
    platform_name = get_platform()
    
    if platform_name == "windows":
        try:
            # Verificar se já está rodando como administrador no Windows
            return check_admin()
        except Exception as e:
            logger.error(f"Erro ao verificar privilégios de administrador: {e}")
            return False
    else:
        # Em outras plataformas, apenas assumimos que não tem privilégios
        # Uma verificação mais precisa seria implementada nas classes específicas da plataforma
        logger.warning(f"Verificação de privilégios de administrador não implementada para {platform_name}")
        return False

class CommandLineParser:
    """
    Parser de argumentos de linha de comando para o AO-Noki Sniffer.
    """
    
    def __init__(self):
        """Inicializa o parser de argumentos."""
        self.parser = argparse.ArgumentParser(
            description="AO-Noki Sniffer - Ferramenta de captura e análise de pacotes Photon",
            epilog="Use -h ou --help para obter ajuda sobre comandos específicos."
        )
        self._setup_arguments()
    
    def _setup_arguments(self):
        """Configura os argumentos aceitos pelo parser."""
        # Argumento para definir o modo de operação
        mode_group = self.parser.add_mutually_exclusive_group()
        
        # Argumentos para instalação e gestão de serviços
        mode_group.add_argument(
            "-service", "--service",
            action="store_true",
            help="Executa o aplicativo como serviço do sistema"
        )
        
        mode_group.add_argument(
            "-console", "--console",
            action="store_true",
            help="Executa o aplicativo no modo console (interativo)"
        )
        
        mode_group.add_argument(
            "-install-service", "--install-service",
            action="store_true",
            help="Instala o aplicativo como serviço do sistema"
        )
        
        mode_group.add_argument(
            "-uninstall-service", "--uninstall-service",
            action="store_true",
            help="Remove o serviço do sistema"
        )
        
        mode_group.add_argument(
            "-start-service", "--start-service",
            action="store_true",
            help="Inicia o serviço se estiver instalado"
        )
        
        mode_group.add_argument(
            "-stop-service", "--stop-service",
            action="store_true",
            help="Para o serviço se estiver em execução"
        )
        
        # Argumentos para configuração da captura
        self.parser.add_argument(
            "-i", "--interface",
            type=str,
            help="Especifica a interface de rede para captura"
        )
        
        self.parser.add_argument(
            "--host",
            type=str,
            default="0.0.0.0",
            help="Host para o servidor WebSocket (padrão: 0.0.0.0)"
        )
        
        self.parser.add_argument(
            "-p", "--port",
            type=int,
            default=8080,
            help="Porta para o servidor WebSocket (padrão: 8080)"
        )
        
        self.parser.add_argument(
            "--webui-port",
            type=int,
            default=8080,
            help="Porta para a interface web (padrão: 8080)"
        )
        
        self.parser.add_argument(
            "-f", "--filter",
            type=str,
            help="Filtro BPF para captura de pacotes"
        )
        
        # Argumentos para modo de operação
        self.parser.add_argument(
            "--low-resource",
            action="store_true",
            help="Executa em modo de baixo consumo de recursos"
        )
        
        self.parser.add_argument(
            "--debug",
            action="store_true",
            help="Ativa o modo de depuração com logs detalhados"
        )
        
        # Argumentos específicos para Windows
        if get_platform() == "windows":
            self.parser.add_argument(
                "--install-npcap",
                action="store_true",
                help="Baixa e instala o Npcap se não estiver presente (Windows)"
            )
    
    def parse_args(self, args: Optional[List[str]] = None) -> argparse.Namespace:
        """
        Processa os argumentos de linha de comando.
        
        Args:
            args: Lista de argumentos para processar (opcional, usa sys.argv se não fornecido)
            
        Returns:
            Namespace com os argumentos processados
        """
        return self.parser.parse_args(args)
    
    def process_args(self, args: argparse.Namespace) -> Dict[str, Any]:
        """
        Processa os argumentos já analisados e executa ações conforme necessário.
        
        Args:
            args: Namespace com os argumentos processados
            
        Returns:
            Dicionário com informações sobre o processamento
        """
        result = {
            "success": True,
            "exit": False,
            "exit_code": 0,
            "mode": "default",
            "message": ""
        }
        
        # Nome e caminhos do serviço
        service_name = "AO-Noki-Sniffer"
        binary_path = os.path.abspath(sys.argv[0])
        display_name = "AO-Noki Sniffer"
        
        # Processar argumentos de gerenciamento de serviço
        if args.service:
            result["mode"] = "service"
            result["message"] = "Executando como serviço do sistema"
            
        elif args.console:
            result["mode"] = "console"
            result["message"] = "Executando no modo console"
            
        elif args.install_service:
            result["exit"] = True
            if not request_admin():
                result["success"] = False
                result["exit_code"] = 1
                result["message"] = "Privilégios de administrador são necessários para instalar o serviço"
            else:
                if platform_install_service(service_name, binary_path, display_name):
                    result["message"] = "Serviço instalado com sucesso"
                else:
                    result["success"] = False
                    result["exit_code"] = 1
                    result["message"] = "Falha ao instalar o serviço"
            
        elif args.uninstall_service:
            result["exit"] = True
            if not request_admin():
                result["success"] = False
                result["exit_code"] = 1
                result["message"] = "Privilégios de administrador são necessários para desinstalar o serviço"
            else:
                if platform_uninstall_service(service_name):
                    result["message"] = "Serviço removido com sucesso"
                else:
                    result["success"] = False
                    result["exit_code"] = 1
                    result["message"] = "Falha ao remover o serviço"
            
        elif args.start_service:
            result["exit"] = True
            if not request_admin():
                result["success"] = False
                result["exit_code"] = 1
                result["message"] = "Privilégios de administrador são necessários para iniciar o serviço"
            else:
                # No nosso modelo atualizado, o start_service está embutido na função de instalação
                # Podemos usar subprocess diretamente para iniciar o serviço
                try:
                    import subprocess
                    start_cmd = ["sc", "start", service_name]
                    process = subprocess.run(
                        start_cmd, 
                        capture_output=True, 
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    if process.returncode == 0:
                        result["message"] = "Serviço iniciado com sucesso"
                    else:
                        result["success"] = False
                        result["exit_code"] = process.returncode
                        result["message"] = f"Falha ao iniciar o serviço: {process.stderr}"
                except Exception as e:
                    result["success"] = False
                    result["exit_code"] = 1
                    result["message"] = f"Erro ao iniciar o serviço: {e}"
            
        elif args.stop_service:
            result["exit"] = True
            if not request_admin():
                result["success"] = False
                result["exit_code"] = 1
                result["message"] = "Privilégios de administrador são necessários para parar o serviço"
            else:
                # Similar ao start_service, usamos subprocess diretamente
                try:
                    import subprocess
                    stop_cmd = ["sc", "stop", service_name]
                    process = subprocess.run(
                        stop_cmd, 
                        capture_output=True, 
                        text=True,
                        creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    if process.returncode == 0:
                        result["message"] = "Serviço parado com sucesso"
                    else:
                        result["success"] = False
                        result["exit_code"] = process.returncode
                        result["message"] = f"Falha ao parar o serviço: {process.stderr}"
                except Exception as e:
                    result["success"] = False
                    result["exit_code"] = 1
                    result["message"] = f"Erro ao parar o serviço: {e}"
        
        # Processar argumento debug
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logger.debug("Modo de depuração ativado")
        
        return result


def parse_and_process_args() -> Tuple[Dict[str, Any], argparse.Namespace]:
    """
    Função auxiliar para analisar e processar os argumentos de linha de comando.
    
    Returns:
        Tupla com o resultado do processamento e os argumentos analisados.
    """
    parser = CommandLineParser()
    args = parser.parse_args()
    result = parser.process_args(args)
    
    return result, args 