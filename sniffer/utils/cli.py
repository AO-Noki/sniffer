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
    ServiceManager, 
    PcapManager,
    get_platform
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
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
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
                service_manager = ServiceManager()
                if service_manager.install_service():
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
                service_manager = ServiceManager()
                if service_manager.uninstall_service():
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
                service_manager = ServiceManager()
                if service_manager.start_service():
                    result["message"] = "Serviço iniciado com sucesso"
                else:
                    result["success"] = False
                    result["exit_code"] = 1
                    result["message"] = "Falha ao iniciar o serviço"
            
        elif args.stop_service:
            result["exit"] = True
            if not request_admin():
                result["success"] = False
                result["exit_code"] = 1
                result["message"] = "Privilégios de administrador são necessários para parar o serviço"
            else:
                service_manager = ServiceManager()
                if service_manager.stop_service():
                    result["message"] = "Serviço parado com sucesso"
                else:
                    result["success"] = False
                    result["exit_code"] = 1
                    result["message"] = "Falha ao parar o serviço"
        
        # Processar argumentos específicos para Windows
        if get_platform() == "windows" and getattr(args, "install_npcap", False):
            pcap_manager = PcapManager()
            if pcap_manager.is_npcap_installed:
                logger.info("Npcap já está instalado.")
            else:
                logger.info("Instalando Npcap...")
                pcap_manager.install_npcap()
                # Não marcamos como falha se não conseguirmos instalar o Npcap,
                # pois o aplicativo pode continuar sem ele em alguns casos
        
        # Configurar modo de recurso
        if args.low_resource:
            logger.info("Modo de baixo consumo de recursos ativado")
        
        # Configurar modo de depuração
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
            logger.debug("Modo de depuração ativado")
        
        return result


def parse_and_process_args() -> Tuple[Dict[str, Any], argparse.Namespace]:
    """
    Função auxiliar para processar argumentos de linha de comando.
    
    Returns:
        Tupla com o resultado do processamento e os argumentos processados
    """
    parser = CommandLineParser()
    args = parser.parse_args()
    result = parser.process_args(args)
    
    return result, args 