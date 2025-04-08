"""
Ponto de entrada principal para o AO-Noki Sniffer.

Este arquivo contém o código principal para inicializar e executar 
o sniffer em diferentes modos (console, serviço, etc).
"""

import os
import sys
import logging
import asyncio
from typing import Dict, Any, Optional

# Importações locais
from sniffer.utils import parse_and_process_args
from sniffer.config import get_config
from sniffer.platform import (
    get_platform, 
    is_platform_supported,
    get_system_info,
    is_service,
    ServiceManager,
    PcapManager
)

# Carregar configuração centralizada
config = get_config()

# Configuração do logger
log_level = getattr(logging, config.get("logs", "level", "INFO").upper())
logging.basicConfig(
    level=log_level,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(os.path.join(config.get("logs", "dir", os.path.dirname(__file__)), 'sniffer.log'))
    ]
)
logger = logging.getLogger("sniffer.main")

class SnifferApplication:
    """Classe principal do aplicativo Sniffer."""
    
    def __init__(self):
        """Inicializa o aplicativo."""
        self.running = False
        self.system_info = get_system_info()
        self.platform = get_platform()
        self.config = config
        
        # Verificar compatibilidade da plataforma
        if not is_platform_supported():
            logger.error(f"Plataforma não suportada: {self.platform}")
            sys.exit(1)
        
        # Processar argumentos de linha de comando
        self.args_result, self.args = parse_and_process_args()
        
        # Se o processamento de argumentos indicar saída, encerrar
        if self.args_result.get("exit", False):
            logger.info(self.args_result.get("message", ""))
            sys.exit(self.args_result.get("exit_code", 0))
        
        # Determinar modo de execução
        self.mode = self.args_result.get("mode", "default")
        
        # Inicializar recursos conforme a plataforma
        if self.platform == "windows":
            self.pcap_manager = PcapManager()
            
            # Verificar Npcap/WinPcap
            if not self.pcap_manager.is_npcap_installed and not self.pcap_manager.is_winpcap_installed:
                logger.warning("Npcap ou WinPcap não detectado. A captura de pacotes pode não funcionar corretamente.")
                
                if getattr(self.args, "install_npcap", False) or self.config.get("system", "auto_install_dependencies", True):
                    logger.info("Tentando instalar Npcap automaticamente...")
                    self.pcap_manager.install_npcap()
        
        # Configurar modo de operação
        app_name = self.config.get("app", "name")
        app_version = self.config.get("app", "version")
        logger.info(f"Iniciando {app_name} v{app_version} no modo: {self.mode}")
    
    async def run_console_mode(self):
        """Executa o aplicativo no modo console."""
        logger.info("Iniciando em modo console")
        
        # Obter interfaces de rede disponíveis
        if self.platform == "windows":
            interfaces = self.pcap_manager.get_network_interfaces()
            if interfaces:
                logger.info(f"Interfaces de rede disponíveis: {len(interfaces)}")
                for idx, interface in enumerate(interfaces):
                    logger.info(f"  {idx+1}. {interface['name']} - {interface['description']} ({interface['ip']})")
            else:
                logger.warning("Nenhuma interface de rede encontrada")
        
        # Aqui implementaremos o loop principal do modo console
        try:
            logger.info("Pressione Ctrl+C para encerrar")
            self.running = True
            
            # Loop principal (simulação)
            while self.running:
                # Simular atividade
                await asyncio.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Interrompido pelo usuário")
            self.running = False
        finally:
            logger.info("Encerrando modo console")
    
    async def run_service_mode(self):
        """Executa o aplicativo como serviço do sistema."""
        logger.info("Iniciando em modo serviço")
        
        # No modo serviço, não exibimos logs no console
        for handler in logging.getLogger().handlers:
            if isinstance(handler, logging.StreamHandler) and handler.stream == sys.stdout:
                logging.getLogger().removeHandler(handler)
        
        # Aqui implementaremos o loop principal do modo serviço
        try:
            self.running = True
            
            # Loop principal (simulação)
            while self.running:
                # Simular atividade
                await asyncio.sleep(1)
                
        except Exception as e:
            logger.error(f"Erro no modo serviço: {e}")
            self.running = False
        finally:
            logger.info("Encerrando modo serviço")
    
    async def run(self):
        """Executa o aplicativo no modo apropriado."""
        if self.mode == "console":
            await self.run_console_mode()
        elif self.mode == "service":
            await self.run_service_mode()
        else:
            # Modo padrão - detectar automaticamente
            if is_service():
                await self.run_service_mode()
            else:
                await self.run_console_mode()


def main():
    """Função principal do aplicativo."""
    app = SnifferApplication()
    
    # Executar o aplicativo com asyncio
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(app.run())
    except KeyboardInterrupt:
        logger.info("Aplicativo interrompido pelo usuário")
    except Exception as e:
        logger.error(f"Erro ao executar o aplicativo: {e}")
    finally:
        loop.close()


if __name__ == "__main__":
    main() 