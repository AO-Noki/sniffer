"""
Módulo de configuração centralizada para o AO-Noki Sniffer.

Este módulo fornece constantes, classes e funções para gerenciar
as configurações da aplicação de forma centralizada.
"""

import os
import json
import logging
import platform
import tempfile
from typing import Dict, Any, Optional, Union, cast, TypedDict

# Informações da aplicação
APP_NAME = "AO Noki Sniffer"
APP_VERSION = "0.1.0"
APP_AUTHOR = "AO Noki"
APP_DESCRIPTION = "Ferramenta para análise e monitoramento de tráfego do protocolo Photon"

# Configurações de protocolo
PHOTON_DEFAULT_PORT = 5056
PHOTON_PROTOCOLS = ["UDP", "TCP", "WebSocket", "HTTP"]

# Configurações do WebSocket server
WS_DEFAULT_PORT = 8080
WS_DEFAULT_HOST = "127.0.0.1"

# Configurações da UI
UI_DEFAULT_THEME = "dark"
UI_DEFAULT_LANGUAGE = "pt-BR"
UI_LANGUAGES = ["pt-BR", "en-US"]
UI_THEMES = ["dark", "light"]

# Configurações de logging
LOG_LEVELS = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
DEFAULT_LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# Nomes de processos
PROCESS_NAMES = {
    "windows": "ao-noki-sniffer.exe",
    "linux": "ao-noki-sniffer",
    "darwin": "ao-noki-sniffer"
}

# URLs
NPCAP_URL = "https://npcap.com/dist/npcap-1.81.exe"
DOCS_URL = "https://github.com/AO-Noki/sniffer/wiki"
REPO_URL = "https://github.com/AO-Noki/sniffer"

class NetworkConfigDict(TypedDict, total=False):
    interface: str
    port: int
    protocol: str
    active: bool

class LoggingConfigDict(TypedDict, total=False):
    level: str
    file_enabled: bool
    console_enabled: bool
    syslog_enabled: bool
    max_size: int
    backup_count: int

class PerformanceConfigDict(TypedDict, total=False):
    threads: int
    buffer_size: int
    batch_size: int
    queue_size: int

class SystemConfigDict(TypedDict, total=False):
    auto_update: bool
    start_with_system: bool
    minimize_to_tray: bool

class UiConfigDict(TypedDict, total=False):
    theme: str
    language: str
    show_notifications: bool
    auto_scroll: bool
    font_size: int

# Configurações padrão
DEFAULT_CONFIG = {
    "network": {
        "interface": "auto",
        "port": PHOTON_DEFAULT_PORT,
        "protocol": "UDP",
        "active": True
    },
    "logging": {
        "level": DEFAULT_LOG_LEVEL,
        "file_enabled": True,
        "console_enabled": True,
        "syslog_enabled": False,
        "max_size": 10 * 1024 * 1024,  # 10MB
        "backup_count": 5
    },
    "performance": {
        "threads": 4,
        "buffer_size": 65536,
        "batch_size": 100,
        "queue_size": 1000
    },
    "system": {
        "auto_update": True,
        "start_with_system": False,
        "minimize_to_tray": True
    },
    "ui": {
        "theme": UI_DEFAULT_THEME,
        "language": UI_DEFAULT_LANGUAGE,
        "show_notifications": True,
        "auto_scroll": True,
        "font_size": 12
    }
}

# Configurações específicas de plataforma
def get_platform_config():
    """
    Retorna configurações específicas da plataforma atual.
    
    Returns:
        Dict com configurações da plataforma.
    """
    system = platform.system().lower()
    
    if system == "windows":
        log_dir = os.path.join(os.environ.get("APPDATA", ""), "AO-Noki", "Sniffer", "logs")
        config_dir = os.path.join(os.environ.get("APPDATA", ""), "AO-Noki", "Sniffer")
        lock_file = os.path.join(tempfile.gettempdir(), "aonoki-sniffer.lock")
    elif system == "darwin":  # macOS
        log_dir = os.path.expanduser("~/Library/Logs/AO-Noki/Sniffer")
        config_dir = os.path.expanduser("~/Library/Application Support/AO-Noki/Sniffer")
        lock_file = "/tmp/aonoki-sniffer.lock"
    else:  # Linux e outros
        log_dir = os.path.expanduser("~/.local/share/AO-Noki/Sniffer/logs")
        config_dir = os.path.expanduser("~/.config/AO-Noki/Sniffer")
        lock_file = "/tmp/aonoki-sniffer.lock"
    
    return {
        "log_dir": log_dir,
        "config_dir": config_dir,
        "lock_file": lock_file,
        "system": system
    }

class ConfigManager:
    """
    Gerencia as configurações da aplicação.
    
    Esta classe é responsável por carregar, salvar e gerenciar as configurações
    da aplicação, fornecendo uma interface para acessar valores específicos.
    """
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Inicializa o gerenciador de configurações.
        
        Args:
            config_file: Caminho opcional para o arquivo de configuração.
                         Se None, usa o caminho padrão da plataforma.
        """
        platform_config = get_platform_config()
        self.config_dir = platform_config["config_dir"]
        
        if config_file is None:
            self.config_file = os.path.join(cast(str, self.config_dir), "config.json")
        else:
            self.config_file = config_file
        
        self.config: Dict[str, Dict[str, Any]] = DEFAULT_CONFIG.copy()
        self.platform_config = platform_config
        
        # Garantir que o diretório de configuração exista
        os.makedirs(cast(str, self.config_dir), exist_ok=True)
        
        # Carregar configurações existentes
        self.load()
    
    def load(self) -> bool:
        """
        Carrega as configurações do arquivo.
        
        Returns:
            True se carregado com sucesso, False caso contrário.
        """
        try:
            config_path = cast(str, self.config_file)
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    loaded_config = json.load(f)
                self._merge_config(loaded_config)
                logger.debug(f"Configurações carregadas de {config_path}")
                return True
            else:
                logger.info(f"Arquivo de configuração não encontrado em {config_path}. Usando padrões.")
                return False
        except Exception as e:
            logger.error(f"Erro ao carregar configurações: {e}")
            return False
    
    def save(self) -> bool:
        """
        Salva as configurações no arquivo.
        
        Returns:
            True se salvo com sucesso, False caso contrário.
        """
        try:
            config_path = cast(str, self.config_file)
            config_dir = os.path.dirname(config_path)
            
            # Garantir que o diretório exista
            if not os.path.exists(config_dir):
                os.makedirs(config_dir, exist_ok=True)
            
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=4)
            
            logger.debug(f"Configurações salvas em {config_path}")
            return True
        except Exception as e:
            logger.error(f"Erro ao salvar configurações: {e}")
            return False
    
    def _merge_config(self, new_config: Dict[str, Dict[str, Any]]) -> None:
        """
        Mescla configurações novas com as existentes.
        
        Args:
            new_config: Novas configurações para mesclar.
        """
        for section, values in new_config.items():
            if section in self.config:
                self.config[section].update(values)
            else:
                self.config[section] = values
    
    def get(self, section: str, key: str, default: Any = None) -> Any:
        """
        Obtém um valor de configuração.
        
        Args:
            section: Seção da configuração.
            key: Chave da configuração.
            default: Valor padrão se a configuração não existir.
            
        Returns:
            Valor da configuração ou o valor padrão.
        """
        try:
            return self.config.get(section, {}).get(key, default)
        except Exception:
            return default
    
    def set(self, section: str, key: str, value: Any) -> bool:
        """
        Define um valor na configuração.
        
        Args:
            section: Seção da configuração.
            key: Chave da configuração.
            value: Valor a ser definido.
            
        Returns:
            True se definido com sucesso, False caso contrário.
        """
        try:
            if section not in self.config:
                self.config[section] = {}
            
            self.config[section][key] = value
            return True
        except Exception as e:
            logger.error(f"Erro ao definir configuração {section}.{key}: {e}")
            return False
    
    def get_all(self) -> Dict[str, Any]:
        """
        Retorna todas as configurações.
        
        Returns:
            Cópia de todas as configurações.
        """
        return self.config.copy()

# Instância global do gerenciador de configuração
CONFIG = ConfigManager()

# Configuração do logger
logger = logging.getLogger("sniffer.config")
logger.setLevel(logging.INFO)

# Configurar handler de arquivo com UTF-8
log_file = os.path.join(CONFIG.get("log_dir", ""), "config.log")
file_handler = logging.FileHandler(log_file, encoding='utf-8')
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(file_handler)

def get_config() -> ConfigManager:
    """
    Retorna a instância única do gerenciador de configurações.
    
    Returns:
        Instância do ConfigManager.
    """
    return CONFIG

# Constante global para facilitar o acesso à configuração
CONFIG = get_config() 