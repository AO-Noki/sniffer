"""
Testes para o módulo de plataforma Windows
"""

import os
import sys
import unittest
import platform
from unittest import mock

# Adicionar o diretório raiz ao path para importação
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Importações condicionais para evitar erros em plataformas não-Windows
if platform.system().lower() == 'windows':
    from sniffer.platform.windows import (
        WindowsServiceManager,
        WindowsPcapManager,
        WindowsSystemInfo,
        is_running_as_service,
        request_admin_privileges
    )
    from sniffer.platform import (
        ServiceManager,
        PcapManager,
        SystemInfo,
        get_platform,
        is_platform_supported,
        get_system_info
    )

@unittest.skipIf(platform.system().lower() != 'windows', "Testes específicos para Windows")
class TestWindowsPlatform(unittest.TestCase):
    """Testes para o módulo de plataforma Windows."""
    
    def test_platform_detection(self):
        """Testa a detecção correta da plataforma Windows."""
        self.assertEqual(get_platform(), 'windows')
        self.assertTrue(is_platform_supported())
        
        # Verificar se as classes corretas foram carregadas
        self.assertEqual(ServiceManager, WindowsServiceManager)
        self.assertEqual(PcapManager, WindowsPcapManager)
        self.assertEqual(SystemInfo, WindowsSystemInfo)
    
    def test_system_info(self):
        """Testa a obtenção de informações do sistema."""
        info = get_system_info()
        
        # Verificar campos obrigatórios
        self.assertIn('platform', info)
        self.assertIn('python_version', info)
        self.assertIn('os_version', info)
        self.assertIn('architecture', info)
        self.assertIn('processor', info)
        self.assertIn('hostname', info)
        self.assertIn('supported', info)
        self.assertIn('compatible', info)
        
        # Verificar valores específicos do Windows
        self.assertEqual(info['platform'], 'windows')
        self.assertTrue(info['supported'])
        
    @mock.patch('sniffer.platform.windows.ctypes.windll.shell32.IsUserAnAdmin')
    def test_admin_check(self, mock_is_admin):
        """Testa a verificação de privilégios de administrador."""
        # Simular que somos administrador
        mock_is_admin.return_value = 1
        
        service_manager = WindowsServiceManager()
        self.assertTrue(service_manager._check_admin())
        
        # Simular que não somos administrador
        mock_is_admin.return_value = 0
        
        service_manager = WindowsServiceManager()
        self.assertFalse(service_manager._check_admin())
    
    @mock.patch('sniffer.platform.windows.winreg.OpenKey')
    def test_npcap_detection(self, mock_open_key):
        """Testa a detecção do Npcap."""
        # Simular Npcap instalado
        mock_open_key.return_value = mock.MagicMock()
        
        pcap_manager = WindowsPcapManager()
        self.assertTrue(pcap_manager.is_npcap_installed)
        self.assertFalse(pcap_manager.is_winpcap_installed)
        
        # Simular Npcap não instalado
        mock_open_key.side_effect = [WindowsError, mock.MagicMock()]
        
        pcap_manager = WindowsPcapManager()
        self.assertFalse(pcap_manager.is_npcap_installed)
        self.assertTrue(pcap_manager.is_winpcap_installed)
        
        # Simular nenhum deles instalado
        mock_open_key.side_effect = WindowsError
        
        pcap_manager = WindowsPcapManager()
        self.assertFalse(pcap_manager.is_npcap_installed)
        self.assertFalse(pcap_manager.is_winpcap_installed)
    
    @mock.patch('sniffer.platform.windows.subprocess.run')
    def test_service_operations(self, mock_run):
        """Testa operações básicas de serviço."""
        # Mock para subprocess.run
        mock_run.return_value = mock.MagicMock(
            returncode=0,
            stdout="SERVICE_NAME: AONokiSniffer\nSTATE: 4 RUNNING",
            stderr=""
        )
        
        # Configurar o mock para check_admin
        with mock.patch('sniffer.platform.windows.WindowsServiceManager._check_admin', 
                        return_value=True):
            
            service_manager = WindowsServiceManager()
            
            # Testar instalação do serviço
            self.assertTrue(service_manager.install_service())
            
            # Testar inicialização do serviço
            self.assertTrue(service_manager.start_service())
            
            # Testar parada do serviço
            self.assertTrue(service_manager.stop_service())
            
            # Testar desinstalação do serviço
            self.assertTrue(service_manager.uninstall_service())
    
    def test_service_status(self):
        """Testa a obtenção do status do serviço."""
        # Mock para subprocess.run
        with mock.patch('sniffer.platform.windows.subprocess.run') as mock_run:
            service_manager = WindowsServiceManager()
            
            # Serviço em execução
            mock_run.return_value = mock.MagicMock(
                returncode=0,
                stdout="SERVICE_NAME: AONokiSniffer\nSTATE: 4 RUNNING",
                stderr=""
            )
            self.assertEqual(service_manager.get_service_status(), "running")
            
            # Serviço parado
            mock_run.return_value = mock.MagicMock(
                returncode=0,
                stdout="SERVICE_NAME: AONokiSniffer\nSTATE: 1 STOPPED",
                stderr=""
            )
            self.assertEqual(service_manager.get_service_status(), "stopped")
            
            # Serviço iniciando
            mock_run.return_value = mock.MagicMock(
                returncode=0,
                stdout="SERVICE_NAME: AONokiSniffer\nSTATE: 2 START_PENDING",
                stderr=""
            )
            self.assertEqual(service_manager.get_service_status(), "starting")
            
            # Serviço parando
            mock_run.return_value = mock.MagicMock(
                returncode=0,
                stdout="SERVICE_NAME: AONokiSniffer\nSTATE: 3 STOP_PENDING",
                stderr=""
            )
            self.assertEqual(service_manager.get_service_status(), "stopping")
            
            # Serviço não existente
            mock_run.return_value = mock.MagicMock(
                returncode=1,
                stdout="",
                stderr="O serviço especificado não existe como serviço instalado."
            )
            self.assertIsNone(service_manager.get_service_status())
    
    @mock.patch('sniffer.platform.windows.subprocess.run')
    def test_get_network_interfaces(self, mock_run):
        """Testa a obtenção das interfaces de rede."""
        # Mock da saída do ipconfig
        mock_run.return_value = mock.MagicMock(
            returncode=0,
            stdout=(
                "Adaptador Ethernet Ethernet:\n"
                "   Descrição . . . . . . . . . . . . : Intel(R) Ethernet Connection\n"
                "   Endereço Físico . . . . . . . . . : 00-11-22-33-44-55\n"
                "   Endereço IPv4. . . . . . . . . . . : 192.168.1.100(Preferencial)\n"
                "\n"
                "Adaptador de Rede sem Fio Wi-Fi:\n"
                "   Descrição . . . . . . . . . . . . : Intel(R) Wireless-AC 9560\n"
                "   Endereço Físico . . . . . . . . . : AA-BB-CC-DD-EE-FF\n"
                "   Endereço IPv4. . . . . . . . . . . : 192.168.1.101(Preferencial)\n"
            ),
            stderr=""
        )
        
        pcap_manager = WindowsPcapManager()
        interfaces = pcap_manager.get_network_interfaces()
        
        # Verificar se encontrou as duas interfaces
        self.assertEqual(len(interfaces), 2)
        
        # Verificar detalhes da primeira interface (Ethernet)
        self.assertEqual(interfaces[0]["name"], "Adaptador Ethernet Ethernet")
        self.assertEqual(interfaces[0]["description"], "Intel(R) Ethernet Connection")
        self.assertEqual(interfaces[0]["mac"], "00-11-22-33-44-55")
        self.assertEqual(interfaces[0]["ip"], "192.168.1.100")
        
        # Verificar detalhes da segunda interface (Wi-Fi)
        self.assertEqual(interfaces[1]["name"], "Adaptador de Rede sem Fio Wi-Fi")
        self.assertEqual(interfaces[1]["description"], "Intel(R) Wireless-AC 9560")
        self.assertEqual(interfaces[1]["mac"], "AA-BB-CC-DD-EE-FF")
        self.assertEqual(interfaces[1]["ip"], "192.168.1.101")

# Executar testes se este arquivo for executado diretamente
if __name__ == "__main__":
    unittest.main() 