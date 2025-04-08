# ![Brazil](https://raw.githubusercontent.com/stevenrskelton/flag-icon/master/png/16/country-4x3/br.png "Brazil") AO-Noki Sniffer

![Logo AO-Noki](https://github.com/AO-Noki.png)

## Descrição

O Sniffer AO-Noki é uma ferramenta especializada para monitoramento de tráfego do Albion Online, desenvolvida em Python. Este aplicativo captura e analisa pacotes de rede do protocolo Photon utilizado pelo jogo, disponibilizando essas informações via WebSocket para outras aplicações.

## Características Principais

- **Análise de Pacotes Photon**: Captura e decodifica pacotes do protocolo Photon usado pelo Albion Online
- **Servidor WebSocket**: Fornece dados de tráfego em tempo real para aplicações cliente na porta 10001
- **Operação em Segundo Plano**: Executa discretamente como serviço do sistema
- **Atualizações Automáticas**: Verifica e instala atualizações do repositório GitHub
- **Configuração Flexível**: Sistema de configuração para personalizar comportamentos
- **Verificação de Conectividade**: Monitora constantemente a conexão com a internet
- **Instância Única**: Previne execução de múltiplas instâncias simultaneamente
- **Sistema de Logs**: Armazena registros detalhados para depuração e auditoria
- **Compatibilidade Multi-plataforma**: Suporte para Windows, Linux, macOS, Android e iOS
- **Recuperação Automática**: Reinicialização automática em caso de falhas
- **Instalação de Dependências**: Gerenciamento automático de dependências do sistema
- **Verificação de Compatibilidade**: Validação de suporte à plataforma na inicialização
- **CI/CD Automatizado**: Workflows para geração de builds e releases automaticamente
- **Modo de Baixo Consumo**: Reduz uso de recursos quando o jogo não estiver em execução

## Requisitos do Sistema

- Windows 10/11, Linux, macOS, Android 9+ ou iOS 14+
- Privilégios de administrador (para captura de pacotes e instalação de serviço)
- Python 3.13+ (para execução)
- Conexão com a Internet (obrigatória para funcionamento)

### Dependências Específicas por Plataforma

#### Windows

- Npcap/WinPcap (instalado automaticamente se não encontrado)
- Microsoft Visual C++ Redistributable (instalado automaticamente)
- PowerShell 5.0+

#### Linux

- libpcap (instalado automaticamente via gerenciador de pacotes)
- Python3-dev e compiladores (para módulos nativos)
- systemd (para serviço)

#### macOS

- libpcap (instalado automaticamente via Homebrew)
- Xcode Command Line Tools (solicitado ao usuário se necessário)

#### Android

- Terminal Emulator ou Termux
- Root (para captura de pacotes) ou VPN mode
- Bibliotecas Python compiladas para ARM

#### iOS

- iSH ou outro ambiente Linux
- Modo VPN para captura de pacotes sem jailbreak

## Instalação

### Download da Versão Compilada

1. Acesse a [página de releases](https://github.com/AO-Noki/sniffer/releases)
2. Baixe a versão mais recente para seu sistema:
   - `ao-noki-sniffer-win-x64-vX.X.X.exe` (Windows 64 bits)
   - `ao-noki-sniffer-win-x86-vX.X.X.exe` (Windows 32 bits)
   - `ao-noki-sniffer-linux-x64-vX.X.X.AppImage` (Linux 64 bits)
   - `ao-noki-sniffer-macos-x64-vX.X.X.dmg` (macOS Intel)
   - `ao-noki-sniffer-macos-arm64-vX.X.X.dmg` (macOS Apple Silicon)
   - `ao-noki-sniffer-android-vX.X.X.apk` (Android)
   - `ao-noki-sniffer-ios-vX.X.X.ipa` (iOS - requer sideloading)
3. Execute o instalador e siga as instruções

### Instalação Manual

```bash
# Clone o repositório
git clone https://github.com/AO-Noki/sniffer.git

# Entre no diretório
cd sniffer

# Instale as dependências
pip install -r requirements.txt

# Execute a aplicação
python -m sniffer
```

## Uso

O aplicativo opera automaticamente após a instalação, sendo executado como serviço do sistema em segundo plano.

### Argumentos de Linha de Comando

O aplicativo aceita os seguintes argumentos quando executado:

- **`-console`**: Mostra a janela do console com output visual para acompanhamento do fluxo
  - Exemplo: `ao-noki-sniffer.exe -console`
  - Útil para desenvolvimento, diagnóstico e visualização do log em tempo real
  - Quando omitido, a aplicação executa em segundo plano na lista de aplicações (modo headless)

- **`-service`**: Instala e executa a aplicação como serviço do sistema operacional
  - Exemplo: `ao-noki-sniffer.exe -service`
  - Cria um serviço persistente que inicia automaticamente com o sistema
  - Configura tarefas de recuperação automática caso o serviço seja encerrado
  - Implementa os mecanismos de persistência específicos para cada sistema operacional:
    - Windows: Serviço do Windows + Tarefa Agendada para verificação
    - Linux: Serviço systemd com flags de restart automático
    - macOS: Serviço launchd com KeepAlive
    - Android/iOS: Serviço em foreground com notificação persistente

- **`-uninstall-service`**: Remove o serviço do sistema
  - Exemplo: `ao-noki-sniffer.exe -uninstall-service`
  - Desinstala completamente o serviço e as tarefas de recuperação associadas

Por padrão, sem argumentos, a aplicação executa como um processo regular em segundo plano (sem console visível).

### Modo de Baixo Consumo

O sniffer é projetado para minimizar o consumo de recursos do sistema:

- **Detecção de Albion Online**: Verifica automaticamente se o jogo está em execução
  - Utiliza detecção de processos no sistema operacional
  - Monitora a presença do executável do Albion Online
- **Monitoramento Seletivo**: Só inicia captura ativa quando o jogo está rodando
  - Quando o jogo não está em execução, permanece em modo de espera
  - Consome recursos mínimos (menos de 0.1% de CPU e 20-30MB de RAM)
- **Verificação Periódica**: A cada 30 segundos, verifica o status do jogo
  - Se o jogo for iniciado, ativa o modo de captura completa
  - Se o jogo for fechado, retorna ao modo de baixo consumo
- **Monitoramento de Tráfego**: Só processa pacotes quando há tráfego relevante
  - Se não detectar tráfego na porta monitorada por 60 segundos, reduz frequência de captura
  - Retoma captura normal quando o tráfego é detectado novamente
- **Status em Tempo Real**: Informa aos clientes WebSocket quando está em modo de baixo consumo
  - Envia mensagem de estado `{"type": "status", "mode": "idle"}` ou `{"type": "status", "mode": "active"}`

### Verificação de Compatibilidade

Na inicialização, o sniffer verifica automaticamente se está sendo executado em uma plataforma suportada:

- Se a plataforma não for suportada, o aplicativo exibe uma mensagem de erro e encerra
- Se a versão do sistema operacional for incompatível, sugere atualização
- Se hardware for insuficiente, exibe requisitos mínimos

### Diretórios da Aplicação

A aplicação usa os seguintes diretórios específicos por sistema operacional:

#### Windows

- **Instalação**: `C:\Program Files\AO-Noki\Sniffer\`
- **Logs**: `C:\ProgramData\AO-Noki\Sniffer\logs\`
- **Configuração**: `C:\ProgramData\AO-Noki\Sniffer\configs\`
- **Temporário**: `%TEMP%\AO-Noki\Sniffer\`

#### Linux

- **Instalação**: `/opt/ao-noki/sniffer/`
- **Logs**: `/var/log/ao-noki/sniffer/`
- **Configuração**: `/etc/ao-noki/sniffer/`
- **Temporário**: `/tmp/ao-noki/sniffer/`

#### macOS

- **Instalação**: `/Applications/AO-Noki Sniffer.app/`
- **Logs**: `~/Library/Logs/AO-Noki/Sniffer/`
- **Configuração**: `~/Library/Application Support/AO-Noki/Sniffer/`
- **Temporário**: `/tmp/ao-noki/sniffer/`

#### Android

- **Instalação**: `/data/data/com.termux/files/home/ao-noki/sniffer/` ou `/data/local/ao-noki/sniffer/`
- **Logs**: `/sdcard/Android/data/ao.noki.sniffer/logs/`
- **Configuração**: `/sdcard/Android/data/ao.noki.sniffer/configs/`
- **Temporário**: `/data/local/tmp/ao-noki/sniffer/`

#### iOS

- **Instalação**: Dentro do sandbox do aplicativo
- **Logs**: Dentro do sandbox com acesso via compartilhamento de arquivos
- **Configuração**: Dentro do sandbox com interface de configuração
- **Temporário**: Diretório temporário do sandbox

### Mecanismos de Persistência e Recuperação

Quando executado com o argumento `-service`, o sniffer implementa múltiplos mecanismos para garantir sua execução contínua:

#### Windows

- Serviço do Windows com reinicialização automática
- Tarefa agendada para verificação do serviço a cada 5 minutos
- Registro de inicialização (opcional)

#### Linux

- Serviço systemd com flag Restart=always
- Timer systemd para verificação a cada 5 minutos
- Crontab para verificação adicional (fallback)

#### macOS

- Serviço launchd com KeepAlive=true
- Watchdog para monitoramento e reinicialização

#### Android/iOS

- Serviço em foreground com notificação persistente
- Função de reinicialização na inicialização do dispositivo

### Instalação de Dependências

Durante a primeira execução ou após atualizações do sistema, o sniffer:

1. Verifica dependências necessárias para captura de pacotes
2. Se não encontradas, inicia processo automatizado de instalação:
   - Windows: Download e instalação silenciosa de Npcap/WinPcap
   - Linux: Instalação via apt/yum/pacman/etc. conforme distribuição
   - macOS: Instalação via Homebrew
   - Android: Instalação via package manager específico
3. Se necessário, solicita reinicialização do sistema
4. Após reinicialização, retoma automaticamente a operação

### Instância Única

O sniffer implementa um mecanismo de verificação de instância única:

- Ao iniciar, verifica se já existe uma instância em execução como serviço do sistema
- Se uma instância for detectada em outro diretório:
  - Encerra o serviço atual
  - Recria o serviço apontando para o diretório atual
  - Inicia o novo serviço
- Se uma instância já estiver em execução no mesmo diretório:
  - A nova tentativa de execução é interrompida
  - Uma mensagem de erro é registrada nos logs
  - Notificação: "Um serviço do AO-Noki-Sniffer-vX.X.X já está em execução"

### Sistema de Logs

O sniffer mantém logs detalhados das operações:

- **Nível de Log**: Configurável (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- **Rotação de Logs**: Arquivos são rotacionados diariamente ou quando atingem 10MB
- **Retenção**: Mantém logs por até 30 dias
- **Formato**: JSON estruturado para fácil análise
- **Campos**: timestamp, nível, mensagem, exceção (se aplicável), contexto
- **Monitoramento de Falhas**: Detecção e registro de crashes com recuperação automática

### Requisito de Conectividade

O sniffer requer uma conexão ativa com a internet para funcionar. Caso a conexão seja perdida:

- O aplicativo tentará restabelecer a conexão periodicamente
- Um aviso será exibido para o usuário
- As funcionalidades continuarão limitadas até que a conexão seja restaurada

### Conexão WebSocket

As aplicações cliente podem se conectar ao sniffer via WebSocket:

```
ws://localhost:10001/ws
```

Isso permite que aplicações web rodando em navegadores ou clientes nativos possam consumir os dados em tempo real.

### Configurações

O sniffer possui um sistema de configuração com os seguintes parâmetros padrão:

```json
{
  "ws_host": "0.0.0.0",
  "ws_port": 10001,
  "auto_update": true,
  "update_check_interval": 3600,
  "connectivity_check_interval": 300,
  "connectivity_check_url": "https://api.github.com/repos/AO-Noki/sniffer",
  "log_level": "info",
  "log_dir": "%PLATFORM_LOG_DIR%",
  "log_max_size_mb": 10,
  "log_backup_count": 30,
  "packet_filter": "udp port 5056",
  "lock_file_path": "%TEMP%/ao-noki-sniffer.lock",
  "service_name": "AO-Noki-Sniffer",
  "recovery_enabled": true,
  "recovery_check_interval": 300,
  "auto_install_dependencies": true,
  "allow_reboot_after_dependency_install": false,
  "check_platform_compatibility": true,
  "low_resource_mode": true,
  "game_process_check_interval": 30,
  "traffic_idle_threshold": 60,
  "albion_process_names": ["Albion-Online.exe", "AlbionOnline"]
}
```

Estas configurações podem ser modificadas no arquivo de configuração específico da plataforma.

### Formato dos Dados

Os dados são transmitidos em formato JSON com a seguinte estrutura:

```json
{
  "type": "photonEvent",
  "timestamp": 1679580125,
  "data": {
    "eventCode": 1,
    "parameters": {
      // Parâmetros específicos do evento
    }
  }
}
```

## Detalhes Técnicos do Protocolo Photon

### Visão Geral do Protocolo

O Albion Online utiliza o protocolo Photon para comunicação cliente-servidor. Este protocolo opera sobre UDP (geralmente na porta 5056) e implementa seus próprios mecanismos de confiabilidade e fragmentação.

### Estrutura do Pacote Photon

1. **Cabeçalho Photon (12 bytes)**:
   - `PeerID` (2 bytes): Identificador do peer na sessão
   - `CrcEnabled` (1 byte): Flag indicando se CRC está habilitado
   - `CommandCount` (1 byte): Número de comandos no pacote
   - `Timestamp` (4 bytes): Timestamp do pacote
   - `Challenge` (4 bytes): Valor de desafio para autenticação

2. **Comandos Photon**:
   Cada pacote pode conter múltiplos comandos. Tipos de comandos incluem:
   - `Acknowledge (1)`: Confirmação de recebimento
   - `Connect (2)`: Estabelecimento de conexão
   - `VerifyConnect (3)`: Verificação de conexão
   - `Disconnect (4)`: Encerramento de conexão
   - `Ping (5)`: Verificação de latência
   - `SendReliable (6)`: Mensagem garantida
   - `SendUnreliable (7)`: Mensagem não garantida
   - `SendReliableFragment (8)`: Fragmento de mensagem garantida

3. **Estrutura de Comando**:
   - `Type` (1 byte): Tipo do comando
   - `ChannelID` (1 byte): Canal de comunicação
   - `Flags` (1 byte): Flags de controle
   - `ReservedByte` (1 byte): Reservado
   - `Length` (4 bytes): Comprimento do comando
   - `ReliableSequenceNumber` (4 bytes): Número de sequência para comandos confiáveis
   - `Data` (variável): Dados do comando

### Tipos de Mensagens

As mensagens podem ser de diferentes tipos:

- `OperationRequest (2)`: Solicitação de operação ao servidor
- `OperationResponse (7)`: Resposta do servidor a uma solicitação
- `EventData (4)`: Evento enviado pelo servidor

### Fragmentação de Mensagens

Mensagens grandes são divididas em fragmentos:

1. Um pacote `SendReliableFragment` contém:
   - `SequenceNumber`: Identificador único da mensagem completa
   - `FragmentCount`: Número total de fragmentos
   - `FragmentNumber`: Número deste fragmento (0-indexed)
   - `TotalLength`: Tamanho total da mensagem completa
   - `FragmentOffset`: Posição deste fragmento na mensagem completa
   - `Data`: Conteúdo do fragmento

2. O sistema de buffer de fragmentos:
   - Armazena fragmentos recebidos em um cache
   - Reconstrói a mensagem completa quando todos os fragmentos são recebidos
   - Converte a mensagem reconstruída em um comando `SendReliable`

### Decodificação de Mensagens

A decodificação de mensagens segue um processo de várias etapas:

1. **Extração de Parâmetros**: As mensagens confiáveis contêm pares chave-valor:
   - Cada parâmetro tem um ID (1 byte) e um tipo (1 byte)
   - Os valores são decodificados de acordo com o tipo

2. **Tipos de Dados Suportados**:
   - Tipos primitivos: Int8, Int16, Int32, Int64, Float32, Boolean, String
   - Tipos compostos: Arrays, Dicionários, Hashtables
   - Tipos customizados: EventData, OperationRequest, OperationResponse

3. **Processamento de Eventos**:
   - Cada evento tem um código específico (EventCode)
   - Os parâmetros do evento contêm dados relevantes para o jogo
   - Eventos críticos incluem movimentação, combate, mercado, e chat

### Implementação em Python

A implementação em Python precisa considerar:

1. **Captura de Pacotes**:
   - Usar bibliotecas como Scapy, PyShark, ou bindings para libpcap
   - Filtrar apenas pacotes UDP na porta 5056
   - Analisar o payload UDP para identificar cabeçalhos Photon

2. **Estruturas de Dados**:
   - Classes para representar camadas Photon, comandos e mensagens
   - Sistema de buffer para lidar com fragmentação
   - Decodificadores para cada tipo de dado suportado

3. **Otimizações de Performance**:
   - Usar `struct` para decodificação binária eficiente
   - Implementar cache LRU para mensagens fragmentadas
   - Considerar processamento paralelo para alta carga de pacotes

## Arquitetura

O projeto é estruturado nos seguintes componentes:

1. **Captura de Pacotes**: Utiliza a biblioteca Scapy/PyShark para interceptar tráfego UDP
2. **Decodificador Photon**: Processa e decodifica os pacotes do protocolo Photon
   - **PhotonLayer**: Parseia o cabeçalho Photon e extrai comandos
   - **PhotonCommand**: Processa diferentes tipos de comandos (reliable, unreliable, fragment)
   - **FragmentBuffer**: Gerencia e reconstrói mensagens fragmentadas
   - **MessageDecoder**: Extrai e decodifica parâmetros de mensagens confiáveis
3. **Servidor WebSocket**: Distribui os dados processados para clientes conectados
4. **Gerenciador de Atualizações**: Verifica e instala novas versões automaticamente
5. **Sistema de Configuração**: Gerencia configurações e parâmetros do aplicativo
6. **Monitor de Conectividade**: Verifica a conexão com a internet e com o repositório
7. **Gerenciador de Instância**: Garante que apenas uma instância do aplicativo seja executada
8. **Sistema de Logs**: Registra eventos e erros do aplicativo
9. **Gerenciador de Serviços**: Controla a instalação e execução como serviço do sistema
10. **Gerenciador de Dependências**: Identifica e instala dependências necessárias
11. **Sistema de Recuperação**: Monitora e recupera de falhas
12. **Verificador de Compatibilidade**: Valida compatibilidade de plataforma e requisitos
13. **Monitor de Processos**: Detecta a execução do jogo para ativar/desativar captura

## Roadmap

### Em Desenvolvimento

- [x] **Sistema Base**: Classes principais e organização do projeto
- [x] **Detecção de Plataforma**: Sistema para identificar o ambiente de execução
- [x] **Argumentos de Linha de Comando**: Parser e processador de comandos
- [x] **Sistema de Registro (Logs)**: Configuração de logging com rotação
- [x] **Suporte Windows**: Implementação das classes específicas para Windows
  - [x] **Gerenciador de Serviços Windows**: Instalação e controle de serviços
  - [x] **Verificação de Informações de Sistema**: Obtenção de dados da plataforma
  - [x] **Instalador Npcap/WinPcap**: Download e instalação automatizada  
  - [x] **Captura de Pacotes Windows**: Integração com pcap usando Scapy
  - [x] **Interface com Protocolo Photon**: Classes para captura e análise de pacotes Photon
  - [x] **Testes para o Módulo Windows**: Validação da implementação Windows
- [ ] **Implementação do Protocolo Photon**: Decodificador para o protocolo de rede
  - [ ] **Estrutura Base do Parser**: Classes para decodificação de pacotes
  - [ ] **Decodificação de Comandos**: Processamento de comandos Photon
  - [ ] **Reconstrução de Mensagens**: Reagrupar mensagens fragmentadas
  - [ ] **Parser de Eventos**: Analisar eventos específicos do jogo
- [ ] **Servidor WebSocket**: Interface para enviar dados em tempo real
- [ ] **Interface Web Básica**: Dashboard para exibir dados capturados
- [ ] **Modo de Baixo Consumo**: Detecção do jogo e ajuste de uso de recursos
- [ ] **Automatização de CI/CD**: GitHub Actions para build e release
- [ ] **Suporte Linux**: Implementação básica para Linux
- [ ] **Suporte macOS**: Implementação básica para macOS

### Pendente (Futuro)

- [ ] **Verificações de Compatibilidade**: Melhorias nos checks de sistema
- [ ] **Gerenciamento de Memória Avançado**: Otimização para dispositivos com restrições
- [ ] **Módulo de Atualizações**: Sistema de verificação e instalação de atualizações
- [ ] **Painel de Administração**: Interface para controle e configuração
- [ ] **Suporte a Dispositivos Móveis**: Adaptação para Android e iOS
- [ ] **Análise Avançada de Pacotes**: Machine learning para detecção de padrões
- [ ] **Instalador Gráfico**: Simplificação do processo de instalação
- [ ] **Documentação Completa**: Manual de usuário e referência para desenvolvedores

## Fluxo de Operação

1. O sniffer verifica compatibilidade com a plataforma atual
   - Se incompatível, exibe mensagem de erro e encerra
2. Verifica se já existe uma instância em execução como serviço
   - Se sim em outro diretório, atualiza o serviço para o diretório atual
   - Se sim no mesmo diretório, exibe notificação e encerra
   - Se não, continua a inicialização
3. Verifica e instala dependências necessárias do sistema
   - Se instalação de dependências necessitar reinicialização, programa tarefa para continuar após reboot
4. Carrega as configurações do arquivo específico da plataforma
5. Configura o sistema de logs
6. Verifica a conexão com a internet:
   - Se não houver conexão, tenta novamente em intervalos definidos
   - Se a conexão for estabelecida, continua a inicialização
7. Inicia no modo de baixo consumo, verificando periodicamente se o jogo está em execução
8. Quando o jogo for detectado:
   - Inicia a captura de pacotes para tráfego UDP na porta do Albion Online
   - Ativa o processamento completo do protocolo Photon
9. Quando pacotes são capturados:
   - Eles são processados pelo decodificador Photon
   - Os eventos extraídos são formatados em JSON
   - Os dados são transmitidos para todos os clientes conectados via WebSocket
10. Se o jogo for fechado ou nenhum tráfego for detectado por um período:
    - Retorna ao modo de baixo consumo
    - Mantém apenas funcionalidades essenciais ativas
11. Em paralelo, threads separadas executam:
    - Verificação periódica de conectividade com a internet
    - Verificação periódica de atualizações no repositório GitHub
    - Monitoramento e recuperação automática em caso de falhas
    - Verificação da presença do processo do jogo
    - Se uma atualização for encontrada, o aplicativo:
      - Baixa a nova versão para uma pasta temporária
      - Fecha a instância atual
      - Instala a nova versão usando ferramentas específicas do sistema operacional
      - Reinicia o serviço automaticamente

## Licença

Este projeto é distribuído sob a licença [MIT](LICENSE).

## Ética

Este projeto adere aos princípios de fair play e respeito às regras do jogo. **Sob nenhuma circunstância permitimos que nossos projetos sejam usados para obter vantagens injustas sobre outros jogadores ou comprometer a integridade do jogo.**

## Contato

Sinta-se à vontade para explorar nossos repositórios e contribuir com ideias, relatórios de bugs ou melhorias.
Juntos, podemos fazer a diferença para a comunidade de Albion Online!

---

> "Jogar limpo é mais do que uma regra: é uma escolha."
