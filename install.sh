#!/usr/bin/env bash
#===============================================================================
# InfraPro Cloud Oracle - Instalação Automatizada
# Versão: 1.0.0
# Autor: Márcio Calicchio
# Ambiente: Oracle Cloud ARM64 (aarch64) + Ubuntu Server 24.04
#
# USO:
#   curl -fsSL https://raw.githubusercontent.com/calicchiom/infrapro-oracle-cloud/main/install.sh | bash
#   ou
#   ./install.sh [--debug] [--from-bootstrap]
#
# REQUISITOS:
#   - Ubuntu 24.04 ARM64
#   - Usuário com sudo
#   - Conexão à internet
#===============================================================================

set -Eeuo pipefail

#===============================================================================
# CONFIGURAÇÕES GLOBAIS - EXECUÇÃO NÃO-INTERATIVA
#===============================================================================
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1
export UCF_FORCE_CONFFNEW=1
export LANG=C.UTF-8
export LC_ALL=C.UTF-8

# Opções APT padrão para evitar QUALQUER interação
APT_OPTS=(
    -y
    -o Dpkg::Options::="--force-confnew"
    -o Dpkg::Options::="--force-confdef"
    -o APT::Get::Assume-Yes=true
    -o APT::Get::AllowUnauthenticated=false
    -o Dpkg::Use-Pty=0
)

#===============================================================================
# VARIÁVEIS GLOBAIS
#===============================================================================
readonly VERSION="1.0.0"
readonly SCRIPT_NAME="InfraPro Cloud Oracle"
readonly AUTHOR="Márcio Calicchio"
readonly LOG_FILE="$HOME/infrapro-install.log"
readonly ENV_FILE="$HOME/.infrapro.env"
readonly REPO_URL="https://github.com/calicchiom/infrapro-oracle-cloud"
readonly REPO_DIR="$HOME/infrapro-oracle-cloud"

# Flags
DEBUG_MODE=false
FROM_BOOTSTRAP=false
INSIDE_REPO=false
REBOOT_RECOMMENDED=false

# Variáveis de input (preenchidas durante execução)
PORTAINER_URL=""
PORTAINER_ADMIN_USER=""
PORTAINER_ADMIN_PASS=""
OVERLAY_NETWORK_NAME=""
SSL_EMAIL=""
POSTGRES_PASSWORD=""
LOCAL_IP=""
PUBLIC_IP=""

#===============================================================================
# TRAP E TRATAMENTO DE ERROS
#===============================================================================
cleanup() {
    local exit_code=$?
    if [[ $exit_code -ne 0 ]]; then
        log_error "Script interrompido com código de saída: $exit_code"
        log_error "Verifique o log em: $LOG_FILE"
    fi
}

trap 'echo -e "\n❌ ERRO: Falha na linha $LINENO. Comando: $BASH_COMMAND" >&2; cleanup' ERR
trap cleanup EXIT

#===============================================================================
# FUNÇÕES DE LOG
#===============================================================================
log_init() {
    mkdir -p "$(dirname "$LOG_FILE")"
    exec > >(tee -a "$LOG_FILE") 2>&1
    echo ""
    echo "==============================================================================="
    echo "Log iniciado em: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "==============================================================================="
}

log_timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

log_info() {
    echo -e "[$(log_timestamp)] 📋 INFO: $*"
}

log_success() {
    echo -e "[$(log_timestamp)] ✅ SUCESSO: $*"
}

log_warning() {
    echo -e "[$(log_timestamp)] ⚠️  AVISO: $*"
}

log_error() {
    echo -e "[$(log_timestamp)] ❌ ERRO: $*" >&2
}

log_progress() {
    echo -e "[$(log_timestamp)] 🔄 PROGRESSO: $*"
}

log_section() {
    echo ""
    echo "==============================================================================="
    echo "  $*"
    echo "==============================================================================="
    echo ""
}

print_banner() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                               ║"
    echo "║   ██╗███╗   ██╗███████╗██████╗  █████╗ ██████╗ ██████╗  ██████╗               ║"
    echo "║   ██║████╗  ██║██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔═══██╗              ║"
    echo "║   ██║██╔██╗ ██║█████╗  ██████╔╝███████║██████╔╝██████╔╝██║   ██║              ║"
    echo "║   ██║██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║██╔═══╝ ██╔══██╗██║   ██║              ║"
    echo "║   ██║██║ ╚████║██║     ██║  ██║██║  ██║██║     ██║  ██║╚██████╔╝              ║"
    echo "║   ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝               ║"
    echo "║                                                                               ║"
    echo "║                        Cloud Oracle - ARM64 Edition                           ║"
    echo "║                                                                               ║"
    echo "║   Criado por: $AUTHOR                                              ║"
    echo "║   Versão: $VERSION                                                            ║"
    echo "║                                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
}

#===============================================================================
# FUNÇÕES AUXILIARES
#===============================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --debug)
                DEBUG_MODE=true
                shift
                ;;
            --from-bootstrap)
                FROM_BOOTSTRAP=true
                shift
                ;;
            *)
                log_warning "Argumento desconhecido: $1"
                shift
                ;;
        esac
    done
    
    if [[ "$DEBUG_MODE" == true ]]; then
        set -x
        log_info "Modo debug ativado"
    fi
}

check_inside_repo() {
    # Detecta se estamos dentro do repositório clonado
    if [[ -f "./traefik.yml" && -f "./portainer.yml" && -f "./uninstall.sh" ]]; then
        INSIDE_REPO=true
    fi
}

check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "Este script NÃO deve ser executado como root."
        log_error "Execute como usuário normal com privilégios sudo."
        exit 1
    fi
    
    if ! sudo -v &>/dev/null; then
        log_error "Usuário não possui privilégios sudo."
        exit 1
    fi
    
    log_success "Verificação de privilégios: OK"
}

check_architecture() {
    local arch
    arch=$(uname -m)
    
    if [[ "$arch" != "aarch64" ]]; then
        log_error "Arquitetura não suportada: $arch"
        log_error "Este script requer ARM64 (aarch64)"
        exit 1
    fi
    
    log_success "Arquitetura ARM64 (aarch64): OK"
}

check_ubuntu_version() {
    if [[ ! -f /etc/os-release ]]; then
        log_error "Arquivo /etc/os-release não encontrado"
        exit 1
    fi
    
    source /etc/os-release
    
    if [[ "$ID" != "ubuntu" ]]; then
        log_error "Sistema operacional não suportado: $ID"
        log_error "Este script requer Ubuntu"
        exit 1
    fi
    
    if [[ "${VERSION_ID}" != "24.04" ]]; then
        log_warning "Versão do Ubuntu: $VERSION_ID (esperado: 24.04)"
        log_warning "O script pode funcionar, mas não foi testado nesta versão"
    else
        log_success "Ubuntu 24.04: OK"
    fi
}

check_internet() {
    log_progress "Verificando conectividade com a internet..."
    
    local test_hosts=("google.com" "github.com" "download.docker.com")
    local success=false
    
    for host in "${test_hosts[@]}"; do
        if ping -c 1 -W 5 "$host" &>/dev/null; then
            success=true
            break
        fi
    done
    
    if [[ "$success" != true ]]; then
        log_error "Sem conectividade com a internet"
        exit 1
    fi
    
    log_success "Conectividade com a internet: OK"
}

get_local_ip() {
    LOCAL_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' || echo "")
    
    if [[ -z "$LOCAL_IP" ]]; then
        LOCAL_IP=$(hostname -I | awk '{print $1}')
    fi
    
    if [[ -z "$LOCAL_IP" ]]; then
        log_error "Não foi possível determinar o IP local"
        exit 1
    fi
    
    log_info "IP local detectado: $LOCAL_IP"
}

get_public_ip() {
    log_progress "Obtendo IP público..."
    
    local services=("ifconfig.me" "ipecho.net/plain" "icanhazip.com" "api.ipify.org")
    
    for service in "${services[@]}"; do
        PUBLIC_IP=$(curl -s --connect-timeout 5 "$service" 2>/dev/null | tr -d '[:space:]' || echo "")
        if [[ -n "$PUBLIC_IP" && "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            log_info "IP público detectado: $PUBLIC_IP"
            return 0
        fi
    done
    
    log_warning "Não foi possível obter IP público"
    PUBLIC_IP="N/A"
}

#===============================================================================
# FUNÇÕES APT COM RETRY E LOCK HANDLING
#===============================================================================
wait_for_apt_lock() {
    local max_wait=300
    local wait_time=0
    
    while fuser /var/lib/dpkg/lock-frontend &>/dev/null 2>&1 || \
          fuser /var/lib/apt/lists/lock &>/dev/null 2>&1 || \
          fuser /var/cache/apt/archives/lock &>/dev/null 2>&1; do
        
        if [[ $wait_time -ge $max_wait ]]; then
            log_error "Timeout aguardando liberação do lock do APT"
            return 1
        fi
        
        log_warning "APT está bloqueado por outro processo. Aguardando... ($wait_time/$max_wait segundos)"
        sleep 5
        ((wait_time+=5))
    done
    
    return 0
}

fix_dpkg_if_needed() {
    if sudo dpkg --audit 2>&1 | grep -q .; then
        log_warning "Detectado dpkg em estado inconsistente. Tentando recuperar..."
        sudo dpkg --configure -a --force-confnew --force-confdef || {
            log_error "Falha ao recuperar dpkg"
            return 1
        }
        log_success "dpkg recuperado"
    fi
    return 0
}

apt_safe() {
    local cmd="$1"
    shift
    local max_retries=3
    local retry=0
    
    while [[ $retry -lt $max_retries ]]; do
        wait_for_apt_lock || return 1
        fix_dpkg_if_needed || return 1
        
        if sudo apt-get "$cmd" "${APT_OPTS[@]}" "$@"; then
            return 0
        fi
        
        ((retry++))
        log_warning "apt-get $cmd falhou. Tentativa $retry de $max_retries"
        sleep 5
    done
    
    log_error "apt-get $cmd falhou após $max_retries tentativas"
    return 1
}

#===============================================================================
# FUNÇÕES DE VALIDAÇÃO DE INPUT
#===============================================================================
validate_hostname() {
    local hostname="$1"
    
    # Remove protocolo se presente
    hostname="${hostname#http://}"
    hostname="${hostname#https://}"
    hostname="${hostname%%/*}"
    hostname="${hostname%%:*}"
    
    # Validação básica de hostname
    if [[ ! "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 1
    fi
    
    # Verifica DNS (apenas aviso)
    if command -v dig &>/dev/null; then
        if ! dig +short "$hostname" &>/dev/null; then
            log_warning "DNS para $hostname não resolveu (pode estar correto se ainda não configurado)"
        fi
    fi
    
    echo "$hostname"
    return 0
}

validate_username() {
    local username="$1"
    
    if [[ ${#username} -lt 3 ]]; then
        return 1
    fi
    
    if [[ ! "$username" =~ ^[a-zA-Z][a-zA-Z0-9_]*$ ]]; then
        return 1
    fi
    
    return 0
}

validate_password() {
    local password="$1"
    
    if [[ ${#password} -lt 12 ]]; then
        return 1
    fi
    
    return 0
}

validate_email() {
    local email="$1"
    
    if [[ ! "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 1
    fi
    
    return 0
}

validate_docker_network_name() {
    local name="$1"
    
    if [[ ${#name} -lt 2 || ${#name} -gt 64 ]]; then
        return 1
    fi
    
    if [[ ! "$name" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]]; then
        return 1
    fi
    
    return 0
}

#===============================================================================
# COLETA DE INPUTS
#===============================================================================
collect_inputs() {
    log_section "COLETA DE INFORMAÇÕES"
    
    echo "Por favor, forneça as informações necessárias para a instalação."
    echo "Todas as senhas devem ter no mínimo 12 caracteres."
    echo ""
    
    # URL do Portainer
    while true; do
        read -rp "📋 URL do Portainer (hostname sem http/https, ex: portainer.exemplo.com): " PORTAINER_URL
        if validated_url=$(validate_hostname "$PORTAINER_URL"); then
            PORTAINER_URL="$validated_url"
            log_success "URL validada: $PORTAINER_URL"
            break
        else
            log_error "Hostname inválido. Tente novamente."
        fi
    done
    
    # Usuário admin do Portainer
    while true; do
        read -rp "📋 Usuário admin do Portainer (mínimo 3 caracteres, alfanumérico): " PORTAINER_ADMIN_USER
        if validate_username "$PORTAINER_ADMIN_USER"; then
            log_success "Usuário validado: $PORTAINER_ADMIN_USER"
            break
        else
            log_error "Usuário inválido. Use apenas letras, números e underscore (mínimo 3 caracteres)."
        fi
    done
    
    # Senha do Portainer
    while true; do
        read -rsp "🔐 Senha do Portainer (mínimo 12 caracteres): " PORTAINER_ADMIN_PASS
        echo ""
        if ! validate_password "$PORTAINER_ADMIN_PASS"; then
            log_error "Senha muito curta. Mínimo 12 caracteres."
            continue
        fi
        
        read -rsp "🔐 Confirme a senha do Portainer: " pass_confirm
        echo ""
        if [[ "$PORTAINER_ADMIN_PASS" != "$pass_confirm" ]]; then
            log_error "Senhas não conferem. Tente novamente."
            continue
        fi
        
        log_success "Senha do Portainer validada"
        break
    done
    
    # Nome da rede overlay
    while true; do
        read -rp "📋 Nome da rede overlay Docker (ex: infrapro-network): " OVERLAY_NETWORK_NAME
        if validate_docker_network_name "$OVERLAY_NETWORK_NAME"; then
            log_success "Nome da rede validado: $OVERLAY_NETWORK_NAME"
            break
        else
            log_error "Nome inválido. Use letras, números, hífens e underscores (2-64 caracteres)."
        fi
    done
    
    # Email para SSL
    while true; do
        read -rp "📧 Email para certificados SSL (Let's Encrypt): " SSL_EMAIL
        if validate_email "$SSL_EMAIL"; then
            log_success "Email validado: $SSL_EMAIL"
            break
        else
            log_error "Email inválido. Tente novamente."
        fi
    done
    
    # Senha do PostgreSQL
    while true; do
        read -rsp "🔐 Senha do PostgreSQL (mínimo 12 caracteres): " POSTGRES_PASSWORD
        echo ""
        if ! validate_password "$POSTGRES_PASSWORD"; then
            log_error "Senha muito curta. Mínimo 12 caracteres."
            continue
        fi
        
        read -rsp "🔐 Confirme a senha do PostgreSQL: " pass_confirm
        echo ""
        if [[ "$POSTGRES_PASSWORD" != "$pass_confirm" ]]; then
            log_error "Senhas não conferem. Tente novamente."
            continue
        fi
        
        log_success "Senha do PostgreSQL validada"
        break
    done
    
    echo ""
    log_success "Todas as informações coletadas com sucesso!"
    
    # Salvar configurações (sem senhas em texto)
    save_env_file
}

save_env_file() {
    log_progress "Salvando configurações em $ENV_FILE..."
    
    cat > "$ENV_FILE" << EOF
# InfraPro Cloud Oracle - Configurações
# Gerado em: $(date '+%Y-%m-%d %H:%M:%S')
# ATENÇÃO: Este arquivo contém informações sensíveis!

PORTAINER_URL=$PORTAINER_URL
PORTAINER_ADMIN_USER=$PORTAINER_ADMIN_USER
OVERLAY_NETWORK_NAME=$OVERLAY_NETWORK_NAME
SSL_EMAIL=$SSL_EMAIL
LOCAL_IP=$LOCAL_IP
PUBLIC_IP=$PUBLIC_IP

# Senhas são armazenadas em Docker Secrets
# Não armazene senhas em texto neste arquivo
EOF

    chmod 600 "$ENV_FILE"
    log_success "Configurações salvas em $ENV_FILE (chmod 600)"
}

#===============================================================================
# BOOTSTRAP - CLONE DO REPOSITÓRIO
#===============================================================================
bootstrap_clone_repo() {
    log_section "BOOTSTRAP - PREPARAÇÃO DO AMBIENTE"
    
    # Verifica se já estamos no repositório
    if [[ "$INSIDE_REPO" == true ]] || [[ "$FROM_BOOTSTRAP" == true ]]; then
        log_info "Execução a partir do repositório detectada. Continuando..."
        return 0
    fi
    
    log_progress "Clonando repositório $REPO_URL..."
    
    # Remove diretório existente se houver
    if [[ -d "$REPO_DIR" ]]; then
        log_warning "Diretório $REPO_DIR já existe. Atualizando..."
        cd "$REPO_DIR"
        git fetch origin
        git reset --hard origin/main || git reset --hard origin/master
        cd - > /dev/null
    else
        git clone "$REPO_URL" "$REPO_DIR" || {
            log_error "Falha ao clonar repositório"
            exit 1
        }
    fi
    
    # Validar arquivos essenciais
    local required_files=("install.sh" "uninstall.sh" "traefik.yml" "portainer.yml")
    for file in "${required_files[@]}"; do
        if [[ ! -f "$REPO_DIR/$file" ]]; then
            log_error "Arquivo obrigatório não encontrado: $REPO_DIR/$file"
            exit 1
        fi
    done
    
    log_success "Repositório clonado e validado"
    
    # Tornar scripts executáveis
    chmod +x "$REPO_DIR/install.sh"
    chmod +x "$REPO_DIR/uninstall.sh"
    
    # Copiar YAMLs para HOME
    cp "$REPO_DIR/traefik.yml" "$HOME/traefik.yml"
    cp "$REPO_DIR/portainer.yml" "$HOME/portainer.yml"
    log_success "Arquivos YAML copiados para $HOME"
    
    # Executar o script do repositório
    log_progress "Delegando execução para o script do repositório..."
    
    cd "$REPO_DIR"
    
    local exec_args=("--from-bootstrap")
    if [[ "$DEBUG_MODE" == true ]]; then
        exec_args+=("--debug")
    fi
    
    exec ./install.sh "${exec_args[@]}"
}

#===============================================================================
# FASE 1 - PREPARAÇÃO DO UBUNTU
#===============================================================================
phase1_prepare_ubuntu() {
    log_section "FASE 1 - PREPARAÇÃO DO UBUNTU"
    
    # 1.1 Desabilitar atualizações automáticas
    log_progress "1.1 Desabilitando atualizações automáticas..."
    
    # Configura /etc/apt/apt.conf.d/20auto-upgrades
    sudo tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null << 'EOF'
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "0";
APT::Periodic::Unattended-Upgrade "0";
EOF
    
    # Configura needrestart para modo automático
    if [[ -f /etc/needrestart/needrestart.conf ]]; then
        sudo sed -i "s/#\$nrconf{restart} = 'i';/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf
        sudo sed -i "s/\$nrconf{restart} = 'i';/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf
    fi
    
    # Criar configuração para evitar prompts
    sudo tee /etc/apt/apt.conf.d/99-infrapro-nointeractive > /dev/null << 'EOF'
Dpkg::Options {
   "--force-confdef";
   "--force-confnew";
}
APT::Get::Assume-Yes "true";
APT::Get::allow-downgrades "true";
APT::Get::allow-remove-essential "false";
EOF
    
    # Parar serviços de atualização automática
    local services=("unattended-upgrades" "apt-daily.timer" "apt-daily-upgrade.timer" "apt-daily.service" "apt-daily-upgrade.service")
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            sudo systemctl stop "$service" 2>/dev/null || true
            sudo systemctl disable "$service" 2>/dev/null || true
            log_info "Serviço $service desabilitado"
        fi
    done
    
    # Mascarar serviços para evitar reativação
    sudo systemctl mask apt-daily.service apt-daily-upgrade.service 2>/dev/null || true
    
    log_success "1.1 Atualizações automáticas desabilitadas"
    
    # 1.2 Remover unattended-upgrades
    log_progress "1.2 Removendo unattended-upgrades..."
    
    if dpkg -l | grep -q unattended-upgrades; then
        apt_safe remove unattended-upgrades
        apt_safe autoremove
        log_success "1.2 unattended-upgrades removido"
    else
        log_info "1.2 unattended-upgrades não estava instalado"
    fi
    
    # 1.3 Update e Upgrade do sistema
    log_progress "1.3 Atualizando sistema (apt update/upgrade)..."
    
    apt_safe update
    apt_safe upgrade
    
    # Instalar apparmor-utils
    apt_safe install apparmor-utils
    
    # Verificar se kernel foi atualizado
    local running_kernel
    local installed_kernel
    running_kernel=$(uname -r)
    installed_kernel=$(dpkg -l | grep -E "^ii\s+linux-image-[0-9]" | tail -1 | awk '{print $2}' | sed 's/linux-image-//' || echo "")
    
    if [[ -n "$installed_kernel" && "$running_kernel" != "$installed_kernel" ]]; then
        REBOOT_RECOMMENDED=true
        log_warning "Kernel atualizado de $running_kernel para $installed_kernel"
        log_warning "Reboot recomendado após a conclusão da instalação"
    fi
    
    log_success "1.3 Sistema atualizado"
    
    # 1.4 Instalar dependências básicas
    log_progress "1.4 Instalando dependências básicas..."
    
    local packages=(
        curl wget git ca-certificates gnupg lsb-release apt-transport-https
        software-properties-common dnsutils jq unzip net-tools htop tree vim nano
    )
    
    apt_safe install "${packages[@]}"
    
    log_success "1.4 Dependências instaladas"
    
    # 1.5 Configurar UFW
    log_progress "1.5 Configurando UFW..."
    
    if ! command -v ufw &>/dev/null; then
        apt_safe install ufw
    fi
    
    # Configurar regras padrão
    sudo ufw default allow outgoing
    sudo ufw default deny incoming
    
    # Permitir SSH (importante!)
    sudo ufw allow ssh
    sudo ufw allow 22/tcp
    
    # Permitir HTTP e HTTPS
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
    
    # Habilitar UFW (não-interativo)
    echo "y" | sudo ufw enable || true
    
    log_success "1.5 UFW configurado"
    sudo ufw status verbose
    
    log_success "FASE 1 CONCLUÍDA"
}

#===============================================================================
# FASE 2 - DOCKER, SWARM, TRAEFIK, PORTAINER
#===============================================================================
phase2_docker_stack() {
    log_section "FASE 2 - DOCKER, SWARM, TRAEFIK, PORTAINER"
    
    # 2.1 Instalar Docker
    log_progress "2.1 Instalando Docker..."
    
    if command -v docker &>/dev/null && sudo docker info &>/dev/null; then
        local docker_version
        docker_version=$(docker --version 2>/dev/null || echo "unknown")
        log_info "Docker já instalado: $docker_version"
    else
        # Remover versões antigas
        for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do
            sudo apt-get remove -y "$pkg" 2>/dev/null || true
        done
        
        # Adicionar repositório oficial Docker
        sudo install -m 0755 -d /etc/apt/keyrings
        
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg --yes
        sudo chmod a+r /etc/apt/keyrings/docker.gpg
        
        echo \
            "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
            $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
            sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
        
        apt_safe update
        apt_safe install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
        
        log_success "Docker instalado"
    fi
    
    # Adicionar usuário ao grupo docker
    if ! groups "$USER" | grep -q docker; then
        sudo usermod -aG docker "$USER"
        log_info "Usuário $USER adicionado ao grupo docker"
        log_warning "Pode ser necessário relogar para aplicar permissões do grupo docker"
    fi
    
    # Habilitar e iniciar Docker
    sudo systemctl enable docker
    sudo systemctl start docker
    
    # Aguardar Docker estar pronto
    local docker_wait=0
    while ! sudo docker info &>/dev/null && [[ $docker_wait -lt 30 ]]; do
        sleep 2
        ((docker_wait+=2))
    done
    
    # Validar instalação
    if ! sudo docker info &>/dev/null; then
        log_error "Falha na validação do Docker"
        exit 1
    fi
    
    log_success "2.1 Docker operacional"
    
    # 2.2 Inicializar Swarm
    log_progress "2.2 Inicializando Docker Swarm..."
    
    if sudo docker info 2>/dev/null | grep -q "Swarm: active"; then
        log_info "Docker Swarm já está ativo"
    else
        get_local_ip
        
        sudo docker swarm init --advertise-addr "$LOCAL_IP" || {
            log_error "Falha ao inicializar Swarm"
            exit 1
        }
        
        log_success "Docker Swarm inicializado"
    fi
    
    # Criar rede overlay
    if sudo docker network ls | grep -q "$OVERLAY_NETWORK_NAME"; then
        log_info "Rede $OVERLAY_NETWORK_NAME já existe"
    else
        sudo docker network create -d overlay --attachable "$OVERLAY_NETWORK_NAME" || {
            log_error "Falha ao criar rede overlay"
            exit 1
        }
        log_success "Rede overlay $OVERLAY_NETWORK_NAME criada"
    fi
    
    log_success "2.2 Docker Swarm configurado"
    
    # 2.3 Instalar btop
    log_progress "2.3 Instalando btop..."
    
    if command -v btop &>/dev/null; then
        log_info "btop já instalado"
    else
        apt_safe install btop || {
            log_warning "btop não disponível via apt, tentando snap..."
            sudo snap install btop 2>/dev/null || log_warning "Falha ao instalar btop"
        }
    fi
    
    log_success "2.3 btop instalado"
    
    # 2.4 Instalar ctop
    log_progress "2.4 Instalando ctop..."
    
    if command -v ctop &>/dev/null; then
        log_info "ctop já instalado"
    else
        local ctop_url="https://github.com/bcicen/ctop/releases/download/v0.7.7/ctop-0.7.7-linux-arm64"
        if sudo wget -q "$ctop_url" -O /usr/local/bin/ctop; then
            sudo chmod +x /usr/local/bin/ctop
            log_success "ctop instalado"
        else
            log_warning "Falha ao baixar ctop"
        fi
    fi
    
    log_success "2.4 ctop processado"
    
    # 2.5 Deploy Traefik
    log_progress "2.5 Configurando e deployando Traefik..."
    
    # Verificar arquivo YAML
    if [[ ! -f "$HOME/traefik.yml" ]]; then
        log_error "Arquivo traefik.yml não encontrado em $HOME"
        exit 1
    fi
    
    # Substituir variáveis no arquivo
    sed -i "s/\${SSL_EMAIL}/$SSL_EMAIL/g" "$HOME/traefik.yml"
    sed -i "s/\${OVERLAY_NETWORK_NAME}/$OVERLAY_NETWORK_NAME/g" "$HOME/traefik.yml"
    sed -i "s/\${PORTAINER_URL}/$PORTAINER_URL/g" "$HOME/traefik.yml"
    
    # Criar diretório para certificados
    sudo mkdir -p /opt/traefik
    sudo touch /opt/traefik/acme.json
    sudo chmod 600 /opt/traefik/acme.json
    
    # Remover stack existente se houver
    if sudo docker stack ls 2>/dev/null | grep -q "traefik"; then
        log_progress "Removendo stack Traefik existente..."
        sudo docker stack rm traefik
        
        local remove_wait=0
        while sudo docker stack ps traefik &>/dev/null && [[ $remove_wait -lt 60 ]]; do
            sleep 2
            ((remove_wait+=2))
        done
        sleep 5
    fi
    
    # Deploy
    sudo docker stack deploy -c "$HOME/traefik.yml" traefik
    
    # Aguardar convergência
    log_progress "Aguardando Traefik iniciar..."
    local max_wait=120
    local waited=0
    
    while [[ $waited -lt $max_wait ]]; do
        local replicas
        replicas=$(sudo docker service ls --format "{{.Replicas}}" --filter "name=traefik_traefik" 2>/dev/null || echo "0/0")
        
        if [[ "$replicas" == "1/1" ]]; then
            log_success "Traefik iniciado"
            break
        fi
        
        sleep 5
        ((waited+=5))
        log_info "Aguardando Traefik... ($waited/$max_wait segundos) - Status: $replicas"
    done
    
    if [[ $waited -ge $max_wait ]]; then
        log_warning "Timeout aguardando Traefik. Verifique manualmente."
    fi
    
    log_success "2.5 Traefik deployado"
    
    # 2.6 Deploy Portainer + Agent
    log_progress "2.6 Configurando e deployando Portainer + Agent..."
    
    # Verificar arquivo YAML
    if [[ ! -f "$HOME/portainer.yml" ]]; then
        log_error "Arquivo portainer.yml não encontrado em $HOME"
        exit 1
    fi
    
    # Criar Docker Secrets para Portainer
    echo -n "$PORTAINER_ADMIN_USER" | sudo docker secret create portainer_admin_user - 2>/dev/null || \
        log_info "Secret portainer_admin_user já existe"
    
    echo -n "$PORTAINER_ADMIN_PASS" | sudo docker secret create portainer_admin_password - 2>/dev/null || \
        log_info "Secret portainer_admin_password já existe"
    
    # Substituir variáveis no arquivo YAML
    sed -i "s/\${PORTAINER_URL}/$PORTAINER_URL/g" "$HOME/portainer.yml"
    sed -i "s/\${OVERLAY_NETWORK_NAME}/$OVERLAY_NETWORK_NAME/g" "$HOME/portainer.yml"
    
    # Volume para dados do Portainer
    sudo docker volume create portainer_data 2>/dev/null || true
    
    # Remover stack existente se houver
    if sudo docker stack ls 2>/dev/null | grep -q "portainer"; then
        log_progress "Removendo stack Portainer existente..."
        sudo docker stack rm portainer
        
        local remove_wait=0
        while sudo docker stack ps portainer &>/dev/null && [[ $remove_wait -lt 60 ]]; do
            sleep 2
            ((remove_wait+=2))
        done
        sleep 5
    fi
    
    # Deploy da stack
    sudo docker stack deploy -c "$HOME/portainer.yml" portainer
    
    # Aguardar convergência do Portainer Server
    log_progress "Aguardando Portainer Server iniciar..."
    max_wait=180
    waited=0
    
    while [[ $waited -lt $max_wait ]]; do
        local replicas
        replicas=$(sudo docker service ls --format "{{.Replicas}}" --filter "name=portainer_portainer" 2>/dev/null | head -1 || echo "0/0")
        
        if [[ "$replicas" == "1/1" ]]; then
            log_success "Portainer Server iniciado"
            break
        fi
        
        sleep 5
        ((waited+=5))
        log_info "Aguardando Portainer Server... ($waited/$max_wait segundos) - Status: $replicas"
    done
    
    if [[ $waited -ge $max_wait ]]; then
        log_warning "Timeout aguardando Portainer Server. Verifique manualmente."
        sudo docker service logs portainer_portainer --tail 50 2>/dev/null || true
    fi
    
    # Aguardar convergência do Portainer Agent
    log_progress "Aguardando Portainer Agent iniciar..."
    waited=0
    max_wait=120
    
    while [[ $waited -lt $max_wait ]]; do
        local agent_status
        agent_status=$(sudo docker service ls --format "{{.Replicas}}" --filter "name=portainer_portainer_agent" 2>/dev/null || echo "0/0")
        
        # Para modo global, verificar se está rodando em todos os nós
        if [[ "$agent_status" =~ ^[1-9][0-9]*/[1-9][0-9]*$ ]]; then
            local running="${agent_status%/*}"
            local expected="${agent_status#*/}"
            
            if [[ "$running" == "$expected" ]]; then
                log_success "Portainer Agent iniciado em $running nó(s)"
                break
            fi
        fi
        
        sleep 5
        ((waited+=5))
        log_info "Aguardando Portainer Agent... ($waited/$max_wait segundos) - Status: $agent_status"
    done
    
    if [[ $waited -ge $max_wait ]]; then
        log_warning "Timeout aguardando Portainer Agent. Verifique manualmente."
    fi
    
    # Validar conectividade HTTPS (se DNS estiver configurado)
    log_progress "Verificando acesso HTTPS ao Portainer..."
    local https_check_wait=0
    local https_max_wait=60
    
    while [[ $https_check_wait -lt $https_max_wait ]]; do
        local http_code
        http_code=$(curl -sSf -o /dev/null -w "%{http_code}" --connect-timeout 5 "https://$PORTAINER_URL" 2>/dev/null || echo "000")
        
        if [[ "$http_code" =~ ^(200|302|303)$ ]]; then
            log_success "Portainer acessível via HTTPS (HTTP $http_code)"
            break
        fi
        
        sleep 5
        ((https_check_wait+=5))
    done
    
    if [[ $https_check_wait -ge $https_max_wait ]]; then
        log_warning "Não foi possível validar HTTPS. Isso pode ser normal se o DNS ainda não propagou."
        log_info "Acesse https://$PORTAINER_URL após configurar o DNS"
    fi
    
    log_success "2.6 Portainer + Agent deployados"
    
    log_success "FASE 2 CONCLUÍDA"
}

#===============================================================================
# FASE 3 - STACK POSTGRESQL
#===============================================================================
phase3_postgres() {
    log_section "FASE 3 - STACK POSTGRESQL"
    
    log_progress "Configurando PostgreSQL stack..."
    
    # Criar Docker Secret para senha do Postgres
    echo -n "$POSTGRES_PASSWORD" | sudo docker secret create postgres_n8n_password - 2>/dev/null || \
        log_info "Secret postgres_n8n_password já existe"
    
    # Verificar se a rede overlay existe
    if ! sudo docker network ls | grep -q "$OVERLAY_NETWORK_NAME"; then
        log_error "Rede overlay $OVERLAY_NETWORK_NAME não encontrada"
        exit 1
    fi
    
    # Gerar arquivo postgres_n8n.yml
    cat > "$HOME/postgres_n8n.yml" << EOF
version: "3.8"

services:
  postgres_n8n:
    image: postgres:16
    environment:
      POSTGRES_USER: postgres
      POSTGRES_DB: n8n
      POSTGRES_PASSWORD_FILE: /run/secrets/postgres_n8n_password
    secrets:
      - postgres_n8n_password
    volumes:
      - postgres_n8n_data:/var/lib/postgresql/data
    networks:
      - $OVERLAY_NETWORK_NAME
    ports:
      - published: 5432
        target: 5432
        mode: host
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
        window: 120s
      resources:
        limits:
          memory: 512M
        reservations:
          memory: 256M
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d n8n"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 30s

secrets:
  postgres_n8n_password:
    external: true

volumes:
  postgres_n8n_data:
    driver: local

networks:
  $OVERLAY_NETWORK_NAME:
    external: true
EOF

    log_success "Arquivo postgres_n8n.yml gerado em $HOME"
    
    # Remover stack existente
    if sudo docker stack ls 2>/dev/null | grep -q "postgres_n8n"; then
        log_progress "Removendo stack postgres_n8n existente..."
        sudo docker stack rm postgres_n8n
        
        local remove_wait=0
        while sudo docker stack ps postgres_n8n &>/dev/null && [[ $remove_wait -lt 60 ]]; do
            sleep 2
            ((remove_wait+=2))
        done
        sleep 5
    fi
    
    # Deploy
    sudo docker stack deploy -c "$HOME/postgres_n8n.yml" postgres_n8n
    
    # Aguardar convergência (timeout 300s)
    log_progress "Aguardando PostgreSQL iniciar (timeout: 300s)..."
    local max_wait=300
    local waited=0
    
    while [[ $waited -lt $max_wait ]]; do
        local replicas
        replicas=$(sudo docker service ls --format "{{.Replicas}}" --filter "name=postgres_n8n_postgres_n8n" 2>/dev/null || echo "0/0")
        
        if [[ "$replicas" == "1/1" ]]; then
            log_success "PostgreSQL iniciado"
            break
        fi
        
        sleep 10
        ((waited+=10))
        log_info "Aguardando PostgreSQL... ($waited/$max_wait segundos) - Status: $replicas"
    done
    
    if [[ $waited -ge $max_wait ]]; then
        log_error "Timeout aguardando PostgreSQL"
        sudo docker service logs postgres_n8n_postgres_n8n --tail 50 2>/dev/null || true
        exit 1
    fi
    
    # Validar porta 5432
    sleep 10  # Aguardar binding da porta
    if ss -lntup 2>/dev/null | grep -q ":5432"; then
        log_success "PostgreSQL listening na porta 5432"
    else
        log_warning "Porta 5432 pode não estar disponível externamente ainda"
    fi
    
    # Adicionar regra UFW para Postgres
    sudo ufw allow 5432/tcp
    log_info "Regra UFW adicionada para porta 5432"
    
    log_success "FASE 3 CONCLUÍDA - PostgreSQL deployado"
}

#===============================================================================
# FASE 4 - STACK REDIS
#===============================================================================
phase4_redis() {
    log_section "FASE 4 - STACK REDIS"
    
    log_progress "Configurando Redis stack..."
    
    # Verificar se a rede overlay existe
    if ! sudo docker network ls | grep -q "$OVERLAY_NETWORK_NAME"; then
        log_error "Rede overlay $OVERLAY_NETWORK_NAME não encontrada"
        exit 1
    fi
    
    # Gerar arquivo redis_n8n.yml
    cat > "$HOME/redis_n8n.yml" << EOF
version: "3.8"

services:
  redis_n8n:
    image: redis:7
    command: redis-server --appendonly yes
    volumes:
      - redis_n8n_data:/data
    networks:
      - $OVERLAY_NETWORK_NAME
    # Sem ports: expostos - acesso apenas interno via rede overlay
    deploy:
      mode: replicated
      replicas: 1
      placement:
        constraints:
          - node.role == manager
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
        window: 120s
      resources:
        limits:
          memory: 256M
        reservations:
          memory: 128M
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 10s

volumes:
  redis_n8n_data:
    driver: local

networks:
  $OVERLAY_NETWORK_NAME:
    external: true
EOF

    log_success "Arquivo redis_n8n.yml gerado em $HOME"
    
    # Remover stack existente
    if sudo docker stack ls 2>/dev/null | grep -q "redis_n8n"; then
        log_progress "Removendo stack redis_n8n existente..."
        sudo docker stack rm redis_n8n
        
        local remove_wait=0
        while sudo docker stack ps redis_n8n &>/dev/null && [[ $remove_wait -lt 60 ]]; do
            sleep 2
            ((remove_wait+=2))
        done
        sleep 5
    fi
    
    # Deploy
    sudo docker stack deploy -c "$HOME/redis_n8n.yml" redis_n8n
    
    # Aguardar convergência
    log_progress "Aguardando Redis iniciar..."
    local max_wait=120
    local waited=0
    
    while [[ $waited -lt $max_wait ]]; do
        local replicas
        replicas=$(sudo docker service ls --format "{{.Replicas}}" --filter "name=redis_n8n_redis_n8n" 2>/dev/null || echo "0/0")
        
        if [[ "$replicas" == "1/1" ]]; then
            log_success "Redis iniciado"
            break
        fi
        
        sleep 5
        ((waited+=5))
        log_info "Aguardando Redis... ($waited/$max_wait segundos) - Status: $replicas"
    done
    
    if [[ $waited -ge $max_wait ]]; then
        log_warning "Timeout aguardando Redis. Verifique manualmente."
    fi
    
    log_success "FASE 4 CONCLUÍDA - Redis deployado"
}

#===============================================================================
# VALIDAÇÕES FINAIS E DNS
#===============================================================================
validate_dns_connectivity() {
    log_section "VALIDAÇÃO DNS E CONECTIVIDADE"
    
    get_public_ip
    
    log_info "Verificando resolução DNS para $PORTAINER_URL..."
    
    local resolved_ip
    resolved_ip=$(dig +short "$PORTAINER_URL" 2>/dev/null | head -1 || echo "")
    
    if [[ -z "$resolved_ip" ]]; then
        log_warning "DNS para $PORTAINER_URL não resolveu"
        log_warning "Configure o registro DNS apontando para: $PUBLIC_IP"
    elif [[ "$resolved_ip" == "$PUBLIC_IP" ]]; then
        log_success "DNS $PORTAINER_URL -> $PUBLIC_IP (correto)"
    else
        log_warning "DNS $PORTAINER_URL resolve para $resolved_ip"
        log_warning "IP público detectado: $PUBLIC_IP"
        log_warning "Verifique se o DNS está correto"
    fi
}

#===============================================================================
# RESUMO FINAL
#===============================================================================
print_summary() {
    log_section "INSTALAÇÃO CONCLUÍDA"
    
    # Atualizar IP público
    get_public_ip
    
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                        RESUMO DA INSTALAÇÃO                                   ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "📋 SERVIÇOS INSTALADOS:"
    echo "   ├── Docker Engine + Docker Compose"
    echo "   ├── Docker Swarm (nó manager)"
    echo "   ├── Traefik (reverse proxy + SSL)"
    echo "   ├── Portainer CE (gerenciamento)"
    echo "   ├── Portainer Agent (comunicação Swarm)"
    echo "   ├── PostgreSQL 16 (stack: postgres_n8n)"
    echo "   └── Redis 7 (stack: redis_n8n)"
    echo ""
    echo "🌐 ACESSO:"
    echo "   ├── Portainer: https://$PORTAINER_URL"
    echo "   │   ├── Usuário: $PORTAINER_ADMIN_USER"
    echo "   │   └── Senha: [configurada - criar no primeiro acesso]"
    echo "   │"
    echo "   ├── PostgreSQL: $PUBLIC_IP:5432"
    echo "   │   ├── Database: n8n"
    echo "   │   ├── Usuário: postgres"
    echo "   │   └── Senha: [configurada via Docker Secret]"
    echo "   │"
    echo "   └── Redis: redis_n8n_redis_n8n:6379 (apenas interno via rede $OVERLAY_NETWORK_NAME)"
    echo ""
    echo "📁 ARQUIVOS GERADOS:"
    echo "   ├── $ENV_FILE (configurações)"
    echo "   ├── $HOME/traefik.yml"
    echo "   ├── $HOME/portainer.yml"
    echo "   ├── $HOME/postgres_n8n.yml"
    echo "   ├── $HOME/redis_n8n.yml"
    echo "   └── $LOG_FILE (log de instalação)"
    echo ""
    echo "🔑 DOCKER SECRETS CRIADOS:"
    echo "   ├── portainer_admin_user"
    echo "   ├── portainer_admin_password"
    echo "   └── postgres_n8n_password"
    echo ""
    echo "🔧 COMANDOS ÚTEIS:"
    echo "   ├── docker service ls              # Listar serviços"
    echo "   ├── docker stack ls                # Listar stacks"
    echo "   ├── docker service logs <serviço>  # Ver logs"
    echo "   ├── btop                           # Monitor de sistema"
    echo "   └── ctop                           # Monitor de containers"
    echo ""
    
    # Verificar stacks
    echo "📊 STATUS DAS STACKS:"
    sudo docker service ls
    echo ""
    
    if [[ "$REBOOT_RECOMMENDED" == true ]]; then
        echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
        echo "║  ⚠️  REBOOT RECOMENDADO                                                       ║"
        echo "║                                                                               ║"
        echo "║  O kernel foi atualizado durante a instalação.                               ║"
        echo "║  Recomendamos reiniciar o servidor para aplicar as alterações:               ║"
        echo "║                                                                               ║"
        echo "║    sudo reboot                                                               ║"
        echo "║                                                                               ║"
        echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
        echo ""
    fi
    
    echo "⚠️  IMPORTANTE: No primeiro acesso ao Portainer, você precisará criar"
    echo "   a senha do administrador na interface web."
    echo ""
    echo "✅ Instalação concluída com sucesso!"
    echo ""
}

#===============================================================================
# MAIN
#===============================================================================
main() {
    # Parse argumentos
    parse_args "$@"
    
    # Verificar se está dentro do repositório
    check_inside_repo
    
    # Inicializar log
    log_init
    
    # Banner
    print_banner
    
    # Verificações iniciais
    log_section "VERIFICAÇÕES INICIAIS"
    check_root
    check_architecture
    check_ubuntu_version
    check_internet
    get_local_ip
    get_public_ip
    
    # Bootstrap (clone repo) se necessário
    if [[ "$INSIDE_REPO" != true ]] && [[ "$FROM_BOOTSTRAP" != true ]]; then
        bootstrap_clone_repo
        # Se chegou aqui, bootstrap falhou
        exit 1
    fi
    
    # Coletar inputs do usuário
    collect_inputs
    
    # Executar fases
    phase1_prepare_ubuntu
    phase2_docker_stack
    phase3_postgres
    phase4_redis
    
    # Validações finais
    validate_dns_connectivity
    
    # Resumo
    print_summary
}

# Executar
main "$@"
