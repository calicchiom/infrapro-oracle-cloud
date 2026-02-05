#!/usr/bin/env bash
#===============================================================================
# InfraPro Cloud Oracle - criado por Márcio Calicchio
# Version: 1.3.0
# Ambiente: Oracle Cloud ARM64 (aarch64) + Ubuntu Server 24.04
#===============================================================================

set -Eeuo pipefail

#---------------------------------------
# Trap para erros
#---------------------------------------
trap 'echo -e "\n❌ ERRO: Falha na linha $LINENO. Comando: $BASH_COMMAND" >&2; exit 1' ERR

#---------------------------------------
# Variáveis de ambiente para não-interativo
#---------------------------------------
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1
export UCF_FORCE_CONFNEW=1

#---------------------------------------
# Constantes
#---------------------------------------
SCRIPT_VERSION="1.3.0"
SCRIPT_NAME="InfraPro Cloud Oracle"
SCRIPT_AUTHOR="Márcio Calicchio"
REPO_URL="https://github.com/calicchiom/infrapro-oracle-cloud"
REPO_DIR="infrapro-oracle-cloud"
LOG_FILE="$HOME/infrapro-install.log"
ENV_FILE="$HOME/.infrapro.env"
BOOTSTRAP_FLAG="$HOME/.infrapro-bootstrap-done"
DEBUG_MODE=false
CONTINUE_MODE=false

#---------------------------------------
# Cores
#---------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'
BOLD='\033[1m'

#---------------------------------------
# Parse argumentos
#---------------------------------------
for arg in "$@"; do
    case $arg in
        --debug)
            DEBUG_MODE=true
            shift
            ;;
        --continue)
            CONTINUE_MODE=true
            shift
            ;;
    esac
done

if [[ "$DEBUG_MODE" == true ]]; then
    set -x
fi

#---------------------------------------
# Inicializar log
#---------------------------------------
exec > >(tee -a "$LOG_FILE") 2>&1

#---------------------------------------
# Funções de log
#---------------------------------------
timestamp() { date "+%Y-%m-%d %H:%M:%S"; }
log_info() { echo -e "$(timestamp) ${BLUE}📋 [INFO]${NC} $1"; }
log_success() { echo -e "$(timestamp) ${GREEN}✅ [SUCCESS]${NC} $1"; }
log_warning() { echo -e "$(timestamp) ${YELLOW}⚠️  [WARNING]${NC} $1"; }
log_error() { echo -e "$(timestamp) ${RED}❌ [ERROR]${NC} $1"; }
log_progress() { echo -e "$(timestamp) ${MAGENTA}🔄 [PROGRESS]${NC} $1"; }

#---------------------------------------
# Banner
#---------------------------------------
show_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << 'EOF'
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ██╗███╗   ██╗███████╗██████╗  █████╗ ██████╗ ██████╗  ██████╗           ║
║   ██║████╗  ██║██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔═══██╗          ║
║   ██║██╔██╗ ██║█████╗  ██████╔╝███████║██████╔╝██████╔╝██║   ██║          ║
║   ██║██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║██╔═══╝ ██╔══██╗██║   ██║          ║
║   ██║██║ ╚████║██║     ██║  ██║██║  ██║██║     ██║  ██║╚██████╔╝          ║
║   ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝           ║
║                                                                           ║
║                    Cloud Oracle Infrastructure                            ║
║                                                                           ║
║              Criado por: Márcio Calicchio - Versão 1.3.0                  ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

#---------------------------------------
# Verificar se está rodando dentro do repo clonado
#---------------------------------------
is_inside_repo() {
    [[ -f "./traefik.yml" ]] && [[ -f "./portainer.yml" ]] && [[ -f "./install.sh" ]]
}

#---------------------------------------
# Bootstrap: clonar repo e re-executar
#---------------------------------------
bootstrap() {
    if [[ "$CONTINUE_MODE" == true ]]; then
        return 0
    fi

    if is_inside_repo; then
        log_info "Já está dentro do repositório clonado"
        return 0
    fi

    if [[ -f "$BOOTSTRAP_FLAG" ]]; then
        log_error "Bootstrap já foi executado mas não está no diretório correto"
        log_info "Execute: cd ~/$REPO_DIR && ./install.sh --continue"
        exit 1
    fi

    log_progress "Iniciando bootstrap - clonando repositório..."

    # Instalar git se necessário
    if ! command -v git &> /dev/null; then
        log_info "Instalando git..."
        sudo apt-get update -qq
        sudo apt-get install -y -qq git
    fi

    # Remover diretório existente se houver
    if [[ -d "$HOME/$REPO_DIR" ]]; then
        log_warning "Removendo diretório existente: $HOME/$REPO_DIR"
        rm -rf "$HOME/$REPO_DIR"
    fi

    # Clonar repositório
    cd "$HOME"
    git clone "$REPO_URL" "$REPO_DIR"

    # Validar arquivos essenciais
    if [[ ! -f "$HOME/$REPO_DIR/traefik.yml" ]]; then
        log_error "Arquivo traefik.yml não encontrado no repositório!"
        exit 1
    fi

    if [[ ! -f "$HOME/$REPO_DIR/portainer.yml" ]]; then
        log_error "Arquivo portainer.yml não encontrado no repositório!"
        exit 1
    fi

    # Tornar scripts executáveis
    chmod +x "$HOME/$REPO_DIR/install.sh"
    chmod +x "$HOME/$REPO_DIR/uninstall.sh" 2>/dev/null || true

    # Marcar bootstrap como concluído
    touch "$BOOTSTRAP_FLAG"

    log_success "Repositório clonado com sucesso!"
    log_progress "Re-executando instalação do repositório clonado..."

    # Re-executar do diretório clonado
    cd "$HOME/$REPO_DIR"
    
    ARGS="--continue"
    [[ "$DEBUG_MODE" == true ]] && ARGS="$ARGS --debug"
    
    exec ./install.sh $ARGS
}

#---------------------------------------
# Verificar arquitetura ARM64
#---------------------------------------
check_architecture() {
    log_progress "Verificando arquitetura..."
    
    ARCH=$(uname -m)
    if [[ "$ARCH" != "aarch64" ]]; then
        log_warning "Arquitetura detectada: $ARCH (esperado: aarch64)"
        log_warning "O script foi otimizado para ARM64, mas tentará continuar..."
    else
        log_success "Arquitetura ARM64 (aarch64) confirmada"
    fi
}

#---------------------------------------
# Verificar Ubuntu 24.04
#---------------------------------------
check_ubuntu() {
    log_progress "Verificando sistema operacional..."
    
    if [[ ! -f /etc/os-release ]]; then
        log_error "Não foi possível detectar o sistema operacional"
        exit 1
    fi

    source /etc/os-release

    if [[ "$ID" != "ubuntu" ]]; then
        log_error "Este script requer Ubuntu. Detectado: $ID"
        exit 1
    fi

    if [[ "${VERSION_ID}" != "24.04" ]]; then
        log_warning "Ubuntu $VERSION_ID detectado. O script foi testado no 24.04"
    else
        log_success "Ubuntu 24.04 confirmado"
    fi
}

#---------------------------------------
# Verificar sudo
#---------------------------------------
check_sudo() {
    log_progress "Verificando permissões sudo..."
    
    if [[ $EUID -eq 0 ]]; then
        log_error "Não execute como root! Use um usuário normal com sudo."
        exit 1
    fi

    if ! sudo -n true 2>/dev/null; then
        log_info "Solicitando permissão sudo..."
        sudo -v
    fi

    log_success "Permissões sudo confirmadas"
}

#---------------------------------------
# Aguardar liberação do apt/dpkg
#---------------------------------------
wait_for_apt() {
    local max_wait=300
    local waited=0

    while sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
          sudo fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || \
          sudo fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
        
        if [[ $waited -ge $max_wait ]]; then
            log_error "Timeout aguardando liberação do apt/dpkg"
            exit 1
        fi

        log_warning "apt/dpkg em uso, aguardando... ($waited/$max_wait segundos)"
        sleep 5
        ((waited+=5))
    done
}

#---------------------------------------
# Recuperar dpkg se necessário
#---------------------------------------
recover_dpkg() {
    log_progress "Verificando estado do dpkg..."
    
    if sudo dpkg --audit 2>&1 | grep -q .; then
        log_warning "dpkg em estado inconsistente, tentando recuperar..."
        sudo dpkg --configure -a || {
            log_error "Não foi possível recuperar o dpkg automaticamente"
            exit 1
        }
        log_success "dpkg recuperado"
    fi
}

#---------------------------------------
# Função apt-get segura com retry
#---------------------------------------
apt_safe() {
    local cmd="$1"
    shift
    local packages="$*"
    local max_retries=3
    local retry=0

    while [[ $retry -lt $max_retries ]]; do
        wait_for_apt
        recover_dpkg

        if sudo apt-get "$cmd" -y \
            -o Dpkg::Options::="--force-confnew" \
            -o Dpkg::Options::="--force-confdef" \
            -o APT::Get::Assume-Yes="true" \
            -o APT::Get::AllowUnauthenticated="false" \
            $packages; then
            return 0
        fi

        ((retry++))
        log_warning "apt-get $cmd falhou, tentativa $retry de $max_retries..."
        sleep 5
    done

    log_error "apt-get $cmd falhou após $max_retries tentativas"
    return 1
}

#---------------------------------------
# Validação de hostname (DNS)
#---------------------------------------
validate_hostname() {
    local hostname="$1"
    
    # Validar formato
    if [[ ! "$hostname" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        return 1
    fi

    # Verificar DNS (apenas warning se falhar)
    if command -v dig &> /dev/null; then
        if ! dig +short "$hostname" | grep -q .; then
            log_warning "DNS para $hostname não resolveu (pode ser configurado depois)"
        fi
    fi

    return 0
}

#---------------------------------------
# Validação de email
#---------------------------------------
validate_email() {
    local email="$1"
    local regex="^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    
    if [[ ! "$email" =~ $regex ]]; then
        return 1
    fi

    # Verificar domínio
    local domain="${email##*@}"
    if command -v dig &> /dev/null; then
        if ! dig +short MX "$domain" | grep -q .; then
            log_warning "Domínio $domain sem registro MX (pode funcionar mesmo assim)"
        fi
    fi

    return 0
}

#---------------------------------------
# Validação de nome Docker
#---------------------------------------
validate_docker_name() {
    local name="$1"
    
    if [[ ! "$name" =~ ^[a-zA-Z][a-zA-Z0-9_-]*$ ]]; then
        return 1
    fi

    if [[ ${#name} -lt 2 ]] || [[ ${#name} -gt 64 ]]; then
        return 1
    fi

    return 0
}

#---------------------------------------
# Coletar inputs do usuário
#---------------------------------------
collect_inputs() {
    log_progress "Coletando informações necessárias..."
    echo ""

    # URL do Portainer
    while true; do
        read -rp "$(echo -e "${CYAN}Digite o hostname do Portainer (ex: portainer.seudominio.com):${NC} ")" PORTAINER_URL
        PORTAINER_URL=$(echo "$PORTAINER_URL" | sed 's|^https\?://||' | sed 's|/$||')
        
        if validate_hostname "$PORTAINER_URL"; then
            log_success "Hostname válido: $PORTAINER_URL"
            break
        else
            log_error "Hostname inválido. Use formato: portainer.exemplo.com"
        fi
    done

    # Usuário admin Portainer
    while true; do
        read -rp "$(echo -e "${CYAN}Digite o usuário admin do Portainer (min 3 caracteres):${NC} ")" PORTAINER_USER
        
        if [[ "$PORTAINER_USER" =~ ^[a-zA-Z0-9_]{3,}$ ]]; then
            log_success "Usuário válido: $PORTAINER_USER"
            break
        else
            log_error "Usuário deve ter mínimo 3 caracteres (alfanumérico e underscore)"
        fi
    done

    # Senha Portainer
    while true; do
        read -rsp "$(echo -e "${CYAN}Digite a senha do Portainer (min 12 caracteres):${NC} ")" PORTAINER_PASS
        echo ""
        
        if [[ ${#PORTAINER_PASS} -lt 12 ]]; then
            log_error "Senha deve ter mínimo 12 caracteres"
            continue
        fi

        read -rsp "$(echo -e "${CYAN}Confirme a senha do Portainer:${NC} ")" PORTAINER_PASS_CONFIRM
        echo ""

        if [[ "$PORTAINER_PASS" != "$PORTAINER_PASS_CONFIRM" ]]; then
            log_error "Senhas não conferem"
            continue
        fi

        log_success "Senha do Portainer definida"
        break
    done

    # Nome da rede overlay
    while true; do
        read -rp "$(echo -e "${CYAN}Digite o nome da rede overlay (ex: infrapro_network):${NC} ")" OVERLAY_NETWORK
        
        if validate_docker_name "$OVERLAY_NETWORK"; then
            log_success "Nome da rede válido: $OVERLAY_NETWORK"
            break
        else
            log_error "Nome inválido. Use: letras, números, underscore e hífen (2-64 chars)"
        fi
    done

    # Email para SSL
    while true; do
        read -rp "$(echo -e "${CYAN}Digite o email para certificados SSL:${NC} ")" SSL_EMAIL
        
        if validate_email "$SSL_EMAIL"; then
            log_success "Email válido: $SSL_EMAIL"
            break
        else
            log_error "Email inválido"
        fi
    done

    # Senha PostgreSQL
    while true; do
        read -rsp "$(echo -e "${CYAN}Digite a senha do PostgreSQL (min 12 caracteres):${NC} ")" POSTGRES_PASS
        echo ""
        
        if [[ ${#POSTGRES_PASS} -lt 12 ]]; then
            log_error "Senha deve ter mínimo 12 caracteres"
            continue
        fi

        read -rsp "$(echo -e "${CYAN}Confirme a senha do PostgreSQL:${NC} ")" POSTGRES_PASS_CONFIRM
        echo ""

        if [[ "$POSTGRES_PASS" != "$POSTGRES_PASS_CONFIRM" ]]; then
            log_error "Senhas não conferem"
            continue
        fi

        log_success "Senha do PostgreSQL definida"
        break
    done

    # Hostname do Traefik
    while true; do
        read -rp "$(echo -e "${CYAN}Digite o hostname do Traefik Dashboard (ex: traefik.seudominio.com):${NC} ")" TRAEFIK_URL
        TRAEFIK_URL=$(echo "$TRAEFIK_URL" | sed 's|^https\?://||' | sed 's|/$||')
        
        if validate_hostname "$TRAEFIK_URL"; then
            log_success "Hostname válido: $TRAEFIK_URL"
            break
        else
            log_error "Hostname inválido"
        fi
    done

    echo ""
    log_success "Todos os inputs coletados com sucesso!"
}

#---------------------------------------
# Salvar variáveis em .env seguro
#---------------------------------------
save_env() {
    log_progress "Salvando configurações..."

    cat > "$ENV_FILE" << EOF
# InfraPro Cloud Oracle - Configurações
# Gerado em: $(date)
# ATENÇÃO: Este arquivo contém informações sensíveis!

PORTAINER_URL=$PORTAINER_URL
PORTAINER_USER=$PORTAINER_USER
OVERLAY_NETWORK=$OVERLAY_NETWORK
SSL_EMAIL=$SSL_EMAIL
TRAEFIK_URL=$TRAEFIK_URL
EOF

    chmod 600 "$ENV_FILE"
    log_success "Configurações salvas em $ENV_FILE (chmod 600)"
}

#---------------------------------------
# FASE 1.1 - Desabilitar atualizações automáticas
#---------------------------------------
phase1_disable_auto_updates() {
    log_progress "FASE 1.1 - Desabilitando atualizações automáticas..."

    # Configurar apt para não atualizar automaticamente
    sudo tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null << 'EOF'
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
APT::Periodic::Download-Upgradeable-Packages "0";
APT::Periodic::AutocleanInterval "0";
EOF

    # Parar e desabilitar serviços
    local services=("unattended-upgrades" "apt-daily.timer" "apt-daily-upgrade.timer" "apt-daily.service" "apt-daily-upgrade.service")
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            sudo systemctl stop "$service" 2>/dev/null || true
        fi
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            sudo systemctl disable "$service" 2>/dev/null || true
        fi
        sudo systemctl mask "$service" 2>/dev/null || true
    done

    log_success "Atualizações automáticas desabilitadas"
}

#---------------------------------------
# FASE 1.2 - Remover unattended-upgrades
#---------------------------------------
phase1_remove_unattended() {
    log_progress "FASE 1.2 - Removendo unattended-upgrades..."

    if dpkg -l | grep -q unattended-upgrades; then
        apt_safe remove unattended-upgrades
        apt_safe autoremove
        log_success "unattended-upgrades removido"
    else
        log_info "unattended-upgrades já não está instalado"
    fi
}

#---------------------------------------
# FASE 1.3 - Update/Upgrade sistema
#---------------------------------------
phase1_update_system() {
    log_progress "FASE 1.3 - Atualizando sistema..."

    # Configurar needrestart para não perguntar
    if [[ -f /etc/needrestart/needrestart.conf ]]; then
        sudo sed -i "s/#\$nrconf{restart} = 'i';/\$nrconf{restart} = 'a';/" /etc/needrestart/needrestart.conf
    fi

    # Criar configuração para needrestart
    sudo mkdir -p /etc/needrestart/conf.d/
    echo "\$nrconf{restart} = 'a';" | sudo tee /etc/needrestart/conf.d/50local.conf > /dev/null

    apt_safe update
    apt_safe upgrade
    apt_safe install apparmor-utils

    log_success "Sistema atualizado"
}

#---------------------------------------
# FASE 1.4 - Configurar UFW
#---------------------------------------
phase1_configure_ufw() {
    log_progress "FASE 1.4 - Configurando UFW..."

    # Instalar ufw se necessário
    if ! command -v ufw &> /dev/null; then
        apt_safe install ufw
    fi

    # Configurar regras
    sudo ufw --force reset
    sudo ufw default allow incoming
    sudo ufw default allow outgoing
    sudo ufw default allow routed

    # Regras essenciais
    sudo ufw allow 22/tcp comment 'SSH'
    sudo ufw allow 80/tcp comment 'HTTP'
    sudo ufw allow 443/tcp comment 'HTTPS'
    sudo ufw allow 9000/tcp comment 'Portainer'
    sudo ufw allow 9443/tcp comment 'Portainer HTTPS'
    sudo ufw allow 8080/tcp comment 'Traefik Dashboard'
    sudo ufw allow 2377/tcp comment 'Docker Swarm'
    sudo ufw allow 7946/tcp comment 'Docker Swarm'
    sudo ufw allow 7946/udp comment 'Docker Swarm'
    sudo ufw allow 4789/udp comment 'Docker Overlay'
    sudo ufw allow 5432/tcp comment 'PostgreSQL'

    # Habilitar
    sudo ufw --force enable

    log_success "UFW configurado"
    sudo ufw status verbose
}

#---------------------------------------
# Instalar dependências base
#---------------------------------------
install_dependencies() {
    log_progress "Instalando dependências..."

    apt_safe update
    apt_safe install curl wget git ca-certificates gnupg lsb-release apt-transport-https \
        software-properties-common dnsutils jq unzip net-tools htop tree vim nano

    log_success "Dependências instaladas"
}

#---------------------------------------
# FASE 2.1 - Docker
#---------------------------------------
phase2_docker() {
    log_progress "FASE 2.1 - Instalando Docker..."

    if command -v docker &> /dev/null; then
        log_warning "Docker já está instalado"
        docker --version
    else
        # Remover versões antigas
        sudo apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

        # Adicionar repositório Docker
        sudo install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
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
    fi

    # Habilitar e iniciar Docker
    sudo systemctl enable docker
    sudo systemctl start docker

    # Validar
    sudo docker info > /dev/null 2>&1
    log_success "Docker validado e funcionando"
}

#---------------------------------------
# FASE 2.2 - Docker Swarm
#---------------------------------------
phase2_swarm() {
    log_progress "FASE 2.2 - Inicializando Docker Swarm..."

    # Verificar se já está em swarm
    if sudo docker info 2>/dev/null | grep -q "Swarm: active"; then
        log_warning "Docker Swarm já está ativo"
    else
        # Detectar IP
        LOCAL_IP=$(ip route get 1.1.1.1 | grep -oP 'src \K\S+')
        log_info "IP detectado: $LOCAL_IP"

        sudo docker swarm init --advertise-addr "$LOCAL_IP"
        log_success "Docker Swarm inicializado"
    fi

    # Criar rede overlay
    if sudo docker network ls | grep -q "$OVERLAY_NETWORK"; then
        log_warning "Rede $OVERLAY_NETWORK já existe"
    else
        sudo docker network create -d overlay --attachable "$OVERLAY_NETWORK"
        log_success "Rede overlay $OVERLAY_NETWORK criada"
    fi
}

#---------------------------------------
# FASE 2.3 - btop
#---------------------------------------
phase2_btop() {
    log_progress "FASE 2.3 - Instalando btop..."

    if command -v btop &> /dev/null; then
        log_warning "btop já está instalado"
    else
        apt_safe install btop
        log_success "btop instalado"
    fi
}

#---------------------------------------
# FASE 2.4 - ctop
#---------------------------------------
phase2_ctop() {
    log_progress "FASE 2.4 - Instalando ctop..."

    if command -v ctop &> /dev/null; then
        log_warning "ctop já está instalado"
    else
        CTOP_VERSION="0.7.7"
        ARCH=$(uname -m)
        
        if [[ "$ARCH" == "aarch64" ]]; then
            CTOP_ARCH="arm64"
        else
            CTOP_ARCH="amd64"
        fi

        wget -q "https://github.com/bcicen/ctop/releases/download/v${CTOP_VERSION}/ctop-${CTOP_VERSION}-linux-${CTOP_ARCH}" -O /tmp/ctop
        sudo mv /tmp/ctop /usr/local/bin/ctop
        sudo chmod +x /usr/local/bin/ctop
        log_success "ctop instalado"
    fi
}

#---------------------------------------
# Criar Docker Secrets
#---------------------------------------
create_docker_secrets() {
    log_progress "Criando Docker Secrets..."

    # Secret para senha do Portainer
    if sudo docker secret ls | grep -q portainer_admin_password; then
        log_warning "Secret portainer_admin_password já existe, removendo..."
        sudo docker secret rm portainer_admin_password 2>/dev/null || true
    fi
    echo -n "$PORTAINER_PASS" | sudo docker secret create portainer_admin_password -

    # Secret para senha do PostgreSQL
    if sudo docker secret ls | grep -q postgres_password; then
        log_warning "Secret postgres_password já existe, removendo..."
        sudo docker secret rm postgres_password 2>/dev/null || true
    fi
    echo -n "$POSTGRES_PASS" | sudo docker secret create postgres_password -

    log_success "Docker Secrets criados"
}

#---------------------------------------
# Copiar e configurar YAMLs
#---------------------------------------
prepare_yaml_files() {
    log_progress "Preparando arquivos YAML..."

    # Copiar traefik.yml para HOME
    if [[ -f "./traefik.yml" ]]; then
        cp ./traefik.yml "$HOME/traefik.yml"
        # Substituir variáveis
        sed -i "s|\${SSL_EMAIL}|$SSL_EMAIL|g" "$HOME/traefik.yml"
        sed -i "s|\${TRAEFIK_URL}|$TRAEFIK_URL|g" "$HOME/traefik.yml"
        sed -i "s|\${OVERLAY_NETWORK}|$OVERLAY_NETWORK|g" "$HOME/traefik.yml"
        log_success "traefik.yml copiado e configurado"
    else
        log_error "traefik.yml não encontrado!"
        exit 1
    fi

    # Copiar portainer.yml para HOME
    if [[ -f "./portainer.yml" ]]; then
        cp ./portainer.yml "$HOME/portainer.yml"
        # Substituir variáveis
        sed -i "s|\${PORTAINER_URL}|$PORTAINER_URL|g" "$HOME/portainer.yml"
        sed -i "s|\${OVERLAY_NETWORK}|$OVERLAY_NETWORK|g" "$HOME/portainer.yml"
        log_success "portainer.yml copiado e configurado"
    else
        log_error "portainer.yml não encontrado!"
        exit 1
    fi
}

#---------------------------------------
# FASE 2.5 - Traefik
#---------------------------------------
phase2_traefik() {
    log_progress "FASE 2.5 - Instalando Traefik..."

    # Criar diretório para ACME
    sudo mkdir -p /opt/traefik
    sudo touch /opt/traefik/acme.json
    sudo chmod 600 /opt/traefik/acme.json

    # Deploy stack
    if sudo docker stack ls | grep -q "^traefik"; then
        log_warning "Stack traefik já existe, atualizando..."
        sudo docker stack rm traefik
        sleep 10
    fi

    sudo docker stack deploy -c "$HOME/traefik.yml" traefik

    # Aguardar convergência
    log_info "Aguardando Traefik inicializar..."
    local timeout=120
    local elapsed=0

    while [[ $elapsed -lt $timeout ]]; do
        if sudo docker service ls | grep -q "traefik.*1/1"; then
            log_success "Traefik iniciado com sucesso"
            return 0
        fi
        sleep 5
        ((elapsed+=5))
        log_info "Aguardando Traefik... ($elapsed/$timeout segundos)"
    done

    log_warning "Traefik pode ainda estar iniciando, continuando..."
}

#---------------------------------------
# FASE 2.6 - Portainer
#---------------------------------------
phase2_portainer() {
    log_progress "FASE 2.6 - Instalando Portainer..."

    # Criar volume se não existir
    if ! sudo docker volume ls | grep -q portainer_data; then
        sudo docker volume create portainer_data
    fi

    # Deploy stack
    if sudo docker stack ls | grep -q "^portainer"; then
        log_warning "Stack portainer já existe, atualizando..."
        sudo docker stack rm portainer
        sleep 10
    fi

    sudo docker stack deploy -c "$HOME/portainer.yml" portainer

    # Aguardar convergência
    log_info "Aguardando Portainer inicializar..."
    local timeout=120
    local elapsed=0

    while [[ $elapsed -lt $timeout ]]; do
        if sudo docker service ls | grep -q "portainer.*1/1"; then
            log_success "Portainer iniciado com sucesso"
            return 0
        fi
        sleep 5
        ((elapsed+=5))
        log_info "Aguardando Portainer... ($elapsed/$timeout segundos)"
    done

    log_warning "Portainer pode ainda estar iniciando, continuando..."
}

#---------------------------------------
# FASE 3 - PostgreSQL Stack
#---------------------------------------
phase3_postgres() {
    log_progress "FASE 3 - Criando Stack PostgreSQL..."

    # Gerar arquivo YAML
    cat > "$HOME/postgres_n8n.yml" << EOF
version: '3.8'

services:
  postgres_n8n:
    image: postgres:16
    environment:
      POSTGRES_USER: postgres
      POSTGRES_DB: n8n
      POSTGRES_PASSWORD_FILE: /run/secrets/postgres_password
    secrets:
      - postgres_password
    volumes:
      - postgres_n8n_data:/var/lib/postgresql/data
    networks:
      - ${OVERLAY_NETWORK}
    ports:
      - "5432:5432"
    deploy:
      mode: replicated
      replicas: 1
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      resources:
        limits:
          memory: 512M
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d n8n"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 30s

secrets:
  postgres_password:
    external: true

volumes:
  postgres_n8n_data:
    driver: local

networks:
  ${OVERLAY_NETWORK}:
    external: true
EOF

    log_success "Arquivo postgres_n8n.yml gerado em $HOME"

    # Deploy
    if sudo docker stack ls | grep -q "^postgres_n8n"; then
        log_warning "Stack postgres_n8n já existe, atualizando..."
        sudo docker stack rm postgres_n8n
        sleep 15
    fi

    sudo docker stack deploy -c "$HOME/postgres_n8n.yml" postgres_n8n

    # Aguardar convergência
    log_info "Aguardando PostgreSQL inicializar..."
    local timeout=300
    local elapsed=0

    while [[ $elapsed -lt $timeout ]]; do
        if sudo docker service ls | grep -q "postgres_n8n.*1/1"; then
            log_success "PostgreSQL iniciado com sucesso"
            
            # Validar porta
            sleep 5
            if ss -lntup | grep -q ":5432"; then
                log_success "PostgreSQL escutando na porta 5432"
            else
                log_warning "Porta 5432 pode ainda não estar disponível"
            fi
            return 0
        fi
        sleep 10
        ((elapsed+=10))
        log_info "Aguardando PostgreSQL... ($elapsed/$timeout segundos)"
    done

    log_error "Timeout aguardando PostgreSQL"
    return 1
}

#---------------------------------------
# FASE 4 - Redis Stack
#---------------------------------------
phase4_redis() {
    log_progress "FASE 4 - Criando Stack Redis..."

    # Gerar arquivo YAML
    cat > "$HOME/redis_n8n.yml" << EOF
version: '3.8'

services:
  redis_n8n:
    image: redis:7
    command: redis-server --appendonly yes
    volumes:
      - redis_n8n_data:/data
    networks:
      - ${OVERLAY_NETWORK}
    deploy:
      mode: replicated
      replicas: 1
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      resources:
        limits:
          memory: 256M
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s

volumes:
  redis_n8n_data:
    driver: local

networks:
  ${OVERLAY_NETWORK}:
    external: true
EOF

    log_success "Arquivo redis_n8n.yml gerado em $HOME"

    # Deploy
    if sudo docker stack ls | grep -q "^redis_n8n"; then
        log_warning "Stack redis_n8n já existe, atualizando..."
        sudo docker stack rm redis_n8n
        sleep 10
    fi

    sudo docker stack deploy -c "$HOME/redis_n8n.yml" redis_n8n

    # Aguardar convergência
    log_info "Aguardando Redis inicializar..."
    local timeout=120
    local elapsed=0

    while [[ $elapsed -lt $timeout ]]; do
        if sudo docker service ls | grep -q "redis_n8n.*1/1"; then
            log_success "Redis iniciado com sucesso"
            return 0
        fi
        sleep 5
        ((elapsed+=5))
        log_info "Aguardando Redis... ($elapsed/$timeout segundos)"
    done

    log_warning "Redis pode ainda estar iniciando..."
}

#---------------------------------------
# Validação DNS
#---------------------------------------
validate_dns() {
    log_progress "Validando configuração DNS..."

    PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s api.ipify.org 2>/dev/null || echo "N/A")
    
    if [[ "$PUBLIC_IP" != "N/A" ]]; then
        log_info "IP Público: $PUBLIC_IP"

        # Verificar Portainer
        if command -v dig &> /dev/null; then
            PORTAINER_DNS=$(dig +short "$PORTAINER_URL" | head -1)
            if [[ -n "$PORTAINER_DNS" ]]; then
                if [[ "$PORTAINER_DNS" == "$PUBLIC_IP" ]]; then
                    log_success "DNS de $PORTAINER_URL aponta corretamente para $PUBLIC_IP"
                else
                    log_warning "DNS de $PORTAINER_URL aponta para $PORTAINER_DNS (esperado: $PUBLIC_IP)"
                fi
            else
                log_warning "DNS de $PORTAINER_URL não configurado"
            fi

            TRAEFIK_DNS=$(dig +short "$TRAEFIK_URL" | head -1)
            if [[ -n "$TRAEFIK_DNS" ]]; then
                if [[ "$TRAEFIK_DNS" == "$PUBLIC_IP" ]]; then
                    log_success "DNS de $TRAEFIK_URL aponta corretamente para $PUBLIC_IP"
                else
                    log_warning "DNS de $TRAEFIK_URL aponta para $TRAEFIK_DNS (esperado: $PUBLIC_IP)"
                fi
            else
                log_warning "DNS de $TRAEFIK_URL não configurado"
            fi
        fi
    fi
}

#---------------------------------------
# Verificar necessidade de reboot
#---------------------------------------
check_reboot_required() {
    if [[ -f /var/run/reboot-required ]]; then
        log_warning "⚠️  REBOOT RECOMENDADO: Uma atualização de kernel foi instalada"
        log_info "Execute 'sudo reboot' quando conveniente"
        return 1
    fi
    return 0
}

#---------------------------------------
# Resumo final
#---------------------------------------
show_summary() {
    PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s api.ipify.org 2>/dev/null || hostname -I | awk '{print $1}')

    echo ""
    echo -e "${GREEN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                           ║"
    echo "║              ✅ INSTALAÇÃO CONCLUÍDA COM SUCESSO!                         ║"
    echo "║                                                                           ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    echo -e "${CYAN}${BOLD}📋 SERVIÇOS INSTALADOS:${NC}"
    echo ""
    
    echo -e "${YELLOW}Portainer:${NC}"
    echo -e "   URL: ${BOLD}https://${PORTAINER_URL}${NC}"
    echo -e "   Usuário: ${BOLD}${PORTAINER_USER}${NC}"
    echo -e "   (Configure a senha no primeiro acesso ou via API)"
    echo ""

    echo -e "${YELLOW}Traefik Dashboard:${NC}"
    echo -e "   URL: ${BOLD}https://${TRAEFIK_URL}${NC}"
    echo ""

    echo -e "${YELLOW}PostgreSQL:${NC}"
    echo -e "   Host externo: ${BOLD}${PUBLIC_IP}:5432${NC}"
    echo -e "   Host interno (Docker): ${BOLD}postgres_n8n_postgres_n8n:5432${NC}"
    echo -e "   Database: ${BOLD}n8n${NC}"
    echo -e "   Usuário: ${BOLD}postgres${NC}"
    echo ""

    echo -e "${YELLOW}Redis:${NC}"
    echo -e "   Host interno (Docker): ${BOLD}redis_n8n_redis_n8n:6379${NC}"
    echo -e "   (Não exposto externamente - acesso apenas via rede overlay)"
    echo ""

    echo -e "${CYAN}${BOLD}📁 ARQUIVOS GERADOS:${NC}"
    echo -e "   Configurações: ${BOLD}${ENV_FILE}${NC}"
    echo -e "   Traefik Stack: ${BOLD}$HOME/traefik.yml${NC}"
    echo -e "   Portainer Stack: ${BOLD}$HOME/portainer.yml${NC}"
    echo -e "   PostgreSQL Stack: ${BOLD}$HOME/postgres_n8n.yml${NC}"
    echo -e "   Redis Stack: ${BOLD}$HOME/redis_n8n.yml${NC}"
    echo -e "   Log: ${BOLD}${LOG_FILE}${NC}"
    echo ""

    echo -e "${CYAN}${BOLD}🔧 COMANDOS ÚTEIS:${NC}"
    echo -e "   Ver stacks: ${BOLD}docker stack ls${NC}"
    echo -e "   Ver serviços: ${BOLD}docker service ls${NC}"
    echo -e "   Logs Traefik: ${BOLD}docker service logs traefik_traefik${NC}"
    echo -e "   Logs Portainer: ${BOLD}docker service logs portainer_portainer${NC}"
    echo -e "   Logs PostgreSQL: ${BOLD}docker service logs postgres_n8n_postgres_n8n${NC}"
    echo -e "   Logs Redis: ${BOLD}docker service logs redis_n8n_redis_n8n${NC}"
    echo -e "   Monitor: ${BOLD}ctop${NC} ou ${BOLD}btop${NC}"
    echo ""

    echo -e "${CYAN}${BOLD}🌐 REDE OVERLAY:${NC}"
    echo -e "   Nome: ${BOLD}${OVERLAY_NETWORK}${NC}"
    echo ""

    # Verificar reboot
    check_reboot_required || true

    echo -e "${GREEN}Documentação: https://github.com/calicchiom/infrapro-oracle-cloud${NC}"
    echo ""
}

#---------------------------------------
# Main
#---------------------------------------
main() {
    show_banner

    # Bootstrap (clonar repo se necessário)
    bootstrap

    # Verificações iniciais
    check_architecture
    check_ubuntu
    check_sudo

    # Coletar inputs
    collect_inputs

    # Salvar configurações
    save_env

    echo ""
    log_info "Iniciando instalação em 5 segundos... (Ctrl+C para cancelar)"
    sleep 5

    # FASE 1 - Preparação Ubuntu
    phase1_disable_auto_updates
    phase1_remove_unattended
    phase1_update_system
    phase1_configure_ufw

    # Instalar dependências
    install_dependencies

    # FASE 2 - Docker + Swarm + Traefik + Portainer
    phase2_docker
    phase2_swarm
    phase2_btop
    phase2_ctop

    # Criar Docker Secrets
    create_docker_secrets

    # Preparar YAMLs
    prepare_yaml_files

    # Deploy Traefik e Portainer
    phase2_traefik
    phase2_portainer

    # FASE 3 - PostgreSQL
    phase3_postgres

    # FASE 4 - Redis
    phase4_redis

    # Validação DNS
    validate_dns

    # Resumo final
    show_summary

    # Limpar flag de bootstrap
    rm -f "$BOOTSTRAP_FLAG"

    log_success "Instalação finalizada!"
}

# Executar
main "$@"
