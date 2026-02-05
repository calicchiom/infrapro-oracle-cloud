#!/usr/bin/env bash
#===============================================================================
# InfraPro Cloud Oracle - Desinstalação Completa
# Versão: 1.0.0
# Autor: Márcio Calicchio
#
# USO:
#   ./uninstall.sh [--debug] [--force]
#
# ATENÇÃO: Este script remove TODOS os componentes instalados pelo InfraPro
#===============================================================================

set -Eeuo pipefail

#===============================================================================
# CONFIGURAÇÕES GLOBAIS
#===============================================================================
export DEBIAN_FRONTEND=noninteractive

readonly VERSION="1.0.0"
readonly SCRIPT_NAME="InfraPro Cloud Oracle - Uninstaller"
readonly LOG_FILE="$HOME/infrapro-uninstall.log"
readonly ENV_FILE="$HOME/.infrapro.env"

# Flags
DEBUG_MODE=false
FORCE_MODE=false

#===============================================================================
# TRAP
#===============================================================================
trap 'echo -e "\n❌ ERRO: Falha na linha $LINENO. Comando: $BASH_COMMAND" >&2' ERR

#===============================================================================
# FUNÇÕES DE LOG
#===============================================================================
log_init() {
    mkdir -p "$(dirname "$LOG_FILE")"
    exec > >(tee -a "$LOG_FILE") 2>&1
    echo ""
    echo "==============================================================================="
    echo "Log de desinstalação iniciado em: $(date '+%Y-%m-%d %H:%M:%S')"
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
    echo "║                          UNINSTALLER - v$VERSION                               ║"
    echo "║                                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
}

#===============================================================================
# PARSE ARGS
#===============================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --debug)
                DEBUG_MODE=true
                shift
                ;;
            --force)
                FORCE_MODE=true
                shift
                ;;
            --help|-h)
                echo "Uso: $0 [--debug] [--force]"
                echo ""
                echo "Opções:"
                echo "  --debug    Ativa modo debug (set -x)"
                echo "  --force    Remove tudo sem pedir confirmação"
                echo "  --help     Mostra esta ajuda"
                exit 0
                ;;
            *)
                log_warning "Argumento desconhecido: $1"
                shift
                ;;
        esac
    done
    
    if [[ "$DEBUG_MODE" == true ]]; then
        set -x
    fi
}

#===============================================================================
# CONFIRMAÇÕES
#===============================================================================
confirm_action() {
    local message="$1"
    local response
    
    if [[ "$FORCE_MODE" == true ]]; then
        return 0
    fi
    
    echo ""
    echo "⚠️  $message"
    read -rp "   Digite 'sim' para confirmar: " response
    
    if [[ "$response" != "sim" ]]; then
        return 1
    fi
    
    return 0
}

double_confirm() {
    local message="$1"
    
    if [[ "$FORCE_MODE" == true ]]; then
        return 0
    fi
    
    echo ""
    echo "🚨 ATENÇÃO: $message"
    echo ""
    read -rp "   Primeira confirmação - Digite 'REMOVER': " response1
    
    if [[ "$response1" != "REMOVER" ]]; then
        log_info "Operação cancelada pelo usuário"
        return 1
    fi
    
    read -rp "   Segunda confirmação - Digite 'CONFIRMO': " response2
    
    if [[ "$response2" != "CONFIRMO" ]]; then
        log_info "Operação cancelada pelo usuário"
        return 1
    fi
    
    return 0
}

#===============================================================================
# VERIFICAR SE DOCKER ESTÁ DISPONÍVEL
#===============================================================================
check_docker() {
    if ! command -v docker &>/dev/null; then
        log_warning "Docker não está instalado"
        return 1
    fi
    
    if ! sudo docker info &>/dev/null; then
        log_warning "Docker não está acessível"
        return 1
    fi
    
    return 0
}

#===============================================================================
# REMOÇÃO DAS STACKS
#===============================================================================
remove_stacks() {
    log_section "REMOVENDO STACKS DOCKER"
    
    if ! check_docker; then
        log_info "Docker não disponível, pulando remoção de stacks"
        return
    fi
    
    local stacks=("redis_n8n" "postgres_n8n" "portainer" "traefik")
    
    for stack in "${stacks[@]}"; do
        if sudo docker stack ls 2>/dev/null | grep -q "$stack"; then
            log_progress "Removendo stack: $stack"
            sudo docker stack rm "$stack" 2>/dev/null || true
            log_success "Stack $stack removida"
        else
            log_info "Stack $stack não encontrada"
        fi
    done
    
    # Aguardar remoção completa
    log_progress "Aguardando remoção completa das stacks..."
    local wait_time=0
    local max_wait=60
    
    while [[ $wait_time -lt $max_wait ]]; do
        local remaining=0
        for stack in "${stacks[@]}"; do
            if sudo docker stack ps "$stack" &>/dev/null 2>&1; then
                ((remaining++))
            fi
        done
        
        if [[ $remaining -eq 0 ]]; then
            break
        fi
        
        sleep 5
        ((wait_time+=5))
        log_info "Aguardando... ($wait_time/$max_wait segundos)"
    done
    
    sleep 5
    
    # Remover rede interna do Portainer Agent (se existir)
    log_progress "Verificando redes internas..."
    local internal_networks=("portainer_portainer_agent_network" "portainer_agent_network")
    
    for net in "${internal_networks[@]}"; do
        if sudo docker network ls 2>/dev/null | grep -q "$net"; then
            log_progress "Removendo rede $net..."
            sudo docker network rm "$net" 2>/dev/null || log_warning "Não foi possível remover $net"
        fi
    done
    
    log_success "Stacks removidas"
}

#===============================================================================
# REMOÇÃO DOS SECRETS
#===============================================================================
remove_secrets() {
    log_section "REMOVENDO DOCKER SECRETS"
    
    if ! check_docker; then
        log_info "Docker não disponível, pulando remoção de secrets"
        return
    fi
    
    if ! confirm_action "Deseja remover os Docker Secrets?"; then
        log_info "Secrets mantidos"
        return
    fi
    
    local secrets=("portainer_admin_user" "portainer_admin_password" "postgres_n8n_password")
    
    for secret in "${secrets[@]}"; do
        if sudo docker secret ls 2>/dev/null | grep -q "$secret"; then
            log_progress "Removendo secret: $secret"
            sudo docker secret rm "$secret" 2>/dev/null || log_warning "Não foi possível remover $secret"
            log_success "Secret $secret removido"
        else
            log_info "Secret $secret não encontrado"
        fi
    done
    
    log_success "Secrets processados"
}

#===============================================================================
# REMOÇÃO DOS VOLUMES (COM CONFIRMAÇÃO DUPLA)
#===============================================================================
remove_volumes() {
    log_section "REMOÇÃO DE VOLUMES (DADOS PERSISTENTES)"
    
    if ! check_docker; then
        log_info "Docker não disponível, pulando remoção de volumes"
        return
    fi
    
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
    echo "║  ⚠️  ATENÇÃO: ESTA AÇÃO É IRREVERSÍVEL!                                       ║"
    echo "║                                                                               ║"
    echo "║  A remoção dos volumes apagará PERMANENTEMENTE:                              ║"
    echo "║    - Todos os dados do PostgreSQL (banco n8n)                                ║"
    echo "║    - Todos os dados do Redis                                                  ║"
    echo "║    - Configurações do Portainer                                               ║"
    echo "║    - Certificados SSL do Traefik                                              ║"
    echo "║                                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
    
    if ! double_confirm "Você está prestes a APAGAR TODOS OS DADOS dos volumes!"; then
        log_info "Volumes mantidos"
        return
    fi
    
    # Lista de volumes conhecidos (podem ter prefixo de stack)
    local volume_patterns=("postgres_n8n" "redis_n8n" "portainer_data" "portainer_portainer")
    
    for pattern in "${volume_patterns[@]}"; do
        # Procurar volumes que correspondem ao padrão
        local found_volumes
        found_volumes=$(sudo docker volume ls -q 2>/dev/null | grep "$pattern" || echo "")
        
        if [[ -n "$found_volumes" ]]; then
            for v in $found_volumes; do
                log_progress "Removendo volume: $v"
                sudo docker volume rm "$v" 2>/dev/null || {
                    log_warning "Falha ao remover volume $v (pode estar em uso)"
                }
            done
        fi
    done
    
    # Remover diretório Traefik
    if [[ -d /opt/traefik ]]; then
        log_progress "Removendo /opt/traefik..."
        sudo rm -rf /opt/traefik
        log_success "/opt/traefik removido"
    fi
    
    log_success "Volumes processados"
}

#===============================================================================
# REMOÇÃO DA REDE OVERLAY
#===============================================================================
remove_network() {
    log_section "REMOVENDO REDE OVERLAY"
    
    if ! check_docker; then
        log_info "Docker não disponível, pulando remoção de rede"
        return
    fi
    
    # Tentar carregar nome da rede do arquivo de configuração
    local network_name=""
    if [[ -f "$ENV_FILE" ]]; then
        network_name=$(grep "OVERLAY_NETWORK_NAME=" "$ENV_FILE" 2>/dev/null | cut -d= -f2 || echo "")
    fi
    
    if [[ -z "$network_name" ]]; then
        log_warning "Nome da rede não encontrado no arquivo de configuração"
        read -rp "Digite o nome da rede overlay para remover (ou Enter para pular): " network_name
    fi
    
    if [[ -n "$network_name" ]]; then
        if sudo docker network ls | grep -q "$network_name"; then
            log_progress "Removendo rede: $network_name"
            sudo docker network rm "$network_name" 2>/dev/null || {
                log_warning "Falha ao remover rede (pode haver containers conectados)"
            }
            log_success "Rede $network_name removida"
        else
            log_info "Rede $network_name não encontrada"
        fi
    fi
    
    log_success "Rede processada"
}

#===============================================================================
# REMOÇÃO DOS ARQUIVOS YAML E CONFIGURAÇÃO
#===============================================================================
remove_config_files() {
    log_section "REMOVENDO ARQUIVOS DE CONFIGURAÇÃO"
    
    local files=(
        "$HOME/traefik.yml"
        "$HOME/portainer.yml"
        "$HOME/postgres_n8n.yml"
        "$HOME/redis_n8n.yml"
        "$ENV_FILE"
    )
    
    for file in "${files[@]}"; do
        if [[ -f "$file" ]]; then
            log_progress "Removendo: $file"
            rm -f "$file"
            log_success "Removido: $file"
        else
            log_info "Arquivo não encontrado: $file"
        fi
    done
    
    log_success "Arquivos de configuração removidos"
}

#===============================================================================
# REVERTER UFW
#===============================================================================
revert_ufw() {
    log_section "REVERTENDO REGRAS UFW"
    
    if ! command -v ufw &>/dev/null; then
        log_info "UFW não instalado"
        return
    fi
    
    if ! confirm_action "Deseja remover a regra UFW para porta 5432 (PostgreSQL)?"; then
        log_info "Regras UFW mantidas"
        return
    fi
    
    if sudo ufw status | grep -q "5432"; then
        log_progress "Removendo regra UFW para porta 5432..."
        sudo ufw delete allow 5432/tcp 2>/dev/null || true
        log_success "Regra UFW removida"
    else
        log_info "Regra UFW para 5432 não encontrada"
    fi
}

#===============================================================================
# DEIXAR SWARM (OPCIONAL)
#===============================================================================
leave_swarm() {
    log_section "DOCKER SWARM"
    
    if ! check_docker; then
        log_info "Docker não disponível, pulando configuração do Swarm"
        return
    fi
    
    if ! sudo docker info 2>/dev/null | grep -q "Swarm: active"; then
        log_info "Docker Swarm não está ativo"
        return
    fi
    
    if ! confirm_action "Deseja sair do Docker Swarm?"; then
        log_info "Docker Swarm mantido"
        return
    fi
    
    log_progress "Saindo do Docker Swarm..."
    sudo docker swarm leave --force 2>/dev/null || {
        log_warning "Falha ao sair do Swarm"
    }
    
    log_success "Docker Swarm desativado"
}

#===============================================================================
# DESINSTALAR DOCKER (OPCIONAL)
#===============================================================================
uninstall_docker() {
    log_section "DOCKER ENGINE"
    
    if ! command -v docker &>/dev/null; then
        log_info "Docker não está instalado"
        return
    fi
    
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
    echo "║  ⚠️  ATENÇÃO: Desinstalar o Docker removerá TODOS os containers e imagens!    ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
    
    if ! double_confirm "Deseja DESINSTALAR COMPLETAMENTE o Docker?"; then
        log_info "Docker mantido"
        return
    fi
    
    log_progress "Parando Docker..."
    sudo systemctl stop docker 2>/dev/null || true
    sudo systemctl stop docker.socket 2>/dev/null || true
    sudo systemctl stop containerd 2>/dev/null || true
    
    log_progress "Desinstalando pacotes Docker..."
    sudo apt-get remove -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin 2>/dev/null || true
    sudo apt-get autoremove -y 2>/dev/null || true
    
    log_progress "Removendo dados Docker..."
    sudo rm -rf /var/lib/docker
    sudo rm -rf /var/lib/containerd
    sudo rm -rf /etc/docker
    sudo rm -f /etc/apt/sources.list.d/docker.list
    sudo rm -f /etc/apt/keyrings/docker.gpg
    
    # Remover grupo docker do usuário
    sudo gpasswd -d "$USER" docker 2>/dev/null || true
    
    log_success "Docker desinstalado"
}

#===============================================================================
# REMOVER FERRAMENTAS AUXILIARES
#===============================================================================
remove_tools() {
    log_section "FERRAMENTAS AUXILIARES"
    
    if ! confirm_action "Deseja remover ctop?"; then
        log_info "Ferramentas mantidas"
        return
    fi
    
    if [[ -f /usr/local/bin/ctop ]]; then
        log_progress "Removendo ctop..."
        sudo rm -f /usr/local/bin/ctop
        log_success "ctop removido"
    fi
    
    log_success "Ferramentas processadas"
}

#===============================================================================
# REMOVER REPOSITÓRIO CLONADO
#===============================================================================
remove_repo() {
    log_section "REMOVENDO REPOSITÓRIO"
    
    local repo_dir="$HOME/infrapro-oracle-cloud"
    
    if [[ -d "$repo_dir" ]]; then
        if confirm_action "Deseja remover o diretório $repo_dir?"; then
            rm -rf "$repo_dir"
            log_success "Repositório removido"
        else
            log_info "Repositório mantido"
        fi
    else
        log_info "Diretório do repositório não encontrado"
    fi
}

#===============================================================================
# REMOVER CONFIGURAÇÕES APT CUSTOMIZADAS
#===============================================================================
remove_apt_configs() {
    log_section "CONFIGURAÇÕES APT"
    
    if ! confirm_action "Deseja remover as configurações APT customizadas?"; then
        log_info "Configurações APT mantidas"
        return
    fi
    
    if [[ -f /etc/apt/apt.conf.d/99-infrapro-nointeractive ]]; then
        log_progress "Removendo /etc/apt/apt.conf.d/99-infrapro-nointeractive..."
        sudo rm -f /etc/apt/apt.conf.d/99-infrapro-nointeractive
        log_success "Configuração removida"
    fi
    
    # Desmascarar serviços de atualização
    if confirm_action "Deseja reativar as atualizações automáticas do sistema?"; then
        sudo systemctl unmask apt-daily.service apt-daily-upgrade.service 2>/dev/null || true
        sudo systemctl enable apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
        log_success "Atualizações automáticas reativadas"
    fi
    
    log_success "Configurações APT processadas"
}

#===============================================================================
# RESUMO
#===============================================================================
print_summary() {
    log_section "DESINSTALAÇÃO CONCLUÍDA"
    
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                     RESUMO DA DESINSTALAÇÃO                                   ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "📋 Ações executadas:"
    echo "   ├── Stacks Docker removidas (traefik, portainer, postgres_n8n, redis_n8n)"
    echo "   ├── Rede interna do Portainer Agent removida"
    echo "   ├── Secrets processados"
    echo "   ├── Volumes processados (conforme confirmação)"
    echo "   ├── Rede overlay processada"
    echo "   ├── Arquivos YAML removidos"
    echo "   ├── Regras UFW revertidas (conforme confirmação)"
    echo "   ├── Docker Swarm processado"
    echo "   └── Docker Engine processado"
    echo ""
    echo "📁 Log salvo em: $LOG_FILE"
    echo ""
    
    if check_docker 2>/dev/null; then
        echo "📊 STATUS ATUAL DO DOCKER:"
        sudo docker service ls 2>/dev/null || echo "   Nenhum serviço ativo"
        echo ""
        sudo docker stack ls 2>/dev/null || echo "   Nenhuma stack ativa"
        echo ""
    fi
    
    echo "✅ Desinstalação concluída!"
    echo ""
}

#===============================================================================
# MAIN
#===============================================================================
main() {
    parse_args "$@"
    
    # Inicializar log
    log_init
    
    print_banner
    
    log_section "INICIANDO DESINSTALAÇÃO"
    
    echo ""
    echo "Este script irá remover os seguintes componentes:"
    echo "  - Stacks: traefik, portainer, postgres_n8n, redis_n8n"
    echo "  - Portainer Agent e sua rede interna"
    echo "  - Docker Secrets relacionados"
    echo "  - Volumes de dados (com confirmação dupla)"
    echo "  - Rede overlay"
    echo "  - Arquivos YAML gerados"
    echo "  - Regras UFW (porta 5432)"
    echo "  - Docker Swarm (opcional)"
    echo "  - Docker Engine (opcional)"
    echo ""
    
    if ! confirm_action "Deseja continuar com a desinstalação?"; then
        log_info "Desinstalação cancelada pelo usuário"
        exit 0
    fi
    
    # Executar remoções na ordem correta
    remove_stacks
    remove_secrets
    remove_volumes
    remove_network
    remove_config_files
    revert_ufw
    leave_swarm
    uninstall_docker
    remove_tools
    remove_repo
    remove_apt_configs
    
    print_summary
}

main "$@"
