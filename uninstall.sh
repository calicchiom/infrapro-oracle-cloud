#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo -e "\n❌ ERRO: Falha na linha $LINENO. Comando: $BASH_COMMAND" >&2' ERR

TITLE="InfraPro Cloud Oracle - criado por Márcio Calicchio - v1.1.0"

LOG_FILE="$HOME/infrapro-install.log"
ENV_FILE="$HOME/.infrapro.env"
STATE_FILE="$HOME/.infrapro.state.json"

if command -v tput >/dev/null 2>&1 && [ -t 1 ]; then
  RED="$(tput setaf 1)"; GREEN="$(tput setaf 2)"; YELLOW="$(tput setaf 3)"; BLUE="$(tput setaf 4)"; WHITE="$(tput setaf 7)"; BOLD="$(tput bold)"; RESET="$(tput sgr0)"
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; WHITE=""; BOLD=""; RESET=""
fi
ts() { date '+%Y-%m-%d %H:%M:%S%z'; }
msg() { local c="$1"; shift; local i="$1"; shift; echo -e "[$(ts)] ${c}${i} $*${RESET}"; }
ok()   { msg "$GREEN" "✅" "$*"; }
warn() { msg "$YELLOW" "⚠️" "$*"; }
err()  { msg "$RED" "❌" "$*"; }
step() { msg "$BLUE" "🔄" "$*"; }
info() { msg "$WHITE" "📋" "$*"; }

need_sudo() { command -v sudo >/dev/null 2>&1 || { err "sudo não encontrado."; exit 1; }; sudo true; }

confirm_double() {
  echo -e "${BOLD}${WHITE}${TITLE}${RESET}"
  warn "Este processo irá remover: stacks (traefik/portainer), swarm, Docker e arquivos locais."
  read -r -p "Digite 'SIM' para continuar: " c1
  [[ "$c1" == "SIM" ]] || { info "Cancelado."; exit 0; }
  read -r -p "Confirma novamente digitando 'REMOVER': " c2
  [[ "$c2" == "REMOVER" ]] || { info "Cancelado."; exit 0; }
}

load_env_if_exists() {
  if [[ -f "$ENV_FILE" ]]; then
    # shellcheck disable=SC1090
    source "$ENV_FILE" || true
  fi
}

remove_stacks() {
  if command -v docker >/dev/null 2>&1; then
    step "Removendo stacks (se existirem)"
    sudo docker stack rm traefik 2>/dev/null || true
    sudo docker stack rm portainer 2>/dev/null || true
    step "Aguardando remoção de serviços (timeout 180s)"
    timeout 180 bash -c 'while sudo docker service ls --format "{{.Name}}" | grep -Eq "^(traefik_|portainer_)"; do sleep 5; done' || true
    ok "Stacks removidas (ou já não existiam)."
  else
    warn "Docker não encontrado; pulando remoção de stacks."
  fi
}

optional_remove_volumes() {
  if ! command -v docker >/dev/null 2>&1; then return 0; fi

  echo
  read -r -p "Remover volumes de dados? (portainer_data e traefik_letsencrypt) (s/N): " ans
  ans="${ans,,}"
  if [[ "$ans" == "s" || "$ans" == "sim" ]]; then
    step "Removendo volumes (se existirem)"
    # volumes com prefixo de stack (mais comuns)
    sudo docker volume rm portainer_portainer_data 2>/dev/null || true
    sudo docker volume rm traefik_traefik_letsencrypt 2>/dev/null || true
    # volumes sem prefixo (fallback)
    sudo docker volume rm portainer_data 2>/dev/null || true
    sudo docker volume rm traefik_letsencrypt 2>/dev/null || true
    ok "Volumes removidos (quando existentes)."
  else
    info "Mantendo volumes."
  fi
}

leave_swarm_and_remove_network() {
  if command -v docker >/dev/null 2>&1; then
    step "Saindo do swarm"
    sudo docker swarm leave --force 2>/dev/null || true
    ok "Swarm removido (ou já estava inativo)."

    if [[ -n "${NOME_REDE_USUARIO:-}" ]]; then
      step "Removendo rede Docker: $NOME_REDE_USUARIO (se existir)"
      sudo docker network rm "$NOME_REDE_USUARIO" 2>/dev/null || true
    fi
  fi
}

remove_docker_completely() {
  step "Removendo Docker"
  sudo systemctl stop docker 2>/dev/null || true
  sudo systemctl stop containerd 2>/dev/null || true

  sudo apt purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras 2>/dev/null || true
  sudo apt autoremove -y || true

  sudo rm -rf /var/lib/docker /var/lib/containerd /etc/docker /etc/containerd 2>/dev/null || true
  ok "Docker removido."
}

restore_auto_upgrades_if_backup_exists() {
  step "Restaurando /etc/apt/apt.conf.d/20auto-upgrades (se houver backup infrapro)"
  local file="/etc/apt/apt.conf.d/20auto-upgrades"
  local last_backup
  last_backup="$(ls -1t /etc/apt/apt.conf.d/20auto-upgrades.bak.infrapro.* 2>/dev/null | head -n1 || true)"
  if [[ -n "$last_backup" ]]; then
    sudo cp -a "$last_backup" "$file"
    ok "Restaurado a partir de: $last_backup"
  else
    info "Nenhum backup infrapro encontrado; mantendo arquivo atual."
  fi
}

remove_local_files() {
  step "Removendo arquivos locais"
  rm -f "$ENV_FILE" "$STATE_FILE" \
    "$HOME/traefik.yaml" "$HOME/portainer.yaml" \
    "$HOME/traefik.yaml.tpl" "$HOME/portainer.yaml.tpl" 2>/dev/null || true
  ok "Arquivos locais removidos."
}

main() {
  exec > >(tee -a "$LOG_FILE") 2>&1

  [[ "$EUID" -ne 0 ]] || { err "Não execute como root direto."; exit 1; }
  need_sudo
  confirm_double
  load_env_if_exists

  remove_stacks
  optional_remove_volumes
  leave_swarm_and_remove_network
  remove_docker_completely
  restore_auto_upgrades_if_backup_exists
  remove_local_files

  ok "Desinstalação concluída."
  info "UFW não é alterado aqui (mantido conforme padrão do projeto)."
}

main "$@"
