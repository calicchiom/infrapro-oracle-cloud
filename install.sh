#!/usr/bin/env bash
set -Eeuo pipefail

# ===== Non-interactive / no UI =====
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE=a
export NEEDRESTART_SUSPEND=1
export UCF_FORCE_CONFFOLD=1

trap 'echo -e "\n❌ ERRO: Falha na linha $LINENO. Comando: $BASH_COMMAND" >&2' ERR

TITLE="InfraPro Cloud Oracle - criado por Márcio Calicchio - v1.1.3"

LOG_FILE="$HOME/infrapro-install.log"
LOCK_FILE="$HOME/.infrapro.lock"
STATE_FILE="$HOME/.infrapro.state.json"
ENV_FILE="$HOME/.infrapro.env"

DEBUG=0

# ---------------- UI ----------------
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

usage() {
  cat <<EOF
$TITLE

Uso:
  ./install.sh [--debug]

Auto-start via curl:
  curl -fsSL https://raw.githubusercontent.com/calicchiom/infrapro-oracle-cloud/main/install.sh | bash
  curl -fsSL https://raw.githubusercontent.com/calicchiom/infrapro-oracle-cloud/main/install.sh | bash -s -- --debug
EOF
}

# ---------------- Args ----------------
parse_args() {
  while (( $# )); do
    if [[ -z "${1:-}" ]]; then shift; continue; fi
    case "$1" in
      --debug) DEBUG=1; shift ;;
      -h|--help) usage; exit 0 ;;
      --) shift; break ;;
      *) err "Argumento desconhecido: $1"; usage; exit 1 ;;
    esac
  done
}

# ---------------- Utils ----------------
require_cmd() { command -v "$1" >/dev/null 2>&1 || { err "Comando obrigatório não encontrado: $1"; return 1; }; }

need_sudo() {
  command -v sudo >/dev/null 2>&1 || { err "sudo não encontrado."; exit 1; }
  if ! sudo -n true >/dev/null 2>&1; then step "Será solicitado seu password do sudo (se necessário)..."; fi
  sudo true
}

is_ubuntu_2404() { . /etc/os-release; [[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]]; }
is_arm64() { [[ "$(uname -m)" == "aarch64" || "$(uname -m)" == "arm64" ]]; }

# Retries/timeouts padronizados
CURL_CONNECT_TIMEOUT=5
CURL_MAX_TIME=25
CURL_RETRY=3
CURL_RETRY_DELAY=1

curlx() {
  curl -sS -f \
    --connect-timeout "$CURL_CONNECT_TIMEOUT" \
    --max-time "$CURL_MAX_TIME" \
    --retry "$CURL_RETRY" \
    --retry-delay "$CURL_RETRY_DELAY" \
    "$@"
}

curlkx() {
  curl -k -sS -f \
    --connect-timeout "$CURL_CONNECT_TIMEOUT" \
    --max-time "$CURL_MAX_TIME" \
    --retry "$CURL_RETRY" \
    --retry-delay "$CURL_RETRY_DELAY" \
    "$@"
}

curl_http_code() { # URL
  local url="$1"
  curl -k -sS -o /dev/null -w '%{http_code}' \
    --connect-timeout "$CURL_CONNECT_TIMEOUT" \
    --max-time "$CURL_MAX_TIME" \
    "$url" || echo "000"
}

with_retries() { # <retries> <delay> -- cmd...
  local r="$1"; shift; local d="$1"; shift; local n=0
  until "$@"; do
    n=$((n+1))
    (( n < r )) || return 1
    sleep "$d"
  done
}

# ---------------- APT non-interactive helpers ----------------
APT_OPTS=(
  -y
  -o Dpkg::Options::="--force-confdef"
  -o Dpkg::Options::="--force-confold"
  -o APT::Get::Assume-Yes=true
)

apt_update() { sudo apt-get update "${APT_OPTS[@]}"; }
apt_install() { sudo apt-get install "${APT_OPTS[@]}" "$@"; }
apt_upgrade() { sudo apt-get upgrade "${APT_OPTS[@]}"; }

apt_setup_retries() {
  sudo tee /etc/apt/apt.conf.d/80infrapro-retries >/dev/null <<'EOF'
Acquire::Retries "3";
EOF
}

apt_install_if_missing() {
  local to_install=()
  for pkg in "$@"; do
    dpkg -s "$pkg" >/dev/null 2>&1 || to_install+=("$pkg")
  done
  if ((${#to_install[@]})); then
    apt_update
    apt_install "${to_install[@]}"
  fi
}

configure_needrestart_noninteractive() {
  step "Configurando needrestart para modo não-interativo"
  sudo mkdir -p /etc/needrestart/conf.d
  sudo tee /etc/needrestart/conf.d/99-infrapro.conf >/dev/null <<'EOF'
$nrconf{restart} = 'a';
$nrconf{kernelhints} = 0;
EOF
  ok "needrestart configurado."
}

# ---------------- Kernel hold (evitar atualizar kernel) ----------------
hold_kernel_packages() {
  step "Aplicando HOLD em pacotes de kernel para evitar atualização e popup"

  # Pacotes comuns que puxam kernel no Ubuntu/Oracle
  local candidates=(
    linux-image-oracle
    linux-headers-oracle
    linux-modules-oracle
    linux-modules-extra-oracle
    linux-oracle
    linux-generic
    linux-image-generic
    linux-headers-generic
  )

  # Também segura o kernel específico em execução (se existir como pacote)
  local running
  running="$(uname -r)"
  candidates+=("linux-image-$running" "linux-headers-$running" "linux-modules-$running")

  local to_hold=()
  local p
  for p in "${candidates[@]}"; do
    if dpkg -s "$p" >/dev/null 2>&1; then
      to_hold+=("$p")
    fi
  done

  if ((${#to_hold[@]}==0)); then
    warn "Nenhum pacote de kernel candidato encontrado para HOLD (ok)."
    return 0
  fi

  # marca hold
  printf '%s\n' "${to_hold[@]}" | sudo xargs -r apt-mark hold >/dev/null
  ok "Kernel HOLD aplicado: ${to_hold[*]}"
}

# ---------------- Lock ----------------
acquire_lock() {
  require_cmd flock
  exec 9>"$LOCK_FILE"
  if ! flock -n 9; then
    err "Outra execução do install.sh já está em andamento (lock: $LOCK_FILE)."
    exit 1
  fi
  ok "Lock adquirido: $LOCK_FILE"
}

# ---------------- State ----------------
state_init() {
  require_cmd jq
  if [[ ! -f "$STATE_FILE" ]]; then
    cat >"$STATE_FILE" <<'JSON'
{
  "version": "1.1.3",
  "checkpoints": {}
}
JSON
    chmod 600 "$STATE_FILE" || true
  fi
}

state_set() { local key="$1"; local val="$2"; local tmp; tmp="$(mktemp)"; jq --arg k "$key" --arg v "$val" '.checkpoints[$k]=$v' "$STATE_FILE" >"$tmp"; mv "$tmp" "$STATE_FILE"; }
state_get() { local key="$1"; jq -r --arg k "$key" '.checkpoints[$k] // empty' "$STATE_FILE"; }

# ---------------- Input validation ----------------
valid_hostname() { local h="$1"; [[ "$h" != http://* && "$h" != https://* ]] || return 1; [[ "$h" =~ ^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}$ ]]; }
dns_resolves() { dig +time=2 +tries=2 +short A "$1" | head -n1 | grep -q . || dig +time=2 +tries=2 +short AAAA "$1" | head -n1 | grep -q .; }
valid_portainer_user() { [[ "$1" =~ ^[A-Za-z0-9_]{3,}$ ]]; }
valid_docker_net() { [[ "$1" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$ ]]; }
valid_email() { [[ "$1" =~ ^[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$ ]]; }
email_domain_resolves() { local d="${1#*@}"; dig +time=2 +tries=2 +short MX "$d" | head -n1 | grep -q . || dig +time=2 +tries=2 +short A "$d" | head -n1 | grep -q .; }

prompt_inputs() {
  info "Informe os dados (com validação)."
  while true; do
    read -r -p "URL do Portainer (ex: painel.seudominio.com): " URL_PORTAINER
    URL_PORTAINER="${URL_PORTAINER,,}"
    valid_hostname "$URL_PORTAINER" || { warn "Hostname inválido (sem http/https)."; continue; }
    dns_resolves "$URL_PORTAINER" || { warn "DNS não resolve para $URL_PORTAINER. Ajuste e tente novamente."; continue; }
    break
  done
  while true; do
    read -r -p "Usuário admin do Portainer (>=3, alfanumérico e underscore): " USUARIO_ADMIN
    valid_portainer_user "$USUARIO_ADMIN" || { warn "Usuário inválido."; continue; }
    break
  done
  while true; do
    read -r -s -p "Senha do Portainer (mínimo 12 caracteres): " SENHA_PORTAINER; echo
    ((${#SENHA_PORTAINER} >= 12)) || { warn "Senha muito curta."; continue; }
    read -r -s -p "Confirme a senha do Portainer: " SENHA_PORTAINER_CONFIRM; echo
    [[ "$SENHA_PORTAINER" == "$SENHA_PORTAINER_CONFIRM" ]] || { warn "Senhas não conferem."; continue; }
    break
  done
  while true; do
    read -r -p "Nome da rede Swarm (ex: infrapro_net): " NOME_REDE_USUARIO
    valid_docker_net "$NOME_REDE_USUARIO" || { warn "Nome de rede inválido."; continue; }
    break
  done
  while true; do
    read -r -p "Email para certificados SSL (Let's Encrypt): " EMAIL_SSL
    valid_email "$EMAIL_SSL" || { warn "Email inválido."; continue; }
    email_domain_resolves "$EMAIL_SSL" || { warn "Domínio do email não resolve (MX/A)."; continue; }
    break
  done
}

write_env_file() {
  step "Criando $ENV_FILE (600) sem senha em texto"
  umask 077
  local pass_hash
  pass_hash="$(printf '%s' "$SENHA_PORTAINER" | sha256sum | awk '{print $1}')"
  cat >"$ENV_FILE" <<EOF
URL_PORTAINER=${URL_PORTAINER}
USUARIO_ADMIN=${USUARIO_ADMIN}
NOME_REDE_USUARIO=${NOME_REDE_USUARIO}
EMAIL_SSL=${EMAIL_SSL}
PORTAINER_PASSWORD_SHA256=${pass_hash}
EOF
  chmod 600 "$ENV_FILE"
  ok "$ENV_FILE criado."
}

# ---------------- Repo bootstrap ----------------
REPO_URL="https://github.com/calicchiom/infrapro-oracle-cloud"
REPO_DIR="$HOME/infrapro-oracle-cloud"

ensure_repo_and_reexec() {
  if [[ "${INFRAPRO_CLONED:-0}" != "1" ]]; then
    step "Primeira ação: git clone $REPO_URL"
    if [[ -d "$REPO_DIR/.git" ]]; then
      ok "Repositório já existe; tentando atualizar (git pull)."
      git -C "$REPO_DIR" pull --ff-only || warn "git pull falhou; continuando."
    else
      git clone "$REPO_URL" "$REPO_DIR"
      ok "Clone concluído em $REPO_DIR"
    fi
    step "chmod +x install.sh e uninstall.sh no repositório"
    [[ -f "$REPO_DIR/install.sh" ]] && chmod +x "$REPO_DIR/install.sh" || true
    [[ -f "$REPO_DIR/uninstall.sh" ]] && chmod +x "$REPO_DIR/uninstall.sh" || true
    step "Reexecutando automaticamente a partir do repositório..."
    if (( DEBUG )); then
      INFRAPRO_CLONED=1 exec "$REPO_DIR/install.sh" --debug
    else
      INFRAPRO_CLONED=1 exec "$REPO_DIR/install.sh"
    fi
  fi
}

# ---------------- YAML render ----------------
render_yaml_with_vars() { local src="$1" dst="$2"; [[ -f "$src" ]] || { err "Arquivo não encontrado: $src"; return 1; }
  export SWARM_NETWORK="$NOME_REDE_USUARIO"; export PORTAINER_URL="$URL_PORTAINER"; export SSL_EMAIL="$EMAIL_SSL"
  command -v envsubst >/dev/null 2>&1 || { err "envsubst não encontrado (instale gettext-base)."; return 1; }
  envsubst '${SWARM_NETWORK} ${PORTAINER_URL} ${SSL_EMAIL}' <"$src" >"$dst"
  if grep -q '\${[A-Za-z_][A-Za-z0-9_]*}' "$dst"; then
    err "Variáveis não resolvidas em $dst:"; grep -n '\${[A-Za-z_][A-Za-z0-9_]*}' "$dst" || true; return 1
  fi
}

copy_and_render_yamls() {
  step "Copiando YAMLs do repo e renderizando no HOME"
  local t="$REPO_DIR/traefik.yaml" p="$REPO_DIR/portainer.yaml"
  [[ -f "$t" ]] || { err "YAML não encontrado: $t"; exit 1; }
  [[ -f "$p" ]] || { err "YAML não encontrado: $p"; exit 1; }
  cp -f "$t" "$HOME/traefik.yaml.tpl"; cp -f "$p" "$HOME/portainer.yaml.tpl"
  step "Renderizando para ~/traefik.yaml e ~/portainer.yaml"
  render_yaml_with_vars "$HOME/traefik.yaml.tpl" "$HOME/traefik.yaml"
  render_yaml_with_vars "$HOME/portainer.yaml.tpl" "$HOME/portainer.yaml"
  ok "YAMLs prontos."
}

# ---------------- Dependencies ----------------
install_dependencies() {
  step "Instalando dependências essenciais"
  apt_install_if_missing curl wget git ca-certificates gnupg lsb-release apt-transport-https software-properties-common dnsutils jq unzip net-tools htop tree vim nano gettext-base util-linux needrestart
  local cmds=(curl wget git gpg lsb_release dig jq unzip netstat envsubst flock)
  for c in "${cmds[@]}"; do require_cmd "$c"; done
  ok "Dependências OK."
}

# ---------------- Phase 1 ----------------
disable_auto_upgrades() {
  local file="/etc/apt/apt.conf.d/20auto-upgrades"
  step "FASE 1.1 — Desabilitando atualizações automáticas"
  sudo mkdir -p /etc/apt/apt.conf.d
  [[ -f "$file" ]] && sudo cp -a "$file" "${file}.bak.infrapro.$(date +%Y%m%d%H%M%S)" || true
  sudo tee "$file" >/dev/null <<'EOF'
APT::Periodic::Update-Package-Lists "0";
APT::Periodic::Unattended-Upgrade "0";
EOF
  sudo systemctl stop unattended-upgrades 2>/dev/null || true
  sudo systemctl disable unattended-upgrades 2>/dev/null || true
  sudo systemctl stop apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
  sudo systemctl disable apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
  ok "Auto-upgrades desabilitados."
}

remove_unattended_upgrades_pkg() {
  step "FASE 1.2 — Removendo unattended-upgrades"
  if dpkg -s unattended-upgrades >/dev/null 2>&1; then
    sudo apt remove -y unattended-upgrades
    sudo apt autoremove -y
    ok "unattended-upgrades removido."
  else
    ok "unattended-upgrades já não instalado."
  fi
}

update_upgrade_and_apparmor() {
  step "FASE 1.3 — Update/upgrade (non-interactive, sem kernel) + apparmor-utils"
  hold_kernel_packages
  apt_update
  apt_upgrade
  apt_install apparmor-utils
  ok "Sistema atualizado sem atualizar kernel."
}

configure_ufw() {
  step "FASE 1.4 — Configurando UFW (modo permissivo conforme solicitado)"
  apt_install_if_missing ufw
  sudo ufw default allow incoming
  sudo ufw default allow outgoing
  sudo ufw --force enable
  ok "UFW habilitado."
  sudo ufw status verbose || true
}

# ---------------- Phase 2 ----------------
install_docker() {
  step "FASE 2.1 — Instalando Docker"
  if ! command -v docker >/dev/null 2>&1; then
    sudo install -m 0755 -d /etc/apt/keyrings
    curlx https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=arm64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
      | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
    apt_update
    apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    ok "Docker instalado."
  else
    ok "Docker já instalado."
  fi
  sudo systemctl enable --now docker
  sudo systemctl enable --now containerd
  sudo docker version >/dev/null
  sudo docker info >/dev/null
  ok "Docker validado."
}

init_swarm_and_network() {
  step "FASE 2.2 — Swarm + rede overlay"
  local state
  state="$(sudo docker info --format '{{.Swarm.LocalNodeState}}' 2>/dev/null || echo "inactive")"
  if [[ "$state" != "active" ]]; then
    local LOCAL_IP
    LOCAL_IP="$(ip route get 1.1.1.1 | grep -oP 'src \K\S+' || true)"
    [[ -n "$LOCAL_IP" ]] || { err "Falha ao detectar IP local."; exit 1; }
    sudo docker swarm init --advertise-addr "$LOCAL_IP"
    ok "Swarm inicializado."
  else
    ok "Swarm já ativo."
  fi
  if sudo docker network ls --format '{{.Name}}' | grep -qx "$NOME_REDE_USUARIO"; then
    ok "Rede já existe: $NOME_REDE_USUARIO"
  else
    sudo docker network create -d overlay --attachable "$NOME_REDE_USUARIO"
    ok "Rede criada: $NOME_REDE_USUARIO"
  fi
}

deploy_traefik() {
  step "FASE 2.3 — Deploy Traefik"
  sudo docker stack deploy -c "$HOME/traefik.yaml" traefik
  timeout 300 bash -c 'until sudo docker service ps traefik_traefik --format "{{.CurrentState}}" | grep -q Running; do sleep 5; done'
  ok "Traefik convergiu."
}

deploy_portainer() {
  step "FASE 2.4 — Deploy Portainer"
  sudo docker stack deploy -c "$HOME/portainer.yaml" portainer
  timeout 300 bash -c 'until sudo docker service ps portainer_portainer --format "{{.CurrentState}}" | grep -q Running; do sleep 5; done'
  ok "Portainer convergiu."
}

# ---------------- Portainer bootstrap ----------------
portainer_get_status_json() { local base="https://${URL_PORTAINER}"; curlkx -H 'Accept: application/json' "${base}/api/status" 2>/dev/null || return 1; }
portainer_wait_api() {
  local base="https://${URL_PORTAINER}"
  step "Aguardando Portainer API em ${base}/api/status (timeout ~240s)"
  local i code
  for i in {1..80}; do
    code="$(curl_http_code "${base}/api/status")"
    if [[ "$code" == "200" || "$code" == "204" || "$code" == "401" ]]; then
      ok "API respondeu /api/status (HTTP $code)"
      return 0
    fi
    sleep 3
  done
  return 1
}
portainer_try_auth() {
  local base="https://${URL_PORTAINER}"
  local code jwt
  code="$(curl -k -sS -o /tmp/pauth.json -w '%{http_code}' \
    --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
    -H 'Content-Type: application/json' \
    -d "{\"Username\":\"${USUARIO_ADMIN}\",\"Password\":\"${SENHA_PORTAINER}\"}" \
    "${base}/api/auth" || echo "000")"
  if [[ "$code" == "200" ]]; then
    jwt="$(jq -r '.jwt // empty' /tmp/pauth.json 2>/dev/null || true)"
    rm -f /tmp/pauth.json 2>/dev/null || true
    [[ -n "$jwt" ]]
    return $?
  fi
  rm -f /tmp/pauth.json 2>/dev/null || true
  return 1
}
portainer_try_init() {
  local url="$1" code
  code="$(curl -k -sS -o /tmp/pinit.json -w '%{http_code}' \
    --connect-timeout "$CURL_CONNECT_TIMEOUT" --max-time "$CURL_MAX_TIME" \
    -H 'Content-Type: application/json' \
    -d "{\"Username\":\"${USUARIO_ADMIN}\",\"Password\":\"${SENHA_PORTAINER}\"}" \
    "$url" || echo "000")"
  case "$code" in
    200|204) rm -f /tmp/pinit.json; ok "Init admin OK via $url (HTTP $code)"; return 0 ;;
    409)     rm -f /tmp/pinit.json; warn "Já inicializado (HTTP 409) via $url"; return 0 ;;
    404)     rm -f /tmp/pinit.json; info "Endpoint não existe (404): $url"; return 2 ;;
    *)       rm -f /tmp/pinit.json; warn "Falha init via $url (HTTP $code)"; return 1 ;;
  esac
}
bootstrap_portainer_admin() {
  step "BOOTSTRAP — Portainer admin (best-effort)"
  if ! portainer_wait_api; then warn "Portainer API não respondeu a tempo."; return 1; fi
  if portainer_try_auth; then ok "Portainer já aceita login com as credenciais informadas."; return 0; fi
  local status_json version
  status_json="$(portainer_get_status_json || true)"
  version="$(jq -r '.Version // .version // empty' <<<"$status_json" 2>/dev/null || true)"
  [[ -n "$version" ]] && info "Portainer version: $version" || info "Versão não detectada (ok)."
  local base="https://${URL_PORTAINER}"
  local endpoints=("${base}/api/users/admin/init" "${base}/api/users/admin/init/force" "${base}/api/users/admin/initialize")
  local ep rc
  for ep in "${endpoints[@]}"; do portainer_try_init "$ep"; rc=$?; [[ "$rc" == "0" ]] && break; done
  if with_retries 10 2 portainer_try_auth; then ok "Bootstrap do Portainer concluído."; return 0; fi
  warn "Bootstrap automático não conseguiu validar login. Faça pela UI: https://${URL_PORTAINER}"
  return 1
}

main() {
  parse_args "$@"

  mkdir -p "$(dirname "$LOG_FILE")"
  exec > >(tee -a "$LOG_FILE") 2>&1

  if (( DEBUG )); then set -x; warn "Modo --debug habilitado."; fi

  echo -e "${BOLD}${WHITE}${TITLE}${RESET}"
  info "Log: $LOG_FILE"

  [[ "$EUID" -ne 0 ]] || { err "Não execute como root direto."; exit 1; }
  is_ubuntu_2404 || { err "Requer Ubuntu 24.04."; exit 1; }
  is_arm64 || { err "Requer ARM64/aarch64."; exit 1; }

  need_sudo
  install_dependencies
  apt_setup_retries
  configure_needrestart_noninteractive

  acquire_lock
  state_init

  ensure_repo_and_reexec

  if [[ -z "$(state_get inputs_ok)" ]]; then
    prompt_inputs
    write_env_file
    state_set inputs_ok "true"
  else
    ok "Checkpoint inputs_ok já concluído."
    # shellcheck disable=SC1090
    source "$ENV_FILE" || true
  fi

  if [[ -z "$(state_get yamls_ok)" ]]; then
    copy_and_render_yamls
    state_set yamls_ok "true"
  else
    ok "Checkpoint yamls_ok já concluído."
  fi

  if [[ -z "$(state_get fase1_ok)" ]]; then
    disable_auto_upgrades
    remove_unattended_upgrades_pkg
    update_upgrade_and_apparmor
    configure_ufw
    state_set fase1_ok "true"
  else
    ok "Checkpoint fase1_ok já concluído."
  fi

  if [[ -z "$(state_get docker_ok)" ]]; then
    install_docker
    state_set docker_ok "true"
  else
    ok "Checkpoint docker_ok já concluído."
  fi

  if [[ -z "$(state_get swarm_ok)" ]]; then
    init_swarm_and_network
    state_set swarm_ok "true"
  else
    ok "Checkpoint swarm_ok já concluído."
  fi

  if [[ -z "$(state_get traefik_ok)" ]]; then
    deploy_traefik
    state_set traefik_ok "true"
  else
    ok "Checkpoint traefik_ok já concluído."
  fi

  if [[ -z "$(state_get portainer_ok)" ]]; then
    deploy_portainer
    state_set portainer_ok "true"
  else
    ok "Checkpoint portainer_ok já concluído."
  fi

  if [[ -z "$(state_get portainer_bootstrap_done)" ]]; then
    bootstrap_portainer_admin || true
    state_set portainer_bootstrap_done "true"
  else
    ok "Checkpoint portainer_bootstrap_done já concluído."
  fi

  unset SENHA_PORTAINER SENHA_PORTAINER_CONFIRM || true

  echo
  ok "Instalação finalizada."
  info "Portainer: https://${URL_PORTAINER}"
  info "State file: $STATE_FILE"
  warn "Kernel updates estão em HOLD para evitar interrupções. Para liberar no futuro: sudo apt-mark unhold linux-image-oracle linux-headers-oracle linux-oracle"
}

main "$@"
