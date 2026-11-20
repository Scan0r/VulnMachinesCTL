#!/usr/bin/env bash
#
# vulnmachinesctl.sh — Vulnerable web and API penetration-testing lab manager.
#
# Installs, deploys, stops, manages, and removes vulnerable labs
# locally using Docker Engine + Docker Compose v2 (`docker compose` plugin).
#
# File structure:
#   1. General configuration and helpers
#   2. Lab catalog (static data)
#   3. Lab-specific logic (install / access / wait_url / post_up)
#   4. Shared logic (dc, installation, up, down, status, logs, shell, remove, purge)
#   5. CLI
#
# To add a new lab:
#   - add its ID to LABS and populate L_DESC, L_TECH, L_REPO, L_METHOD, L_GIT,
#     L_BUILD and L_SHELL (section 2);
#   - define lab_<id>_install, lab_<id>_wait_url and lab_<id>_access (section 3),
#     and opcionalmente lab_<id>_post_up (hyphens in IDs become underscores).
#
# Security: all published ports bind to 127.0.0.1; sudo is used only for
# narrowly scoped /etc/hosts edits (never for Docker or this script), and
# deletion commands only accept catalog IDs (never paths) and verify
# the directory belongs to the managed root and contains our marker.

set -Eeuo pipefail
shopt -s inherit_errexit 2>/dev/null || true

# ─────────────────────────────────────────────────────────────────────────────
# 1. Configuration and helpers
# ─────────────────────────────────────────────────────────────────────────────
readonly PROG="vulnmachinesctl.sh"
readonly VERSION="1.0.0"
readonly PROJECT_PREFIX="vulnmachinesctl"          # Compose project: vulnmachinesctl-<id>
readonly ROOT_MARKER=".vulnmachinesctl-root"       # managed-root marker
readonly LAB_MARKER=".vulnmachinesctl-lab"         # per-lab marker
readonly INSTALLED_MARKER=".vulnmachinesctl-installed"
readonly WAIT_TIMEOUT="${WAIT_TIMEOUT:-300}"
readonly VULNMACHINESCTL_BROWSER_DELAY="${VULNMACHINESCTL_BROWSER_DELAY:-2}"
[[ $VULNMACHINESCTL_BROWSER_DELAY =~ ^[0-9]+([.][0-9]+)?$ ]] || { echo "Invalid VULNMACHINESCTL_BROWSER_DELAY (must be nonnegative seconds)" >&2; exit 2; }
readonly LABS_DIR_INPUT="${LABS_DIR:-./vuln-labs}"
readonly TOOL_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly PROXY_ENABLED="${VULNMACHINESCTL_PROXY:-1}"
LABS_ROOT=""

if [[ -t 1 ]]; then
  C_B=$'\033[1m'; C_R=$'\033[0m'; C_RED=$'\033[31m'; C_GRN=$'\033[32m'
  C_YEL=$'\033[33m'; C_BLU=$'\033[34m'
else
  C_B=""; C_R=""; C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""
fi

info() { printf '%s[i]%s %s\n' "$C_BLU" "$C_R" "$*"; }
ok()   { printf '%s[ok]%s %s\n' "$C_GRN" "$C_R" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YEL" "$C_R" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$C_RED" "$C_R" "$*" >&2; }
die()  { err "$1"; exit "${2:-1}"; }

on_err() { err "Unexpected error (code $1) at line $2 of $PROG."; }
trap 'on_err $? $LINENO' ERR

key() { printf '%s' "${1//-/_}"; }   # ID -> function suffix

# ─────────────────────────────────────────────────────────────────────────────
# 2. Catalog (static data)
# ─────────────────────────────────────────────────────────────────────────────
# Alphabetical order used by 'list', 'status', 'install all' and 'up all'.
LABS=(crapi dvga dvwa dvws-node juice-shop mutillidae oauth2 vampi vapi
     vulnbank vulndap vulnerableapp vulnlab webgoat webgoat7 xvwa)

declare -A L_DESC L_TECH L_REPO L_METHOD L_GIT L_BUILD L_SHELL

L_DESC[crapi]="OWASP crAPI: vehicle dealership API covering the OWASP API Security Top 10"
L_TECH[crapi]="Microservices (Java, Python, Go), PostgreSQL, MongoDB, MailHog, ChromaDB"
L_REPO[crapi]="https://github.com/OWASP/crAPI"
L_METHOD[crapi]="git clone (main branch) + upstream deploy/docker Compose (crapi/* images)"
L_GIT[crapi]=yes;  L_BUILD[crapi]=no;  L_SHELL[crapi]=crapi-web

L_DESC[vampi]="VAmPI: API REST vulnerable (Flask, OpenAPI 3, Swagger UI)"
L_TECH[vampi]="Python/Flask, SQLite"
L_REPO[vampi]="https://github.com/erev0s/VAmPI"
L_METHOD[vampi]="upstream erev0s/vampi:latest image (custom Compose, vulnerable=1)"
L_GIT[vampi]=no;   L_BUILD[vampi]=no;  L_SHELL[vampi]=vampi

L_DESC[dvws-node]="DVWS Node: vulnerable web/API services (REST, SOAP, XML-RPC, GraphQL)"
L_TECH[dvws-node]="Node.js, MongoDB 4.0, MySQL 8"
L_REPO[dvws-node]="https://github.com/snoopysecurity/dvws-node"
L_METHOD[dvws-node]="git clone (master) + custom Compose based on upstream (local build)"
L_GIT[dvws-node]=yes; L_BUILD[dvws-node]=yes; L_SHELL[dvws-node]=web

L_DESC[vulndap]="vuLnDAP: vulnerable LDAP-backed web app focused on business-logic flaws"
L_TECH[vulndap]="Go (embedded LDAP server + HTTP application)"
L_REPO[vulndap]="https://github.com/digininja/vuLnDAP"
L_METHOD[vulndap]="git clone (master) + custom Go build and Compose (no official Docker image)"
L_GIT[vulndap]=yes; L_BUILD[vulndap]=yes; L_SHELL[vulndap]=vulndap

L_DESC[vulnerableapp]="OWASP VulnerableApp: SQLi, XSS, XXE, SSRF, JWT, LDAP, file upload..."
L_TECH[vulnerableapp]="Java/Spring Boot, JSP, PHP, nginx (facade), MongoDB, Mailpit"
L_REPO[vulnerableapp]="https://github.com/SasanLabs/VulnerableApp"
L_METHOD[vulnerableapp]="upstream sasanlabs/* images (custom Compose based on docker-compose.without_llm.yml)"
L_GIT[vulnerableapp]=no; L_BUILD[vulnerableapp]=no; L_SHELL[vulnerableapp]=VulnerableApp-base

L_DESC[xvwa]="XVWA: intentionally vulnerable PHP/MySQL app (SQLi, XSS, XXE, XPath, SSRF, IDOR...)"
L_TECH[xvwa]="PHP 7.4 + Apache, MariaDB"
L_REPO[xvwa]="https://github.com/SVelizDonoso/xvwa (Spanish fork of archived s4n7h0/xvwa)"
L_METHOD[xvwa]="git clone + Dockerfile and custom Compose (no upstream Docker support)"
L_GIT[xvwa]=yes; L_BUILD[xvwa]=yes; L_SHELL[xvwa]=web

L_DESC[webgoat]="OWASP WebGoat (Latest): guided web security lessons with WebWolf (Java/Spring)"
L_TECH[webgoat]="Java, Spring Boot (WebGoat + WebWolf)"
L_REPO[webgoat]="https://github.com/WebGoat/WebGoat"
L_METHOD[webgoat]="upstream webgoat/webgoat:latest image"
L_GIT[webgoat]=no; L_BUILD[webgoat]=no; L_SHELL[webgoat]=webgoat

L_DESC[juice-shop]="OWASP Juice Shop: modern storefront with OWASP Top 10 challenges"
L_TECH[juice-shop]="Node.js, Angular, SQLite"
L_REPO[juice-shop]="https://github.com/juice-shop/juice-shop"
L_METHOD[juice-shop]="upstream bkimminich/juice-shop:latest image"
L_GIT[juice-shop]=no; L_BUILD[juice-shop]=no; L_SHELL[juice-shop]=juice-shop

L_DESC[dvwa]="DVWA: classic vulnerable PHP/MariaDB application with difficulty levels"
L_TECH[dvwa]="PHP, MariaDB 10"
L_REPO[dvwa]="https://github.com/digininja/DVWA"
L_METHOD[dvwa]="upstream ghcr.io/digininja/dvwa:latest image + MariaDB (based on upstream Compose)"
L_GIT[dvwa]=no; L_BUILD[dvwa]=no; L_SHELL[dvwa]=dvwa

L_DESC[mutillidae]="OWASP Mutillidae II: 40+ vulnerabilities, REST/SOAP, LDAP"
L_TECH[mutillidae]="PHP/Apache, MySQL, OpenLDAP, phpMyAdmin, phpLDAPadmin"
L_REPO[mutillidae]="https://github.com/webpwnized/mutillidae (Docker setup: webpwnized/mutillidae-docker)"
L_METHOD[mutillidae]="git clone mutillidae-docker (five local container builds) + custom Compose with remapped ports"
L_GIT[mutillidae]=yes; L_BUILD[mutillidae]=yes; L_SHELL[mutillidae]=www

L_DESC[dvga]="DVGA: vulnerable GraphQL (introspection, injections, DoS, bypasses...)"
L_TECH[dvga]="Python/Flask, Graphene"
L_REPO[dvga]="https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application"
L_METHOD[dvga]="upstream dolevf/dvga:latest image"
L_GIT[dvga]=no; L_BUILD[dvga]=no; L_SHELL[dvga]=dvga

L_DESC[vulnbank]="VulnBank: vulnerable banking app (JWT, BOLA, mass assignment, business logic, GraphQL, AI)"
L_TECH[vulnbank]="Python/Flask, PostgreSQL 13"
L_REPO[vulnbank]="https://github.com/Commando-X/vuln-bank"
L_METHOD[vulnbank]="git clone (main) + custom Compose (without upstream autoheal/docker.sock service)"
L_GIT[vulnbank]=yes; L_BUILD[vulnbank]=yes; L_SHELL[vulnbank]=web

L_DESC[vapi]="vAPI: PHP/Laravel API simulating OWASP API Top 10 scenarios"
L_TECH[vapi]="PHP (Laravel), MySQL 8"
L_REPO[vapi]="https://github.com/roottusk/vapi"
L_METHOD[vapi]="git clone (master) + custom Compose based on upstream (MySQL/phpMyAdmin not exposed)"
L_GIT[vapi]=yes; L_BUILD[vapi]=yes; L_SHELL[vapi]=www

L_DESC[oauth2]="Vulnerable OAuth 2.0 Applications: gallery (server), photoprint (client), attacker"
L_TECH[oauth2]="Node.js (MEAN), MongoDB 4.0, Selenium Firefox (VNC)"
L_REPO[oauth2]="https://github.com/koenbuyens/Vulnerable-OAuth-2.0-Applications"
L_METHOD[oauth2]="git clone (master) + custom Compose based on insecureapplication/docker-compose.yml"
L_GIT[oauth2]=yes; L_BUILD[oauth2]=yes; L_SHELL[oauth2]=photoprint

L_DESC[vulnlab]="Yavuzlar VulnLab: 15 categories (SQLi, XSS, CMDi, IDOR, CSRF, XXE, deserialization, file upload/inclusion, SSTI, race conditions, API, CAPTCHA...)"
L_TECH[vulnlab]="PHP + Apache + MariaDB in one container (ubuntu:20.04)"
L_REPO[vulnlab]="https://github.com/Yavuzlar/VulnLab"
L_METHOD[vulnlab]="upstream yavuzlar/vulnlab:latest image (custom Compose; upstream documents docker run only)"
L_GIT[vulnlab]=no; L_BUILD[vulnlab]=no; L_SHELL[vulnlab]=vulnlab

L_DESC[webgoat7]="OWASP WebGoat 7.1 (Legacy): classic WebGoat 7.x security lessons"
L_TECH[webgoat7]="Java (embedded Tomcat), one app on port 8080"
L_REPO[webgoat7]="https://hub.docker.com/r/webgoat/webgoat-7.1 (source: https://github.com/WebGoat/WebGoat, 7.x tags)"
L_METHOD[webgoat7]="webgoat/webgoat-7.1 Docker Hub image (custom Compose; WebWolf did not exist in 7.x)"
L_GIT[webgoat7]=no; L_BUILD[webgoat7]=no; L_SHELL[webgoat7]=webgoat7


# ─────────────────────────────────────────────────────────────────────────────
# File and validation helpers
# ─────────────────────────────────────────────────────────────────────────────

# Read VAR=value from the lab .env file (or return the default).
env_val() {
  local id=$1 var=$2 def=$3 f="$LABS_ROOT/$1/.env" v=""
  if [[ -f $f ]]; then
    v="$(grep -E "^${var}=" "$f" | tail -n1 | cut -d= -f2- | tr -d "\"'" || true)"
  fi
  printf '%s' "${v:-$def}"
}

resolve_root() {
  command -v realpath >/dev/null 2>&1 || die "The 'realpath' command (coreutils) is required." 3
  LABS_ROOT="$(realpath -m -- "$LABS_DIR_INPUT")"
  [[ $LABS_ROOT != "/" ]] || die "LABS_DIR cannot be the filesystem root." 2
  [[ $LABS_ROOT != "${HOME:-/nonexistent-home}" ]] || die "LABS_DIR cannot be your home directory." 2
  local depth
  depth="$(awk -F/ '{print NF-1}' <<<"$LABS_ROOT")"
  (( depth >= 2 )) || die "LABS_DIR='$LABS_ROOT' is too shallow; use a dedicated subdirectory." 2
}

# Create the managed root (with marker) or verify it; never adopt unrelated folders.
ensure_root() {
  if [[ ! -e $LABS_ROOT ]]; then
    mkdir -p -- "$LABS_ROOT"
    : >"$LABS_ROOT/$ROOT_MARKER"
  elif [[ -L $LABS_ROOT || ! -d $LABS_ROOT ]]; then
    die "'$LABS_ROOT' exists but is not a regular directory." 2
  elif [[ ! -f $LABS_ROOT/$ROOT_MARKER ]]; then
    if [[ -z "$(ls -A -- "$LABS_ROOT")" ]]; then
      : >"$LABS_ROOT/$ROOT_MARKER"
    else
      die "'$LABS_ROOT' is not empty and is not a managed root of $PROG (missing $ROOT_MARKER). Choose another LABS_DIR." 2
    fi
  fi
}

valid_lab() {
  local id=$1 l
  [[ $id =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 1
  for l in "${LABS[@]}"; do [[ $l == "$id" ]] && return 0; done
  return 1
}

# Return lab IDs for an argument <laboratorio|all>.
targets_of() {
  local arg=${1:-}
  [[ -n $arg ]] || die "Missing argument <laboratorio>. Use: $PROG list" 2
  if [[ $arg == all && ${2:-} == allow-all ]]; then
    printf '%s\n' "${LABS[@]}"
  else
    valid_lab "$arg" || die "Invalid lab: '$arg'. Use: $PROG list" 2
    printf '%s\n' "$arg"
  fi
}

# Verified lab directory for deletion.
# Accept catalog IDs only; verify root containment, no symlink, and marker.
safe_lab_dir() {
  local id=$1 d real root_real
  valid_lab "$id" || die "Invalid ID for deletion: '$id'" 2
  [[ -f $LABS_ROOT/$ROOT_MARKER ]] || die "The root '$LABS_ROOT' is not managed by $PROG; deletion refused." 2
  d="$LABS_ROOT/$id"
  [[ -d $d && ! -L $d ]] || { printf ''; return 1; }
  real="$(realpath -- "$d")"
  root_real="$(realpath -- "$LABS_ROOT")"
  [[ $real == "$root_real/$id" ]] || die "'$real' is outside the managed root; aborting." 2
  [[ -f $real/$LAB_MARKER && "$(cat -- "$real/$LAB_MARKER")" == "$id" ]] \
    || die "'$real' does not contain the marker of $PROG for '$id'; deletion refused." 2
  printf '%s' "$real"
}

# Write a managed file from stdin without overwriting local edits.
write_managed() {
  local path=$1 tmp
  tmp="$(mktemp)"
  cat >"$tmp"
  if [[ -e $path ]]; then
    if cmp -s "$tmp" "$path"; then
      :
    else
      warn "$path has local changes: keeping it (new template at $path.new)"
      install -m 644 "$tmp" "$path.new"
    fi
  else
    install -m 644 "$tmp" "$path"
  fi
  rm -f -- "$tmp"
}

# Create .env from .env.example only if absent (never overwrite).
make_env() {
  local dir=$1
  if [[ -f $dir/.env ]]; then
    info "  existing .env: preserved"
  elif [[ -f $dir/.env.example ]]; then
    cp -- "$dir/.env.example" "$dir/.env"
  fi
}

# Clone a shallow repository atomically; leave existing clones untouched.
clone_repo() {
  local url=$1 dest=$2 branch=${3:-}
  if [[ -d $dest/.git ]]; then
    if [[ -n "$(git -C "$dest" status --porcelain 2>/dev/null)" ]]; then
      warn "  $dest has local changes: left untouched"
    else
      info "  repository already cloned: $dest"
    fi
    return 0
  fi
  [[ $dest == "$LABS_ROOT"/* ]] || die "Clone destination outside managed root: $dest" 2
  rm -rf -- "$dest.partial"
  info "  cloning $url ..."
  if [[ -n $branch ]]; then
    git clone --quiet --depth 1 --branch "$branch" -- "$url" "$dest.partial"
  else
    git clone --quiet --depth 1 -- "$url" "$dest.partial"
  fi
  mv -- "$dest.partial" "$dest"
}

acc_head() { printf '\n%s▶ %s%s\n' "$C_B" "$1" "$C_R"; }
acc_url()  { printf '  %-24s %s\n' "$1" "$2"; }
acc_cred() { printf '  %-24s %s\n' "$1" "$2"; }
acc_note() { printf '  %s\n' "$1"; }

# ─────────────────────────────────────────────────────────────────────────────
# 3. Lab-specific logic
# ─────────────────────────────────────────────────────────────────────────────

lab_compose_file() {
  case $1 in
    crapi) printf '%s' "$LABS_ROOT/crapi/repo/deploy/docker/docker-compose.yml" ;;
    *)     printf '%s' "$LABS_ROOT/$1/docker-compose.yml" ;;
  esac
}

# ── crAPI ────────────────────────────────────────────────────────────────────
lab_crapi_install() {
  local dir=$1
  clone_repo "https://github.com/OWASP/crAPI.git" "$dir/repo" main
  [[ -f $dir/repo/deploy/docker/docker-compose.yml ]] \
    || die "crAPI repository is missing deploy/docker/docker-compose.yml (did its structure change?)" 1
  warn "  crAPI uses fixed container names (mongodb, postgresdb, mailhog...); these may conflict with other containers."
}
lab_crapi_wait_url() { printf 'http://127.0.0.1:8888/'; }
lab_crapi_access() {
  acc_head "crAPI"
  acc_url "Web:" "http://127.0.0.1:8888"
  acc_url "MailHog (correos):" "http://127.0.0.1:8025"
  acc_cred "Credentials:" "no default user: register in the app (emails arrive in MailHog)"
  acc_note "Chatbot: requires CHATBOT_OPENAI_API_KEY (optional, see deploy/docker)."
}

# ── VAmPI ────────────────────────────────────────────────────────────────────
lab_vampi_install() {
  local dir=$1
  write_managed "$dir/.env.example" <<'EOF'
# Ports bound ONLY to 127.0.0.1
VAMPI_PORT=5002
VAMPI_SECURE_PORT=5001
VAMPI_TOKEN_TTL=3600
EOF
  write_managed "$dir/docker-compose.yml" <<'EOF'
# Generated by vulnmachinesctl.sh. Source: https://github.com/erev0s/VAmPI
services:
  vampi:
    image: erev0s/vampi:latest
    environment:
      - vulnerable=1
      - tokentimetolive=${VAMPI_TOKEN_TTL:-3600}
    ports:
      - "127.0.0.1:${VAMPI_PORT:-5002}:5000"

  # Non-vulnerable version for comparison (opcional): COMPOSE_PROFILES=secure
  vampi-secure:
    image: erev0s/vampi:latest
    profiles: ["secure"]
    environment:
      - vulnerable=0
      - tokentimetolive=${VAMPI_TOKEN_TTL:-3600}
    ports:
      - "127.0.0.1:${VAMPI_SECURE_PORT:-5001}:5000"
EOF
  make_env "$dir"
}
lab_vampi_wait_url() { printf 'http://127.0.0.1:%s/' "$(env_val vampi VAMPI_PORT 5002)"; }
lab_vampi_open_url() { printf 'http://127.0.0.1:%s/ui/' "$(env_val vampi VAMPI_PORT 5002)"; }
lab_vampi_post_up() {
  # The README requires calling /createdb to seed the database.
  local p; p="$(env_val vampi VAMPI_PORT 5002)"
  if curl -fsS --max-time 15 "http://127.0.0.1:$p/createdb" >/dev/null 2>&1; then
    ok "[vampi] database initialized/seeded (/createdb)"
  else
    warn "[vampi] could not call /createdb; run manually: curl http://127.0.0.1:$p/createdb"
  fi
}
lab_vampi_access() {
  local p; p="$(env_val vampi VAMPI_PORT 5002)"
  acc_head "VAmPI"
  acc_url "API:" "http://127.0.0.1:$p"
  acc_url "Swagger UI:" "http://127.0.0.1:$p/ui/"
  acc_cred "Credentials:" "no fixed login: POST /users/v1/register and POST /users/v1/login (returns a token)"
  acc_note "GET /users/v1/_debug (vulnerable mode) lists preloaded users with all their data."
}

# ── DVWS Node ────────────────────────────────────────────────────────────────
lab_dvws_node_install() {
  local dir=$1
  clone_repo "https://github.com/snoopysecurity/dvws-node.git" "$dir/repo" master
  write_managed "$dir/.env.example" <<'EOF'
# Ports bound ONLY to 127.0.0.1
DVWS_WEB_PORT=8081
DVWS_XMLRPC_PORT=9091
DVWS_GRAPHQL_PORT=4000
DVWS_MYSQL_ROOT_PASSWORD=mysecretpassword
EOF
  write_managed "$dir/docker-compose.yml" <<'EOF'
# Generated by vulnmachinesctl.sh. Based on the upstream docker-compose.yml from
# https://github.com/snoopysecurity/dvws-node (internal ports 80, 9090 y
# 4000 are defined in its .env; upstream only publishes port 80 on 0.0.0.0).
services:
  dvws-mongo:
    image: mongo:4.0.4
    healthcheck:
      test: ["CMD", "mongo", "--eval", "db.adminCommand('ping')"]
      interval: 30s
      timeout: 5s
      retries: 10
      start_period: 10s

  dvws-mysql:
    image: mysql:8
    environment:
      MYSQL_ROOT_PASSWORD: ${DVWS_MYSQL_ROOT_PASSWORD:-mysecretpassword}
      MYSQL_DATABASE: dvws_sqldb
    healthcheck:
      test: mysqladmin ping -h 127.0.0.1 -u root -p$${MYSQL_ROOT_PASSWORD}
      interval: 30s
      timeout: 5s
      retries: 10
      start_period: 10s

  web:
    build: ./repo
    ports:
      - "127.0.0.1:${DVWS_WEB_PORT:-8081}:80"
      - "127.0.0.1:${DVWS_XMLRPC_PORT:-9091}:9090"
      - "127.0.0.1:${DVWS_GRAPHQL_PORT:-4000}:4000"
    command: sh -c "node scripts/seed-database.js && npm start"
    environment:
      SQL_LOCAL_CONN_URL: dvws-mysql
      SQL_PASSWORD: ${DVWS_MYSQL_ROOT_PASSWORD:-mysecretpassword}
      MONGO_LOCAL_CONN_URL: mongodb://dvws-mongo:27017/node-dvws
    depends_on:
      dvws-mongo:
        condition: service_healthy
      dvws-mysql:
        condition: service_healthy
EOF
  make_env "$dir"
}
lab_dvws_node_wait_url() { printf 'http://127.0.0.1:%s/' "$(env_val dvws-node DVWS_WEB_PORT 8081)"; }
lab_dvws_node_access() {
  acc_head "DVWS Node"
  acc_url "Web/API/Swagger:" "http://127.0.0.1:$(env_val dvws-node DVWS_WEB_PORT 8081)"
  acc_url "XML-RPC / SOAP:" "http://127.0.0.1:$(env_val dvws-node DVWS_XMLRPC_PORT 9091)  (internal port 9090)"
  acc_url "GraphQL:" "http://127.0.0.1:$(env_val dvws-node DVWS_GRAPHQL_PORT 4000)"
  acc_cred "admin (admin):" "admin / letmein"
  acc_cred "user:" "test / test"
  acc_cred "challenge victims:" "recovery-victim / Victim123!   session-victim / Session123!"
  acc_note "Users from scripts/seed-database.js (master). Some Swagger URLs expect host dvws.local."
}

# ── vuLnDAP (digininja) ────────────────────────────────────────────────────────
# Repair the Dockerfile generated by earlier VulnMachinesCTL releases.
# Only the exact legacy template is touched; custom Dockerfiles are preserved.
lab_vulndap_patch_dockerfile() {
  local f="$LABS_ROOT/vulndap/Dockerfile"
  [[ -f $f && ! -L $f ]] || return 0
  command -v python3 >/dev/null 2>&1 || { warn '[vulndap] Python3 required to migrate the old Dockerfile.'; return 1; }
  python3 -I - "$f" <<'PYFIX'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text()
old = r'''RUN test -f main.go && test -f vulndap.cfg-sample && \
    if [ ! -f go.mod ]; then go mod init github.com/digininja/vuLnDAP; fi && \
    go mod tidy && CGO_ENABLED=0 go build -o /out/vulndap .'''
new = r'''# Upstream imports a legacy Blackfriday module alias. Current Go modules use
# github.com/russross/blackfriday/v2; patch only the build-stage source copy.
RUN test -f main.go && test -f vulndap.cfg-sample && \
    find . -name '*.go' -type f -exec sed -i \
      's|gopkg.in/russross/blackfriday.v2|github.com/russross/blackfriday/v2|g' {} + && \
    if [ ! -f go.mod ]; then go mod init github.com/digininja/vuLnDAP; fi && \
    go mod tidy && CGO_ENABLED=0 go build -o /out/vulndap .'''
if old in s and '# Generated by VulnMachinesCTL.' in s:
    p.write_text(s.replace(old, new, 1))
    print('[vulndap] migrated legacy Dockerfile to the corrected Go import path')
elif new not in s:
    print('[vulndap] Dockerfile is custom or differs from the old template; preserved unchanged')
PYFIX
}

lab_vulndap_install() {
  local dir=$1
  clone_repo "https://github.com/digininja/vuLnDAP.git" "$dir/repo" master
  [[ -f $dir/repo/vulndap.cfg-sample && -f $dir/repo/main.go ]] \
    || die "[vulndap] upstream source or sample configuration missing." 1
  write_managed "$dir/.env.example" <<'EOF'
# Only the HTTP web application is published on the host.
VULNDAP_PORT=9093
EOF
  write_managed "$dir/.dockerignore" <<'EOF'
repo/.git
.env
*.new
EOF
  write_managed "$dir/Dockerfile" <<'EOF'
# Generated by VulnMachinesCTL. Builds the original GPL-3.0 vuLnDAP source.
# The upstream project has no Docker image or Go module manifest.
FROM golang:1.23-bookworm AS builder
WORKDIR /src
COPY repo/ ./
# Upstream imports a legacy Blackfriday module alias. Current Go modules use
# github.com/russross/blackfriday/v2; patch only the build-stage source copy.
RUN test -f main.go && test -f vulndap.cfg-sample && \
    find . -name '*.go' -type f -exec sed -i \
      's|gopkg.in/russross/blackfriday.v2|github.com/russross/blackfriday/v2|g' {} + && \
    if [ ! -f go.mod ]; then go mod init github.com/digininja/vuLnDAP; fi && \
    go mod tidy && CGO_ENABLED=0 go build -o /out/vulndap .

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /src/ /app/
COPY --from=builder /out/vulndap /app/vulndap
# The application expects its config in the working directory.
RUN cp /app/vulndap.cfg-sample /app/vulndap.cfg && \
    chmod 755 /app/vulndap
EXPOSE 9090
CMD ["/app/vulndap"]
EOF
  write_managed "$dir/docker-compose.yml" <<'EOF'
# Generated by VulnMachinesCTL. Source: https://github.com/digininja/vuLnDAP
services:
  vulndap:
    build:
      context: .
    ports:
      - "127.0.0.1:${VULNDAP_PORT:-9093}:9090"
    restart: "no"
EOF
  make_env "$dir"
  warn "[vulndap] upstream GPL-3.0 application; build requires fetching Go dependencies."
}
lab_vulndap_wait_url() { printf 'http://127.0.0.1:%s/' "$(env_val vulndap VULNDAP_PORT 9093)"; }
lab_vulndap_access() {
  local p; p="$(env_val vulndap VULNDAP_PORT 9093)"
  acc_head "vuLnDAP (LDAP business-logic training)"
  acc_url "Web:" "http://127.0.0.1:$p/"
  acc_note "Local reverse proxy URL (if enabled): http://vulndap"
  acc_note "Embedded LDAP listens inside the container; it is not exposed on the host."
  acc_note "Upstream repository: https://github.com/digininja/vuLnDAP (GPL-3.0)."
}

# ── VulnerableApp ────────────────────────────────────────────────────────────
lab_vulnerableapp_install() {
  local dir=$1
  write_managed "$dir/.env.example" <<'EOF'
# Ports bound ONLY to 127.0.0.1
VULNERABLEAPP_PORT=8082
VULNERABLEAPP_MAILPIT_PORT=8026
EOF
  write_managed "$dir/docker-compose.yml" <<'EOF'
# Generated by vulnmachinesctl.sh. Based on docker-compose.without_llm.yml from
# https://github.com/SasanLabs/VulnerableApp (without LLMForge/Ollama).
# Differences: ports only on 127.0.0.1 and remapped; MongoDB is not published;
# do not mount ./templates (the facade image already includes nginx templates).
services:
  VulnerableApp-base:
    image: sasanlabs/owasp-vulnerableapp:latest

  VulnerableApp-jsp:
    image: sasanlabs/owasp-vulnerableapp-jsp:latest

  VulnerableApp-php:
    image: sasanlabs/owasp-vulnerableapp-php:latest
    depends_on:
      - mongodb

  mongodb:
    image: mongo:8.0.12
    volumes:
      - mongodb_data:/data/db

  mailpit:
    image: axllent/mailpit:v1.30.1
    environment:
      - MP_MAX_MESSAGES=5000
      - MP_DATABASE=/data/mailpit.db
      - MP_SMTP_AUTH_ACCEPT_ANY=1
      - MP_SMTP_AUTH_ALLOW_INSECURE=1
      - MP_WEBROOT=/mailpit
    ports:
      - "127.0.0.1:${VULNERABLEAPP_MAILPIT_PORT:-8026}:8025"
    volumes:
      - mailpit_data:/data

  VulnerableApp-facade:
    image: sasanlabs/owasp-vulnerableapp-facade:latest
    depends_on:
      - VulnerableApp-base
      - VulnerableApp-jsp
      - VulnerableApp-php
      - mailpit
    environment:
      - NGINX_HOST=foobar.com
      - NGINX_PORT=80
      - ENABLE_VULNERABLEAPP_JSP=true
      - ENABLE_VULNERABLEAPP_PHP=true
      - ENABLE_LLMFORGE=false
    ports:
      - "127.0.0.1:${VULNERABLEAPP_PORT:-8082}:80"

volumes:
  mongodb_data:
  mailpit_data:
EOF
  make_env "$dir"
}
lab_vulnerableapp_wait_url() { printf 'http://127.0.0.1:%s/' "$(env_val vulnerableapp VULNERABLEAPP_PORT 8082)"; }
lab_vulnerableapp_access() {
  local p; p="$(env_val vulnerableapp VULNERABLEAPP_PORT 8082)"
  acc_head "VulnerableApp"
  acc_url "Web (facade):" "http://127.0.0.1:$p"
  acc_url "Mailpit:" "http://127.0.0.1:$p/mailpit/   (directo: http://127.0.0.1:$(env_val vulnerableapp VULNERABLEAPP_MAILPIT_PORT 8026)/mailpit/)"
  acc_cred "Credentials:" "no login: each challenge has its own forms"
}

# ── XVWA ─────────────────────────────────────────────────────────────────────
lab_xvwa_install() {
  local dir=$1
  clone_repo "https://github.com/SVelizDonoso/xvwa.git" "$dir/repo" master
  write_managed "$dir/.env.example" <<'EOF'
# Port bound ONLY to 127.0.0.1
XVWA_PORT=8083
XVWA_DB_ROOT_PASSWORD=xvwa_root_pass
EOF
  write_managed "$dir/php-xvwa.ini" <<'EOF'
file_uploads = On
allow_url_fopen = On
allow_url_include = On
display_errors = On
; XVWA pages use ISO-8859-1 (and declare
 ; <meta charset="iso-8859-1">). PHP 7.4 defaults to UTF-8, so
 ; the HTTP header can conflict with the source encoding. Match the files.
default_charset = "ISO-8859-1"
auto_prepend_file = /usr/local/etc/php/xvwa-compat.php
EOF
  write_managed "$dir/patch-config.sh" <<'EOF'
#!/bin/sh
# Point XVWA config.php at the container database 'db'.
set -eu
f="$1"
sed -i -E 's/^([[:space:]]*\$host[[:space:]]*=[[:space:]]*).*$/\1"db";/' "$f"
sed -i -E 's/^([[:space:]]*\$user[[:space:]]*=[[:space:]]*).*$/\1"xvwa";/' "$f"
sed -i -E 's/^([[:space:]]*\$pass[[:space:]]*=[[:space:]]*).*$/\1"xvwa_db_pass";/' "$f"
for v in host user pass; do
  grep -Eq "^[[:space:]]*\\\$$v[[:space:]]*=[[:space:]]*\"" "$f" || { echo "Could not patch \$$v en $f" >&2; exit 1; }
done
# XVWA source files use Latin-1. Using utf8mb4 makes the INSERT of
# setup products fail (MariaDB strict mode), and the page ends in
# mysql_error(). Force latin1 in mysqli and PDO.
sed -i -E 's/^([[:space:]]*\$conn[[:space:]]*=[[:space:]]*new mysqli\(.*\);)[[:space:]]*$/\1 $conn->set_charset("latin1");/' "$f"
sed -i -E 's/dbname=\$dbname"/dbname=$dbname;charset=latin1"/' "$f"
grep -q 'set_charset("latin1")' "$f" || { echo "Could not set latin1 in mysqli ($f)" >&2; exit 1; }
grep -q 'charset=latin1' "$f" || { echo "Could not set latin1 in PDO ($f)" >&2; exit 1; }
EOF
  write_managed "$dir/xvwa-compat.php" <<'EOF'
<?php
// PHP 7+ compatibility: XVWA (setup/home.php) llama a mysql_error(), removed
// en PHP 7.0. Without this, any setup error ends in "Call to undefined
// function mysql_error()" and hides the actual MariaDB error.
if (!function_exists('mysql_error')) {
    function mysql_error() {
        global $conn;
        return (isset($conn) && $conn instanceof mysqli) ? $conn->error : '';
    }
}
EOF
  write_managed "$dir/Dockerfile" <<'EOF'
# Generated by vulnmachinesctl.sh. XVWA has no official Docker image; this is a custom build.
# PHP 7.4 is end-of-life: this is intentional (the app was built for that era) pero
# never expose outside localhost.
FROM php:7.4-apache
# 1) Database extensions required by XVWA (config.php uses both mysqli and PDO).
#    They require no OS packages, so this build layer does not depend on apt.
#    mbstring, DOM, SimpleXML and curl already ship in the official PHP image.
RUN docker-php-ext-install -j"$(nproc)" mysqli pdo pdo_mysql
# 2) GD (used by CAPTCHA and FCKeditor thumbnails). php:7.4 es Debian
#    bullseye, now archived: deb.debian.org may return 404, so
#    point to archive.debian.org. If it still fails, warn and continue without
#    GD (the rest of the lab works; CAPTCHA will not).
RUN set -eux; \
    for f in /etc/apt/sources.list /etc/apt/sources.list.d/*; do \
      [ -f "$f" ] || continue; \
      sed -i -e 's|deb.debian.org/debian-security|archive.debian.org/debian-security|g' \
             -e 's|security.debian.org/debian-security|archive.debian.org/debian-security|g' \
             -e 's|deb.debian.org/debian|archive.debian.org/debian|g' \
             -e '/bullseye-updates/d' "$f"; \
    done; \
    ( apt-get -o Acquire::Check-Valid-Until=false update \
      && apt-get install -y --no-install-recommends libpng-dev libjpeg-dev libfreetype6-dev \
      && docker-php-ext-configure gd --with-freetype --with-jpeg \
      && docker-php-ext-install -j"$(nproc)" gd \
    ) || echo "AVISO: could not install GD; XVWA CAPTCHA will not work."; \
    rm -rf /var/lib/apt/lists/*
COPY php-xvwa.ini /usr/local/etc/php/conf.d/xvwa.ini
COPY xvwa-compat.php /usr/local/etc/php/xvwa-compat.php
COPY repo/ /var/www/html/xvwa/
COPY patch-config.sh /tmp/patch-config.sh
RUN sh /tmp/patch-config.sh /var/www/html/xvwa/config.php \
 && rm /tmp/patch-config.sh \
 && chown -R www-data:www-data /var/www/html/xvwa
EOF
  write_managed "$dir/.dockerignore" <<'EOF'
.env
repo/.git
docker-compose.yml
EOF
  write_managed "$dir/docker-compose.yml" <<'EOF'
# Generated by vulnmachinesctl.sh (custom configuration; XVWA has no official Docker setup).
services:
  web:
    build: .
    depends_on:
      - db
    ports:
      - "127.0.0.1:${XVWA_PORT:-8083}:80"

  db:
    image: mariadb:10
    environment:
      MYSQL_ROOT_PASSWORD: ${XVWA_DB_ROOT_PASSWORD:-xvwa_root_pass}
      MYSQL_DATABASE: xvwa
      MYSQL_USER: xvwa
      MYSQL_PASSWORD: xvwa_db_pass
    volumes:
      - xvwa-db:/var/lib/mysql

volumes:
  xvwa-db:
EOF
  make_env "$dir"
}
lab_xvwa_wait_url() { printf 'http://127.0.0.1:%s/xvwa/' "$(env_val xvwa XVWA_PORT 8083)"; }
lab_xvwa_access() {
  local p; p="$(env_val xvwa XVWA_PORT 8083)"
  acc_head "XVWA"
  acc_url "Web:" "http://127.0.0.1:$p/xvwa/"
  acc_url "Setup (create database):" "http://127.0.0.1:$p/xvwa/setup/   <- open this on first run"
  acc_cred "admin:" "admin / admin"
  acc_cred "user:" "xvwa / xvwa"
  acc_cred "user:" "user / vulnerable"
  acc_note "The path /xvwa/ is required (the port root $p is not the app). XVWA es Apache/PHP, no Tomcat."
  acc_note "A Tomcat 404 ('Type Status Report') means you are on el 8089 (WebGoat) o el 8088 (WebGoat 7.1), not XVWA."
}

# ── WebGoat ──────────────────────────────────────────────────────────────────
lab_webgoat_install() {
  local dir=$1
  write_managed "$dir/.env.example" <<'EOF'
# Ports bound ONLY to 127.0.0.1
WEBGOAT_PORT=8089
WEBWOLF_PORT=9090
TZ=Europe/Madrid
EOF
  write_managed "$dir/docker-compose.yml" <<'EOF'
# Generated by vulnmachinesctl.sh. Source: https://github.com/WebGoat/WebGoat
# Equivale a: docker run -p 127.0.0.1:8089:8080 -p 127.0.0.1:9090:9090 webgoat/webgoat
# (8089 instead of 8080, leaving port 8080 available for Burp Suite)
services:
  webgoat:
    image: webgoat/webgoat:latest
    environment:
      - TZ=${TZ:-Europe/Madrid}
    ports:
      - "127.0.0.1:${WEBGOAT_PORT:-8089}:8080"
      - "127.0.0.1:${WEBWOLF_PORT:-9090}:9090"
EOF
  make_env "$dir"
}
lab_webgoat_wait_url() { printf 'http://127.0.0.1:%s/WebGoat/' "$(env_val webgoat WEBGOAT_PORT 8089)"; }
lab_webgoat_access() {
  acc_head "WebGoat"
  acc_url "WebGoat:" "http://127.0.0.1:$(env_val webgoat WEBGOAT_PORT 8089)/WebGoat/"
  acc_url "WebWolf:" "http://127.0.0.1:$(env_val webgoat WEBWOLF_PORT 9090)/WebWolf/"
  acc_cred "Credentials:" "no default user: create an account on the login page"
}

# ── WebGoat 7.1 ──────────────────────────────────────────────────────────────
lab_webgoat7_install() {
  local dir=$1
  write_managed "$dir/.env.example" <<'EOF'
# Port bound ONLY to 127.0.0.1. Port 8088 allows running alongside
# laboratorio 'webgoat' (latest version), which uses 8089. Port 8080 stays free (Burp).
WEBGOAT7_PORT=8088
EOF
  write_managed "$dir/docker-compose.yml" <<'EOF'
# Generated by vulnmachinesctl.sh. Image: https://hub.docker.com/r/webgoat/webgoat-7.1
# Equivale a: docker run -p 8080:8080 -t webgoat/webgoat-7.1
services:
  webgoat7:
    image: webgoat/webgoat-7.1
    ports:
      - "127.0.0.1:${WEBGOAT7_PORT:-8088}:8080"
EOF
  make_env "$dir"
  warn "  WebGoat 7.1 is a legacy image (unmaintained for years): use localhost only."
}
lab_webgoat7_wait_url() { printf 'http://127.0.0.1:%s/WebGoat/' "$(env_val webgoat7 WEBGOAT7_PORT 8088)"; }
lab_webgoat7_access() {
  acc_head "WebGoat 7.1"
  acc_url "WebGoat:" "http://127.0.0.1:$(env_val webgoat7 WEBGOAT7_PORT 8088)/WebGoat/   (enter the path /WebGoat/)"
  acc_cred "Login:" "guest / guest   (from a third-party guide; not documented on Docker Hub)"
}

# ── Juice Shop ───────────────────────────────────────────────────────────────
lab_juice_shop_install() {
  local dir=$1
  write_managed "$dir/.env.example" <<'EOF'
# Port bound ONLY to 127.0.0.1. Es 3100 (no 3000) to avoid conflicting with el
# laboratorio oauth2, whose redirect URLs require port 3000.
JUICE_SHOP_PORT=3100
EOF
  write_managed "$dir/docker-compose.yml" <<'EOF'
# Generated by vulnmachinesctl.sh. Source: https://github.com/juice-shop/juice-shop
services:
  juice-shop:
    image: bkimminich/juice-shop:latest
    ports:
      - "127.0.0.1:${JUICE_SHOP_PORT:-3100}:3000"
EOF
  make_env "$dir"
}
lab_juice_shop_wait_url() { printf 'http://127.0.0.1:%s/' "$(env_val juice-shop JUICE_SHOP_PORT 3100)"; }
lab_juice_shop_access() {
  acc_head "Juice Shop"
  acc_url "Web:" "http://127.0.0.1:$(env_val juice-shop JUICE_SHOP_PORT 3100)"
  acc_cred "Credentials:" "no default user: register in the store (Account > Login > Not yet a customer?)"
  acc_note "The image is 'distroless': 'shell' will not work for this lab."
}

# ── DVWA ─────────────────────────────────────────────────────────────────────
lab_dvwa_install() {
  local dir=$1
  write_managed "$dir/.env.example" <<'EOF'
# Port bound ONLY to 127.0.0.1
DVWA_PORT=4280
EOF
  write_managed "$dir/docker-compose.yml" <<'EOF'
# Generated by vulnmachinesctl.sh. Based on compose.yml from https://github.com/digininja/DVWA
# The database credentials are DVWA defaults (do not change).
services:
  dvwa:
    image: ghcr.io/digininja/dvwa:latest
    pull_policy: missing
    environment:
      - DB_SERVER=db
    depends_on:
      - db
    networks:
      - dvwa
    ports:
      - "127.0.0.1:${DVWA_PORT:-4280}:80"

  db:
    image: docker.io/library/mariadb:10
    environment:
      - MYSQL_ROOT_PASSWORD=dvwa
      - MYSQL_DATABASE=dvwa
      - MYSQL_USER=dvwa
      - MYSQL_PASSWORD=p@ssw0rd
    volumes:
      - dvwa:/var/lib/mysql
    networks:
      - dvwa

volumes:
  dvwa:

networks:
  dvwa:
EOF
  make_env "$dir"
}
lab_dvwa_wait_url() { printf 'http://127.0.0.1:%s/' "$(env_val dvwa DVWA_PORT 4280)"; }
lab_dvwa_access() {
  acc_head "DVWA"
  acc_url "Web:" "http://127.0.0.1:$(env_val dvwa DVWA_PORT 4280)"
  acc_cred "Login:" "admin / password"
  acc_note "First run: 'Setup DVWA' > 'Create / Reset Database', then log in again."
  acc_note "The port is $(env_val dvwa DVWA_PORT 4280), not 80 nor 8080from the DVWA docs."
  acc_note "A Tomcat 404 ('Type Status Report') means you are on el 8089 (WebGoat) o el 8088 (WebGoat 7.1), not DVWA."
  acc_cred "Base de datos:" "dvwa / p@ssw0rd (database dvwa, interna)"
}

# ── Mutillidae ───────────────────────────────────────────────────────────────
lab_mutillidae_install() {
  local dir=$1
  clone_repo "https://github.com/webpwnized/mutillidae-docker.git" "$dir/repo" main
  [[ -d $dir/repo/.build/www ]] \
    || die "mutillidae-docker is missing .build/www (did its structure change?)" 1
  write_managed "$dir/.env.example" <<'EOF'
# Ports bound ONLY to 127.0.0.1 (remapeados to avoid conflicting with otros labs)
MUTILLIDAE_PORT=8084
MUTILLIDAE_TLS_PORT=8444
MUTILLIDAE_PMA_PORT=8085
MUTILLIDAE_LDAPADMIN_PORT=8086
MUTILLIDAE_LDAP_PORT=3890
EOF
  write_managed "$dir/docker-compose.yml" <<'EOF'
# Generated by vulnmachinesctl.sh. Based on .build/docker-compose.yml de
# https://github.com/webpwnized/mutillidae-docker (5 contenedores, build local).
# Changes: puertos remapeados (80/443/81/82/389 -> variables .env) and without
# nombres de imagen/contenedor fijos.
services:
  database:
    build: ./repo/.build/database
    networks:
      - datanet

  database_admin:
    build: ./repo/.build/database_admin
    depends_on:
      - database
    networks:
      - datanet
    ports:
      - "127.0.0.1:${MUTILLIDAE_PMA_PORT:-8085}:80"

  www:
    build: ./repo/.build/www
    depends_on:
      - database
      - directory
    networks:
      - datanet
      - ldapnet
    ports:
      - "127.0.0.1:${MUTILLIDAE_PORT:-8084}:80"
      - "127.0.0.1:${MUTILLIDAE_TLS_PORT:-8444}:443"

  directory:
    build: ./repo/.build/ldap
    volumes:
      - ldap_data:/var/lib/ldap
      - ldap_config:/etc/ldap/slapd.d
    networks:
      - ldapnet
    ports:
      - "127.0.0.1:${MUTILLIDAE_LDAP_PORT:-3890}:389"

  directory_admin:
    build: ./repo/.build/ldap_admin
    depends_on:
      - directory
    networks:
      - ldapnet
    ports:
      - "127.0.0.1:${MUTILLIDAE_LDAPADMIN_PORT:-8086}:80"

volumes:
  ldap_data:
  ldap_config:

networks:
  datanet:
  ldapnet:
EOF
  make_env "$dir"
}
lab_mutillidae_wait_url() { printf 'http://127.0.0.1:%s/' "$(env_val mutillidae MUTILLIDAE_PORT 8084)"; }
lab_mutillidae_access() {
  acc_head "Mutillidae II"
  local mp; mp="$(env_val mutillidae MUTILLIDAE_PORT 8084)"
  acc_url "Web:" "http://127.0.0.1:$mp   (alternativa: http://mutillidae.localhost:$mp)"
  acc_note "NOTE: Mutillidae docs mention ports 80/81/82/8080; here they are remapped (see URLs)."
  acc_note "El 8089 belongs to WebGoat, not Mutillidae (Mutillidae uses Apache/PHP; a Tomcat 404 indicates another lab)."
  acc_note "First run: if the database is missing, click 'rebuild' or run: curl http://127.0.0.1:$mp/set-up-database.php"
  acc_url "phpMyAdmin:" "http://127.0.0.1:$(env_val mutillidae MUTILLIDAE_PMA_PORT 8085)"
  acc_url "phpLDAPadmin:" "http://127.0.0.1:$(env_val mutillidae MUTILLIDAE_LDAPADMIN_PORT 8086)"
  acc_cred "LDAP admin:" "cn=admin,dc=mutillidae,dc=localhost / mutillidae"
  acc_note "App and phpMyAdmin credentials are unverified (not documented in the mutillidae-docker README)."
  acc_note "The LDAP directory starts empty: see the mutillidae-docker README (ldapadd with .build/ldap/configuration/ldif/mutillidae.ldif)."
}

# ── DVGA ─────────────────────────────────────────────────────────────────────
lab_dvga_install() {
  local dir=$1
  write_managed "$dir/.env.example" <<'EOF'
# Port bound ONLY to 127.0.0.1
DVGA_PORT=5013
EOF
  write_managed "$dir/docker-compose.yml" <<'EOF'
# Generated by vulnmachinesctl.sh. Source: https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application
# Equivale a: docker run -p 5013:5013 -e WEB_HOST=0.0.0.0 dolevf/dvga
# (WEB_HOST=0.0.0.0 applies inside the container; the host binds only to 127.0.0.1)
services:
  dvga:
    image: dolevf/dvga:latest
    environment:
      - WEB_HOST=0.0.0.0
      - WEB_PORT=5013
    ports:
      - "127.0.0.1:${DVGA_PORT:-5013}:5013"
EOF
  make_env "$dir"
}
lab_dvga_wait_url() { printf 'http://127.0.0.1:%s/' "$(env_val dvga DVGA_PORT 5013)"; }
lab_dvga_access() {
  acc_head "DVGA"
  acc_url "Web:" "http://127.0.0.1:$(env_val dvga DVGA_PORT 5013)"
  acc_url "GraphQL:" "http://127.0.0.1:$(env_val dvga DVGA_PORT 5013)/graphql"
  acc_cred "Credentials:" "no documented login (switch Beginner/Expert mode in the web UI)"
}

# ── VulnBank ─────────────────────────────────────────────────────────────────
lab_vulnbank_install() {
  local dir=$1
  clone_repo "https://github.com/Commando-X/vuln-bank.git" "$dir/repo" main
  write_managed "$dir/.env.example" <<'EOF'
# Port bound ONLY to 127.0.0.1
VULNBANK_PORT=5000
EOF
  write_managed "$dir/docker-compose.yml" <<'EOF'
# Generated by vulnmachinesctl.sh. Based on docker-compose.yml de
# https://github.com/Commando-X/vuln-bank
# Differences: port bound to 127.0.0.1 (upstream publishes ports 5000 and 80 and the database on
# all interfaces) WITHOUT the autoheal service, which mounts /var/run/docker.sock
# (unnecessary privilege). PostgreSQL is not published.
services:
  web:
    build: ./repo
    restart: "no"
    environment:
      - DB_NAME=vulnerable_bank
      - DB_USER=postgres
      - DB_PASSWORD=postgres
      - DB_HOST=db
      - DB_PORT=5432
    ports:
      - "127.0.0.1:${VULNBANK_PORT:-5000}:5000"
    volumes:
      - ./repo/static/uploads:/app/static/uploads
    depends_on:
      db:
        condition: service_healthy
    networks:
      - vuln_network

  db:
    image: postgres:13
    restart: "no"
    environment:
      - POSTGRES_DB=vulnerable_bank
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres -d vulnerable_bank"]
      interval: 10s
      timeout: 5s
      retries: 5
      start_period: 10s
    networks:
      - vuln_network

volumes:
  postgres_data:

networks:
  vuln_network:
    driver: bridge
EOF
  make_env "$dir"
}
lab_vulnbank_wait_url() { printf 'http://127.0.0.1:%s/healthz' "$(env_val vulnbank VULNBANK_PORT 5000)"; }
lab_vulnbank_open_url() { printf 'http://127.0.0.1:%s/' "$(env_val vulnbank VULNBANK_PORT 5000)"; }
lab_vulnbank_access() {
  local p; p="$(env_val vulnbank VULNBANK_PORT 5000)"
  acc_head "VulnBank"
  acc_url "Web:" "http://127.0.0.1:$p"
  acc_url "Docs de la API:" "http://127.0.0.1:$p/api/docs"
  acc_url "GraphQL:" "http://127.0.0.1:$p/graphql"
  acc_cred "Credentials:" "no documented users: register in the app"
  acc_cred "PostgreSQL (interna):" "postgres / postgres (database vulnerable_bank)"
}

# ── vAPI ─────────────────────────────────────────────────────────────────────
lab_vapi_install() {
  local dir=$1
  clone_repo "https://github.com/roottusk/vapi.git" "$dir/repo" master
  write_managed "$dir/.env.example" <<'EOF'
# Port bound ONLY to 127.0.0.1
VAPI_PORT=8000
EOF
  write_managed "$dir/docker-compose.yml" <<'EOF'
# Generated by vulnmachinesctl.sh. Based on docker-compose.yml from https://github.com/roottusk/vapi
# Differences: bound only to 127.0.0.1; MySQL (3306) and phpMyAdmin are not published;
# empty upstream variables (AWS, Pusher) are omitted.
services:
  www:
    build: ./repo
    depends_on:
      - db
    ports:
      - "127.0.0.1:${VAPI_PORT:-8000}:80"
    volumes:
      - ./repo/vapi:/var/www/html/vapi
    environment:
      APP_NAME: Laravel
      APP_ENV: local
      APP_KEY: "base64:JUXTsCKQubRlvxGv6sVwkFL2rJ/gSksD4B/68948Mww:"
      APP_DEBUG: "true"
      APP_URL: http://vapi.test
      SERVER_PORT: 80
      LOG_CHANNEL: errorlog
      LOG_LEVEL: debug
      DB_CONNECTION: mysql
      DB_HOST: db
      DB_PORT: 3306
      DB_DATABASE: vapi
      DB_USERNAME: root
      DB_PASSWORD: vapi123456
      BROADCAST_DRIVER: log
      CACHE_DRIVER: file
      FILESYSTEM_DRIVER: local
      QUEUE_CONNECTION: sync
      SESSION_DRIVER: file
      SESSION_LIFETIME: 120

  db:
    image: mysql:8.0
    command: --default-authentication-plugin=mysql_native_password
    environment:
      MYSQL_DATABASE: vapi
      MYSQL_USER: vapi
      MYSQL_PASSWORD: vapi123456
      MYSQL_ROOT_PASSWORD: vapi123456
    volumes:
      - ./repo/database:/docker-entrypoint-initdb.d
      - ./repo/conf:/etc/mysql/conf.d
      - persistent:/var/lib/mysql

volumes:
  persistent:
EOF
  make_env "$dir"
}
lab_vapi_wait_url() { printf 'http://127.0.0.1:%s/vapi/' "$(env_val vapi VAPI_PORT 8000)"; }
lab_vapi_access() {
  acc_head "vAPI"
  acc_url "Documentation/API:" "http://127.0.0.1:$(env_val vapi VAPI_PORT 8000)/vapi/"
  acc_cred "Credentials:" "no fixed login: follow the Postman collection workflow (vAPI.postman_collection.json in repo/)"
  acc_cred "MySQL (interna):" "root / vapi123456 (database vapi)"
  acc_note "Postman collection and environment: $LABS_ROOT/vapi/repo/ (also at postman.com/roottusk/workspace/vapi)."
}

# ── VulnLab (Yavuzlar) ───────────────────────────────────────────────────────
lab_vulnlab_install() {
  local dir=$1
  write_managed "$dir/.env.example" <<'EOF'
# Port bound ONLY to 127.0.0.1. Use 8087 instead of 1337 (upstream README) to avoid
# conflicting with the oauth2 lab attacker service.
VULNLAB_PORT=8087
EOF
  write_managed "$dir/docker-compose.yml" <<'EOF'
# Generated by vulnmachinesctl.sh. Source: https://github.com/Yavuzlar/VulnLab
# README: docker run --name vulnlab -d -p 1337:80 yavuzlar/vulnlab:latest
# A single container (Apache + PHP + MariaDB); data is kept inside the
# container, with no volume: 'down' + 'up' resets the lab from scratch.
services:
  vulnlab:
    image: yavuzlar/vulnlab:latest
    ports:
      - "127.0.0.1:${VULNLAB_PORT:-8087}:80"
EOF
  make_env "$dir"
  warn "  VulnLab is based on ubuntu:20.04 (end of support) with a passwordless MariaDB root user: localhost only."
}
lab_vulnlab_wait_url() { printf 'http://127.0.0.1:%s/' "$(env_val vulnlab VULNLAB_PORT 8087)"; }
lab_vulnlab_access() {
  acc_head "VulnLab (Yavuzlar)"
  acc_url "Web:" "http://127.0.0.1:$(env_val vulnlab VULNLAB_PORT 8087)"
  acc_cred "Credentials:" "not documented in the README; challenges have their own login/registration"
  acc_note "Internal database: sql_injection user without a password (according to upstream run.sh)."
}

# ── OAuth 2.0 (koenbuyens) ───────────────────────────────────────────────────
# Upstream pins array-set@0.1.2, whose npm tarball is no longer available.
# Remove that obsolete direct dependency from BOTH npm manifests before build.
# This affects the local cloned lab only and is safe to run more than once.
lab_oauth2_patch_dependencies() {
  local dir="$LABS_ROOT/oauth2/repo/insecureapplication/gallery"
  [[ -f $dir/package.json ]] || die "[oauth2] gallery/package.json was not found." 1
  command -v python3 >/dev/null 2>&1 \
    || die "[oauth2] python3 is needed to repair upstream npm manifests." 3
  python3 -I - "$dir" <<'PYEOF'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
updated = []
for name, section in (("package.json", "dependencies"),
                      ("package-lock.json", "dependencies")):
    path = root / name
    if not path.is_file():
        continue
    data = json.loads(path.read_text(encoding="utf-8"))
    deps = data.get(section, {})
    if "array-set" in deps:
        del deps["array-set"]
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        updated.append(name)
if updated:
    print("[oauth2] removed unavailable array-set@0.1.2 from " + ", ".join(updated))
PYEOF
}

# The upstream mongo-seed Dockerfile uses mongo:latest, whose modern
# mongorestore cannot talk to the pinned MongoDB 4.0 server (wire version 7).
# Use matching MongoDB 4.0 database tools and mount upstream dump files read-only.
# Update ONLY the exact Compose fragment from earlier VulnMachinesCTL releases.
lab_oauth2_patch_mongoseed() {
  local file="$LABS_ROOT/oauth2/docker-compose.yml"
  [[ -f $file ]] || die "[oauth2] docker-compose.yml was not found." 1
  command -v python3 >/dev/null 2>&1 \
    || die "[oauth2] python3 is required to repair MongoDB seeding." 3
  python3 -I - "$file" <<'PYEOF'
from pathlib import Path
import sys

path = Path(sys.argv[1])
compose = path.read_text(encoding="utf-8")
old = """  mongoseed:
    build: ./repo/insecureapplication/mongo-seed
    restart: "no"
    command: mongorestore --host mongodb:27017 -d gallery2 mongodbdata/gallery2
    depends_on:
"""
new = """  mongoseed:
    image: mongo:4.0
    restart: "no"
    volumes:
      - ./repo/insecureapplication/mongo-seed/mongodbdata:/mongodbdata:ro
    command: mongorestore --host mongodb:27017 -d gallery2 /mongodbdata/gallery2
    depends_on:
"""
if old in compose:
    path.write_text(compose.replace(old, new, 1), encoding="utf-8")
    print("[oauth2] switched mongoseed to MongoDB 4.0 compatible tools")
elif new not in compose:
    print("[oauth2] custom mongoseed configuration: not modified", file=sys.stderr)
PYEOF
}

lab_oauth2_install() {
  local dir=$1
  clone_repo "https://github.com/koenbuyens/Vulnerable-OAuth-2.0-Applications.git" "$dir/repo" master
  [[ -d $dir/repo/insecureapplication/gallery ]] \
    || die "Missing insecureapplication/gallery in the repository (did its structure change?)" 1
  write_managed "$dir/.env.example" <<'EOF'
# Ports bound ONLY to 127.0.0.1. Do NOT change them when using the host browser
# browser: application redirect URLs use these fixed ports.
OAUTH2_PHOTOPRINT_PORT=3000
OAUTH2_GALLERY_PORT=3005
OAUTH2_ATTACKER_PORT=1337
OAUTH2_VNC_PORT=5900
OAUTH2_SELENIUM_PORT=4444
EOF
  write_managed "$dir/docker-compose.yml" <<'EOF'
# Generated by vulnmachinesctl.sh. Based on insecureapplication/docker-compose.yml from
# https://github.com/koenbuyens/Vulnerable-OAuth-2.0-Applications
# Differences: ports bound to 127.0.0.1; MongoDB is internal and pinned to
# mongo:4.0 (upstream uses mongo:latest with --smallfiles, a flag removed in
# MongoDB 4.2); MongoDB healthcheck ensures seeding waits for readiness.
services:
  mongodb:
    image: mongo:4.0
    healthcheck:
      test: ["CMD", "mongo", "--quiet", "--eval", "db.adminCommand('ping')"]
      interval: 10s
      timeout: 5s
      retries: 12
      start_period: 10s

  mongoseed:
    image: mongo:4.0
    restart: "no"
    volumes:
      - ./repo/insecureapplication/mongo-seed/mongodbdata:/mongodbdata:ro
    command: mongorestore --host mongodb:27017 -d gallery2 /mongodbdata/gallery2
    depends_on:
      mongodb:
        condition: service_healthy

  gallery:
    build: ./repo/insecureapplication/gallery
    ports:
      - "127.0.0.1:${OAUTH2_GALLERY_PORT:-3005}:3005"
    depends_on:
      mongoseed:
        condition: service_completed_successfully

  photoprint:
    build: ./repo/insecureapplication/photoprint
    ports:
      - "127.0.0.1:${OAUTH2_PHOTOPRINT_PORT:-3000}:3000"
    depends_on:
      - gallery

  attacker:
    build: ./repo/insecureapplication/attacker
    ports:
      - "127.0.0.1:${OAUTH2_ATTACKER_PORT:-1337}:1337"
    depends_on:
      - gallery
      - photoprint

  selenium:
    image: selenium/standalone-firefox-debug:latest
    ports:
      - "127.0.0.1:${OAUTH2_SELENIUM_PORT:-4444}:4444"
      - "127.0.0.1:${OAUTH2_VNC_PORT:-5900}:5900"
EOF
  make_env "$dir"
}
lab_oauth2_wait_url() { printf 'http://127.0.0.1:%s/' "$(env_val oauth2 OAUTH2_GALLERY_PORT 3005)"; }
# Open photoprint (the OAuth client) by IP to avoid changing /etc/hosts,
#although OAuth redirects require the hostnames gallery/photoprint/attacker.
lab_oauth2_open_url() { printf 'http://127.0.0.1:%s/' "$(env_val oauth2 OAUTH2_PHOTOPRINT_PORT 3000)"; }
lab_oauth2_access() {
  acc_head "OAuth 2.0 vulnerable (gallery / photoprint / attacker)"
  acc_url "photoprint (client):" "http://photoprint:$(env_val oauth2 OAUTH2_PHOTOPRINT_PORT 3000)"
  acc_url "gallery (server):" "http://gallery:$(env_val oauth2 OAUTH2_GALLERY_PORT 3005)"
  acc_url "attacker:" "http://attacker:$(env_val oauth2 OAUTH2_ATTACKER_PORT 1337)"
  acc_cred "Login photoprint:" "koen / password"
  acc_cred "VNC (Firefox):" "127.0.0.1:$(env_val oauth2 OAUTH2_VNC_PORT 5900)  password: secret"
  acc_note "Option A (without changing the host): connect by VNC and open http://photoprint:3000 in the container's Firefox."
  acc_note "Short names are managed automatically when the local proxy is enabled."
  acc_note "Legacy OAuth redirect URLs may still include ports (3000/3005/1337)."
}

# ─────────────────────────────────────────────────────────────────────────────
# 4. Shared logic
# ─────────────────────────────────────────────────────────────────────────────

require_git() {
  command -v git >/dev/null 2>&1 || die "Git is not installed (required for this lab)." 3
}

require_docker() {
  command -v docker >/dev/null 2>&1 || die "Docker is missing or not on PATH." 3
  docker compose version >/dev/null 2>&1 \
    || die "Docker Compose v2 is required (plugin 'docker compose'). Compose v1 is unsupported." 3
  local out
  if ! out="$(docker info 2>&1 >/dev/null)"; then
    if grep -qi 'permission denied' <<<"$out"; then
      die "Docker permission denied. Add your user to the docker group (this script does not use sudo)." 3
    fi
    die "Cannot connect to the Docker daemon: ${out:-is it running?}" 3
  fi
}

# docker compose scoped to the lab project.
#   DC_ALL_PROFILES=1 -> includes services with 'profiles' (down/remove/ps/config).
dc() {
  local id=$1; shift
  local file dir
  file="$(lab_compose_file "$id")"
  [[ -f $file ]] || die "[$id] Compose file not found: $file (run: $PROG install $id)"
  dir="$(dirname -- "$file")"
  local -a args=(compose)
  [[ $id == crapi ]] && args+=(--compatibility)
  [[ -n ${DC_ALL_PROFILES:-} ]] && args+=(--profile '*')
  args+=(--project-name "${PROJECT_PREFIX}-${id}" --project-directory "$dir" -f "$file")
  if [[ $id == crapi ]]; then
    LISTEN_IP=127.0.0.1 docker "${args[@]}" "$@"   # force localhost-only port binding
  else
    docker "${args[@]}" "$@"
  fi
}

installed_p() {
  local id=$1
  [[ -f $LABS_ROOT/$id/$INSTALLED_MARKER && -f "$(lab_compose_file "$id")" ]]
}

install_lab() {
  local id=$1 dir="$LABS_ROOT/$1"
  ensure_root
  if installed_p "$id"; then
    # Compatibility repairs are safe to reapply and preserve unrelated settings.
    if [[ $id == vulndap ]]; then
      lab_vulndap_patch_dockerfile
    fi
    if [[ $id == oauth2 ]]; then
      lab_oauth2_patch_dependencies
      lab_oauth2_patch_mongoseed
    fi
    ok "[$id] already installed at $dir (compatibility fixes checked)"
    return 0
  fi
  if [[ -e $dir || -L $dir ]]; then
    [[ -d $dir && ! -L $dir ]] || die "[$id] target exists but is not a regular directory: $dir" 2
    [[ -f $dir/$LAB_MARKER && "$(cat -- "$dir/$LAB_MARKER")" == "$id" ]] \
      || die "[$id] directory is not managed by VulnMachinesCTL: $dir" 2
    warn "[$id] partial installation detected: resuming"
  fi
  [[ ${L_GIT[$id]} == yes ]] && require_git
  mkdir -p -- "$dir"
  printf '%s\n' "$id" >"$dir/$LAB_MARKER"
  info "[$id] installing at $dir"
  "lab_$(key "$id")_install" "$dir"
  [[ -f "$(lab_compose_file "$id")" ]] || die "[$id] Compose file was not generated."
  if [[ $id == vulndap ]]; then
    lab_vulndap_patch_dockerfile
  fi
  if [[ $id == oauth2 ]]; then
    # Apply both legacy compatibility fixes at install time, not just at 'up'.
    lab_oauth2_patch_dependencies
    lab_oauth2_patch_mongoseed
  fi
  date -u +%FT%TZ >"$dir/$INSTALLED_MARKER"
  ok "[$id] installed (containers not started). Run: $PROG up $id"
}

diagnose() {
  local id=$1
  warn "[$id] diagnostics:"
  DC_ALL_PROFILES=1 dc "$id" ps -a 2>&1 | sed 's/^/    /' >&2 || true
  DC_ALL_PROFILES=1 dc "$id" logs --tail=12 2>&1 | sed 's/^/    /' >&2 || true
  warn "[$id] if you see 'address already in use' means the port is busy: change the port in $LABS_ROOT/$id/.env"
  warn "[$id] partially created containers remain: '$PROG down $id' cleans them up (preserves data)"
  warn "[$id] more details: $PROG logs $id"
}

wait_ready() {
  local id=$1 url code deadline
  if ! command -v curl >/dev/null 2>&1; then
    warn "[$id] curl not available: cannot check readiness."
    return 1
  fi
  url="$("lab_$(key "$id")_wait_url")"
  deadline=$(( SECONDS + WAIT_TIMEOUT ))
  info "[$id] waiting for HTTP response at $url (max ${WAIT_TIMEOUT}s)..."
  while (( SECONDS < deadline )); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null || true)"
    if [[ $code =~ ^[234][0-9][0-9]$ ]]; then
      ok "[$id] responding (HTTP $code)"
      return 0
    fi
    sleep 3
  done
  warn "[$id] did not respond within ${WAIT_TIMEOUT}s."
  diagnose "$id"
  return 1
}

# Runtime information from Docker (by project label).
# Populates RT_TOTAL, RT_RUN, RT_HEALTH and RT_PORTS.
runtime_info() {
  local id=$1 proj="${PROJECT_PREFIX}-$1" lines
  RT_TOTAL=0; RT_RUN=0; RT_HEALTH="-"; RT_PORTS="-"
  lines="$(docker ps -a --filter "label=com.docker.compose.project=$proj" \
            --format '{{.State}}|{{.Status}}|{{.Ports}}' 2>/dev/null || true)"
  [[ -n $lines ]] || return 0
  RT_TOTAL="$(grep -c . <<<"$lines")"
  RT_RUN="$(grep -c '^running|' <<<"$lines" || true)"
  if grep -q '(unhealthy)' <<<"$lines"; then RT_HEALTH="unhealthy"
  elif grep -q 'health: starting' <<<"$lines"; then RT_HEALTH="starting"
  elif grep -q '(healthy)' <<<"$lines"; then RT_HEALTH="healthy"
  fi
  local p exposed
  p="$(grep -oE '127\.0\.0\.1:[0-9]+' <<<"$lines" | sed 's/^127\.0\.0\.1://' | sort -un | paste -sd, - || true)"
  exposed="$(grep -oE '(0\.0\.0\.0|\[::\]):[0-9]+' <<<"$lines" | sort -u | paste -sd, - || true)"
  RT_PORTS="${p:--}"
  [[ -z $exposed ]] || RT_PORTS="$RT_PORTS  ⚠ EXPUESTO: $exposed"
}

show_access() {
  local id=$1
  if [[ $PROXY_ENABLED == 1 && -f $(proxy_state_dir)/active/$id ]] \
      && [[ -n "$(proxy_compose ps -q 2>/dev/null)" ]]; then
    acc_head 'Local proxy (short hostname)'
    acc_url 'Browser:' "$(proxy_url_of "$id")"
    [[ $id == oauth2 ]] && {
      acc_url 'Gallery:' 'http://gallery'
      acc_url 'Attacker:' 'http://attacker'
    }
    acc_note 'Legacy application redirects may continue using explicit ports.'
  fi
  "lab_$(key "$id")_access"
  printf '\n'
}

banner_security() {
  warn "INTENTIONALLY vulnerable labs: localhost only (127.0.0.1), never expose to the Internet."
  warn "Default passwords are public; some images are old or unpatched."
}

# Is anything listening on port $2 (127.0.0.1/0.0.0.0/::)?
port_in_use() {
  local port=$2
  if command -v ss >/dev/null 2>&1; then
    ss -H -ltn 2>/dev/null | awk -v p="$port" '$4 ~ ("^(127\\.0\\.0\\.1|0\\.0\\.0\\.0|\\*|\\[::\\]|::):" p "$") {f=1} END{exit !f}'
  else
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null
  fi
}

# Before downloading or starting anything, check, that the published ports of the
# lab are free. Already-running labs own their ports.
preflight_ports() {
  local id=$1 json line ip port who busy=()
  command -v python3 >/dev/null 2>&1 || return 0
  [[ -z "$(dc "$id" ps -q 2>/dev/null || true)" ]] || return 0
  json="$(dc "$id" config --format json 2>/dev/null)" || return 0
  while read -r ip port; do
    [[ -n $port ]] || continue
    if [[ " ${RESERVED_PORTS//,/ } " == *" $port "* ]]; then
      busy+=("$port (RESERVED: change it in .env)"); continue
    fi
    if port_in_use "$ip" "$port"; then
      who="$(docker ps --format '{{.Names}}|{{.Ports}}' 2>/dev/null | grep -E ":${port}->" | cut -d'|' -f1 | head -n1 || true)"
      busy+=("$port${who:+ (contenedor: $who)}")
    fi
  done < <(python3 -I -c '
import json, sys
c = json.load(sys.stdin)
for v in c.get("services", {}).values():
    for p in v.get("ports", []) or []:
        if p.get("published"): print(p.get("host_ip") or "0.0.0.0", p["published"])
' <<<"$json")
  (( ${#busy[@]} == 0 )) && return 0
  err "[$id] busy or reserved ports: ${busy[*]}"
  err "[$id] nothing started. Options:"
  err "    1) Find who uses it:   ss -ltnp | grep -E ':(${busy[0]%% *})\\b'   o   docker ps --filter publish=${busy[0]%% *}"
  err "    2) Change the lab port in $LABS_ROOT/$id/.env and retry '$PROG up $id'"
  err "    3) Stop the process using it (if another lab: '$PROG down <lab>')"
  return 1
}

# ── Managed local hostnames and Caddy reverse proxy ───────────────────────────
# Uses short hostnames (http://crapi), NOT .test suffixes. Caddy runs in a
# Docker host-network container, which is Linux-only and deliberately bound to
# 127.0.0.1:80. This lets it reach lab ports also bound to localhost.
# Never passes project-controlled input to a shell running as root.
proxy_state_dir() { printf '%s' "$LABS_ROOT/.proxy"; }

proxy_routes_of() {
  local id=$1 url port
  url="$("lab_$(key "$id")_wait_url")"
  if [[ $url =~ ^http://127\.0\.0\.1:([0-9]+) ]]; then
    port=${BASH_REMATCH[1]}
    printf '%s|%s\n' "$id" "$port"
  else
    warn "[$id] cannot determine localhost HTTP port for proxy"
    return 1
  fi
  if [[ $id == oauth2 ]]; then
    printf 'gallery|%s\n' "$(env_val oauth2 OAUTH2_GALLERY_PORT 3005)"
    printf 'photoprint|%s\n' "$(env_val oauth2 OAUTH2_PHOTOPRINT_PORT 3000)"
    printf 'attacker|%s\n' "$(env_val oauth2 OAUTH2_ATTACKER_PORT 1337)"
  fi
}

proxy_collect_routes() {
  local id
  for id in "${LABS[@]}"; do
    [[ -f $(proxy_state_dir)/active/$id ]] || continue
    installed_p "$id" || continue
    proxy_routes_of "$id"
  done
}

proxy_compose() {
  local state; state="$(proxy_state_dir)"
  docker compose --project-name vulnmachinesctl-localproxy \
    --project-directory "$state" -f "$state/docker-compose.yml" "$@"
}

proxy_prepare() {
  local state; state="$(proxy_state_dir)"
  mkdir -p -- "$state/active"
  cat > "$state/docker-compose.yml" <<'EOF'
# Generated by VulnMachinesCTL. Linux/Kali only. Never publish outside localhost.
services:
  caddy:
    image: caddy:2-alpine
    network_mode: host
    restart: unless-stopped
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
EOF
}

# /etc/hosts is changed only by an isolated, audited Python helper.
# Use sudo for this single action, never for Docker or the management script.
# TEST ONLY: VULNMACHINESCTL_HOSTS_FILE points to a temporary fixture.
proxy_sync_hosts() {
  local -a hosts=()
  local name port
  while IFS='|' read -r name port; do
    [[ -n $name ]] && hosts+=("$name")
  done < <(proxy_collect_routes)
  local helper="$TOOL_DIR/scripts/hosts-manager.py"
  [[ -f $helper ]] || { warn "Hosts helper missing: $helper"; return 1; }
  if [[ -n ${VULNMACHINESCTL_HOSTS_FILE:-} ]]; then
    python3 -I "$helper" --file "$VULNMACHINESCTL_HOSTS_FILE" "${hosts[@]}"
  elif [[ -w /etc/hosts ]]; then
    python3 -I "$helper" "${hosts[@]}"
  elif command -v sudo >/dev/null 2>&1; then
    # -n first: no hidden password prompts in CI. On interactive terminals,
    # sudo may prompt for permission just for /etc/hosts maintenance.
    if sudo -n python3 -I "$helper" "${hosts[@]}" 2>/dev/null; then return 0; fi
    if [[ -t 0 && -t 2 ]]; then
      sudo python3 -I "$helper" "${hosts[@]}"
    else
      warn 'Cannot update /etc/hosts non-interactively; run on Kali with sudo access.'
      return 1
    fi
  else
    warn 'Cannot update /etc/hosts (sudo unavailable).'
    return 1
  fi
}

proxy_refresh() {
  command -v python3 >/dev/null 2>&1 || { warn 'Python3 missing: local proxy disabled'; return 1; }
  local state routes
  state="$(proxy_state_dir)"
  proxy_prepare
  routes="$(proxy_collect_routes)" || return 1
  if [[ -z $routes ]]; then
    # First stop the proxy, then remove only our generated hosts block.
    proxy_compose down >/dev/null 2>&1 || warn 'Could not stop local proxy.'
    proxy_sync_hosts || warn 'Managed /etc/hosts entries require manual cleanup.'
    return 0
  fi
  printf '%s\n' "$routes" | python3 -I "$TOOL_DIR/scripts/proxy-render.py" >"$state/Caddyfile" \
    || { warn 'Unable to generate Caddy routes'; return 1; }
  # Protect unrelated service on port 80. Existing managed Caddy may own it.
  if ! proxy_compose ps -q 2>/dev/null | grep -q . && port_in_use 127.0.0.1 80; then
    warn 'Port 80 is already occupied: keeping standard lab URLs with explicit ports.'
    proxy_sync_hosts || true
    return 1
  fi
  if ! proxy_compose up -d --force-recreate; then
    warn 'Local proxy startup failed; labs remain accessible on their published ports.'
    proxy_sync_hosts || true
    return 1
  fi
  proxy_sync_hosts || warn 'Proxy running, but hostnames need /etc/hosts permission.'
  ok 'Local proxy ready on 127.0.0.1:80 (short names, no suffix).'
}

proxy_activate() {
  local id=$1
  [[ $PROXY_ENABLED == 1 ]] || return 0
  proxy_prepare
  : > "$(proxy_state_dir)/active/$id"
  proxy_refresh || warn "[$id] proxy unavailable; use its original localhost:PORT URL."
}
proxy_deactivate() {
  local id=$1
  # Always clean previously managed hosts, even if proxy mode was disabled
  # after the original 'up'.
  [[ -f $(proxy_state_dir)/active/$id ]] || return 0
  rm -f -- "$(proxy_state_dir)/active/$id"
  proxy_refresh || warn "[$id] proxy/hosts cleanup incomplete."
}
proxy_url_of() {
  local id=$1 orig path
  orig="$(open_url_of "$id")"
  if [[ $id == oauth2 ]]; then
    printf 'http://photoprint/'
  elif [[ $orig =~ ^http://127\.0\.0\.1:[0-9]+(/.*)?$ ]]; then
    path=${BASH_REMATCH[1]:-/}
    printf 'http://%s%s' "$id" "$path"
  else
    printf '%s' "$orig"
  fi
}

# ── Automatic browser opening (Firefox default) ────────────────
# Ports that NO lab may use (default 8080 reserved for Burp Suite).
# Multiple: VULNMACHINESCTL_RESERVED_PORTS="8080 8081 9090"
RESERVED_PORTS="${VULNMACHINESCTL_RESERVED_PORTS:-8080}"
OPEN_BROWSER=${VULNMACHINESCTL_OPEN:-1}          # 0 = do not open (or use --no-open)
BROWSER_CMD=${VULNMACHINESCTL_BROWSER:-firefox}  # another browser: VULNMACHINESCTL_BROWSER=chromium

open_url_of() {
  local id=$1 fn
  fn="lab_$(key "$id")_open_url"
  if declare -F "$fn" >/dev/null; then "$fn"; else "lab_$(key "$id")_wait_url"; fi
}

open_browser() {
  local id=$1 url
  [[ $OPEN_BROWSER == 1 ]] || return 0
  url="$(open_url_of "$id")"
  if [[ $PROXY_ENABLED == 1 && -f $(proxy_state_dir)/active/$id ]]       && proxy_compose ps -q 2>/dev/null | grep -q .; then
    local host="${id}"
    [[ $id == oauth2 ]] && host=photoprint
    if getent ahostsv4 "$host" 2>/dev/null | grep -q '127.0.0.1'; then
      url="$(proxy_url_of "$id")"
    fi
  fi
  if [[ -z ${DISPLAY:-}${WAYLAND_DISPLAY:-} ]]; then
    info "[$id] no graphical desktop (DISPLAY/WAYLAND_DISPLAY): cannot open browser. URL: $url"
    return 0
  fi
  if command -v "$BROWSER_CMD" >/dev/null 2>&1; then
    # Give the web UI an additional two seconds to finish initializing.
    sleep "$VULNMACHINESCTL_BROWSER_DELAY"
    # Background and detached from terminal; never blocks or uses sudo.
    nohup "$BROWSER_CMD" --new-tab "$url" >/dev/null 2>&1 &
    disown 2>/dev/null || true
    ok "[$id] opened in $BROWSER_CMD: $url"
  elif [[ $BROWSER_CMD == firefox ]] && command -v flatpak >/dev/null 2>&1 \
       && flatpak info org.mozilla.firefox >/dev/null 2>&1; then
    sleep "$VULNMACHINESCTL_BROWSER_DELAY"
    nohup flatpak run org.mozilla.firefox --new-tab "$url" >/dev/null 2>&1 &
    disown 2>/dev/null || true
    ok "[$id] opened in Firefox (flatpak): $url"
  else
    warn "[$id] could not find '$BROWSER_CMD' on PATH: open manually $url"
  fi
}

up_lab() {
  local id=$1
  require_docker
  installed_p "$id" || install_lab "$id"
  # Repair known upstream build issues on both fresh and existing installs.
  if [[ $id == vulndap ]]; then
    lab_vulndap_patch_dockerfile
  fi
  if [[ $id == oauth2 ]]; then
    lab_oauth2_patch_dependencies
    lab_oauth2_patch_mongoseed
  fi
  preflight_ports "$id" || return 1
  info "[$id] pulling images..."
  dc "$id" pull --ignore-buildable \
    || warn "[$id] could not pull every image (using cached images if available)"
  local -a up_args=(up -d)                 # ALWAYS detached
  [[ ${L_BUILD[$id]} == yes ]] && up_args+=(--build)
  info "[$id] starting services (docker compose ${up_args[*]})"
  if ! dc "$id" "${up_args[@]}"; then
    err "[$id] deployment failed."
    diagnose "$id"
    return 1
  fi
  local fn="lab_$(key "$id")_post_up"
  local ready=yes
  wait_ready "$id" || ready=no
  if [[ $ready == yes ]] && declare -F "$fn" >/dev/null; then
    "$fn" || warn "[$id] post-start initialization failed"
  fi
  runtime_info "$id"
  ok "[$id] containers: $RT_RUN/$RT_TOTAL running · ports: $RT_PORTS · health: $RT_HEALTH"
  if [[ $ready == yes ]]; then proxy_activate "$id"; fi
  show_access "$id"
  if [[ $ready == yes ]]; then
    open_browser "$id"
  else
    warn "[$id] not ready in time: browser not opened (when ready: $(open_url_of "$id"))"
  fi
}

down_lab() {
  local id=$1
  require_docker
  if ! installed_p "$id"; then
    proxy_deactivate "$id"
    info "[$id] not installed: nothing to stop."
    return 0
  fi
  info "[$id] stopping (files, images, and volumes are preserved)..."
  DC_ALL_PROFILES=1 dc "$id" down || return 1
  proxy_deactivate "$id"
  ok "[$id] stopped"
}

restart_lab() {
  local id=$1
  require_docker
  installed_p "$id" || die "[$id] is not installed. Use: $PROG up $id"
  if [[ -n "$(DC_ALL_PROFILES=1 dc "$id" ps -q 2>/dev/null)" ]]; then
    info "[$id] restarting..."
    dc "$id" restart
    if wait_ready "$id"; then proxy_activate "$id"; fi
    show_access "$id"
  else
    info "[$id] was not running: starting instead."
    up_lab "$id"
  fi
}

# Typed confirmation (requires typing exactly the expected text).
confirm_typed() {
  local expected=$1 prompt=$2 reply=""
  printf '%s' "$prompt" >&2
  if ! read -r reply; then
    err "No interactive input: operation cancelled."
    return 1
  fi
  [[ $reply == "$expected" ]] || { warn "Incorrect confirmation: operation cancelled."; return 1; }
}

# Images used by OTHER installed labs (to avoid removing shared images).
declare -A OTHER_IMAGES=()
collect_other_images() {
  local self=$1 other img
  OTHER_IMAGES=()
  for other in "${LABS[@]}"; do
    [[ $other == "$self" ]] && continue
    [[ -f "$(lab_compose_file "$other")" ]] || continue
    while IFS= read -r img; do
      [[ -n $img ]] && OTHER_IMAGES["$img"]=$other
    done < <(DC_ALL_PROFILES=1 dc "$other" config --images 2>/dev/null || true)
  done
}

# Remove Docker resources belonging to the lab (y ONLY its own).
cleanup_docker() {
  local id=$1 proj="${PROJECT_PREFIX}-$1" f imgs="" x
  f="$(lab_compose_file "$id")"
  if [[ -f $f ]]; then
    imgs="$(DC_ALL_PROFILES=1 dc "$id" config --images 2>/dev/null | sort -u || true)"
    DC_ALL_PROFILES=1 dc "$id" down --volumes --remove-orphans \
      || warn "[$id] 'compose down' failed; cleaning up by project label."
  fi
  # Leftover Compose project resources (por etiqueta): containers, networks, volumes.
  local -a ids=()
  mapfile -t ids < <(docker ps -aq --filter "label=com.docker.compose.project=$proj")
  (( ${#ids[@]} )) && docker rm -f "${ids[@]}" >/dev/null
  mapfile -t ids < <(docker network ls -q --filter "label=com.docker.compose.project=$proj")
  (( ${#ids[@]} )) && docker network rm "${ids[@]}" >/dev/null || true
  mapfile -t ids < <(docker volume ls -q --filter "label=com.docker.compose.project=$proj")
  (( ${#ids[@]} )) && docker volume rm "${ids[@]}" >/dev/null || true
  # Images: only when no other lab uses them; docker rmi without -f
  # refuses if another container (outside the catalog) is using them.
  if [[ -n $imgs ]]; then
    collect_other_images "$id"
    while IFS= read -r x; do
      [[ -n $x ]] || continue
      if [[ -n ${OTHER_IMAGES[$x]:-} ]]; then
        info "[$id] image shared with '${OTHER_IMAGES[$x]}', preserved: $x"
      elif docker image inspect "$x" >/dev/null 2>&1; then
        if docker rmi "$x" >/dev/null 2>&1; then
          info "[$id] image removed: $x"
        else
          info "[$id] image used by other containers, preserved: $x"
        fi
      fi
    done <<<"$imgs"
  fi
}

remove_lab_files() {
  local id=$1 d
  if d="$(safe_lab_dir "$id")" && [[ -n $d ]]; then
    rm -rf -- "$d"
    ok "[$id] directory removed: $d"
  else
    info "[$id] no local directory to remove."
  fi
}

lab_has_docker_resources() {
  local proj="${PROJECT_PREFIX}-$1"
  [[ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$proj" 2>/dev/null)" ]] && return 0
  [[ -n "$(docker volume ls -q --filter "label=com.docker.compose.project=$proj" 2>/dev/null)" ]] && return 0
  return 1
}

remove_lab() {
  local id=$1 dir="$LABS_ROOT/$1"
  valid_lab "$id" || die "Invalid lab: '$id'" 2
  require_docker
  [[ -f $LABS_ROOT/$ROOT_MARKER ]] || { info "Managed root does not exist ($LABS_ROOT): nothing to remove."; return 0; }
  if [[ ! -d $dir ]] && ! lab_has_docker_resources "$id"; then
    info "[$id] nothing to remove."
    return 0
  fi
  printf '\n%sThe lab "%s" will be permanently removed:%s\n' "$C_B" "$id" "$C_R"
  printf '  - Containers, networks and VOLUMES (persistent data) for project %s-%s\n' "$PROJECT_PREFIX" "$id"
  printf '  - Images exclusive to this lab (shared images are preserved)\n'
  printf '  - Entire local directory: %s\n\n' "$dir"
  confirm_typed "$id" "Type '$id' to confirm: " || exit 1
  cleanup_docker "$id"
  proxy_deactivate "$id"
  remove_lab_files "$id"
  ok "[$id] removed"
}

purge_all() {
  require_docker
  [[ -f $LABS_ROOT/$ROOT_MARKER ]] || { info "Managed root does not exist ($LABS_ROOT): nothing to purge."; return 0; }
  local -a affected=() id
  for id in "${LABS[@]}"; do
    if [[ -d $LABS_ROOT/$id ]] || lab_has_docker_resources "$id"; then affected+=("$id"); fi
  done
  if (( ${#affected[@]} == 0 )); then
    info "There are no managed labs to remove."
    return 0
  fi
  printf '\n%sFULL PURGE%s\n' "$C_RED$C_B" "$C_R"
  printf '  Root directory:  %s\n' "$LABS_ROOT"
  printf '  Labs:     %s\n' "${affected[*]}"
  printf '  Containers, networks, VOLUMES/data, exclusive images, and directories will be removed.\n'
  printf '  No global Docker cleanup will run; unrelated resources are left untouched.\n\n'
  confirm_typed "DELETE ALL" "Type exactly 'DELETE ALL' to continue: " || exit 1
  for id in "${affected[@]}"; do
    cleanup_docker "$id"
    proxy_deactivate "$id"
    remove_lab_files "$id"
  done
  # Clear our proxy state; never remove unrelated directories.
  if [[ -d $(proxy_state_dir) ]]; then rm -rf -- "$(proxy_state_dir)"; fi
  rm -f -- "$LABS_ROOT/$ROOT_MARKER"
  rmdir -- "$LABS_ROOT" 2>/dev/null || { : >"$LABS_ROOT/$ROOT_MARKER"; warn "The root contains unrelated files: preserved."; }
  ok "Purge complete"
}

# ─────────────────────────────────────────────────────────────────────────────
# 5. CLI commands
# ─────────────────────────────────────────────────────────────────────────────

usage() {
  cat <<EOF
$PROG $VERSION — Vulnerable Web/API Lab Manager (Docker Compose v2)

USAGE
  $PROG <command> [arguments]

COMMANDS
  list                          List available labs
  info <lab>                    Show lab details, access URLs, and credentials
  install <lab|all>             Install files without starting containers
  up <lab|all> [--yes] [--no-open]
                                Start services in the background; open the browser once ready
                                'up all' needs confirmation (or --yes) and starts sequentially
  down <lab|all>                Stop services, preserving files, images, and data
  restart <lab>                 Restart one installed lab
  ports                         List published ports and report conflicts
  status                        Show installation, container, and health status
  logs <lab> [-f] [--tail N] [service]
                                Show logs (-f follows them in real time)
  shell <lab> [service]         Open a shell (bash, sh, or ash)
  remove <lab>                  Remove only this lab, including its Docker data and files
  purge                         Remove all managed labs (requires typed confirmation)
  -h, --help                    Show this help

ENVIRONMENT VARIABLES
  LABS_DIR                         Root for lab files (default: ./vuln-labs)
  WAIT_TIMEOUT                     HTTP readiness timeout in seconds (default: 300)
  VULNMACHINESCTL_BROWSER          Browser executable (default: firefox)
  VULNMACHINESCTL_BROWSER_DELAY    Extra delay before opening browser, seconds (default: 2)
  VULNMACHINESCTL_OPEN             Set to 0 to disable auto-opening (or use --no-open)
  VULNMACHINESCTL_RESERVED_PORTS   Space-separated reserved ports (default: 8080)
  VULNMACHINESCTL_PROXY            1 = manage local Caddy proxy and hosts (default: 1)
  VULNMACHINESCTL_HOSTS_FILE       Test-only alternate hosts fixture (never use in production)

AVAILABLE LABS
  ${LABS[*]}

SECURITY
  Labs are intentionally vulnerable. Keep them isolated on localhost.
  Only /etc/hosts changes may invoke sudo. Docker always runs unprivileged.
EOF
}

cmd_list() {
  local id
  printf '%s%-15s %s%s\n' "$C_B" ID DESCRIPTION "$C_R"
  for id in "${LABS[@]}"; do
    printf '%-15s %s\n' "$id" "${L_DESC[$id]}"
  done
}

cmd_info() {
  local id; id="$(targets_of "${1:-}")"
  printf '%s%s%s\n' "$C_B" "$id" "$C_R"
  printf '  Description:   %s\n' "${L_DESC[$id]}"
  printf '  Technologies:   %s\n' "${L_TECH[$id]}"
  printf '  Repository:   %s\n' "${L_REPO[$id]}"
  printf '  Deployment:    %s\n' "${L_METHOD[$id]}"
  printf '  Directory:    %s\n' "$LABS_ROOT/$id"
  if installed_p "$id"; then
    printf '  Installed:     yes\n'
  elif [[ -d $LABS_ROOT/$id ]]; then
    printf '  Installed:     PARTIAL (run: %s install %s)\n' "$PROG" "$id"
  else
    printf '  Installed:     no\n'
  fi
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    runtime_info "$id"
    printf '  Containers:  %s/%s running · ports: %s · health: %s\n' "$RT_RUN" "$RT_TOTAL" "$RT_PORTS" "$RT_HEALTH"
  fi
  show_access "$id"
}

cmd_install() {
  local id arg=${1:-}
  [[ $arg == all ]] || valid_lab "$arg" || die "Invalid lab: ${arg:-<missing>}" 2
  while IFS= read -r id; do install_lab "$id"; done < <(targets_of "$arg" allow-all)
}

cmd_up() {
  local arg="" assume_yes=no a
  for a in "$@"; do
    case $a in
      -y|--yes) assume_yes=yes ;;
      --no-open) OPEN_BROWSER=0 ;;
      -*) die "Unknown option: $a" 2 ;;
      *) arg=$a ;;
    esac
  done
  [[ $arg == all ]] || valid_lab "$arg" || die "Invalid lab: ${arg:-<missing>}" 2
  local -a ids=()
  mapfile -t ids < <(targets_of "$arg" allow-all)
  if [[ $arg == all && $assume_yes != yes ]]; then
    warn "You are about to start ${#ids[@]} labs (many GB of images and substantial RAM)."
    confirm_typed "ALL" "Type 'ALL' to continue (or use --yes): " || exit 1
  fi
  if [[ $arg == all ]]; then
    local pre
    for pre in "${ids[@]}"; do installed_p "$pre" || install_lab "$pre"; done
    info "Checking for overlapping lab ports..."
    overlap_ok quiet || exit 1
  fi
  banner_security
  local id failed=()
  for id in "${ids[@]}"; do          # one by one, never simultaneously
    up_lab "$id" || failed+=("$id")
  done
  if (( ${#failed[@]} )); then
    err "Failed: ${failed[*]}"
    exit 1
  fi
}

# List "lab service ip host_port container_port" for all labs
# for installed labs (including profiles). 'compose config' needs no daemon.
collect_ports() {
  command -v docker >/dev/null 2>&1 || die "Docker is missing or not on PATH." 3
  command -v python3 >/dev/null 2>&1 || die "python3 is required to parse port mappings." 3
  local id json
  for id in "${LABS[@]}"; do
    installed_p "$id" || continue
    json="$(DC_ALL_PROFILES=1 dc "$id" config --format json 2>/dev/null)" \
      || { warn "[$id] 'compose config' failed; skipping this lab"; continue; }
    python3 -I -c '
import json, sys
lab = sys.argv[1]
for s, v in json.load(sys.stdin).get("services", {}).items():
    for p in v.get("ports", []) or []:
        if p.get("published"):
            print(lab, s, p.get("host_ip") or "0.0.0.0", p["published"], p["target"])
' "$id" <<<"$json"
  done
}

# 0 = no collisions; 1 = duplicate ports across services/labs.
# Con $1=quiet print problems only, without the table.
overlap_ok() {
  local quiet=${1:-} rows dups wide
  rows="$(collect_ports)"
  [[ -n $rows ]] || { [[ $quiet == quiet ]] || info "No installed labs: nothing to check."; return 0; }
  if [[ $quiet != quiet ]]; then
    printf '%s%-15s %-22s %-10s %-7s %s%s\n' "$C_B" LAB SERVICE IP PORT TARGET "$C_R"
    sort -k4,4n <<<"$rows" | awk '
      function cell(s, max) { return length(s)>max ? substr(s,1,max-3) "..." : s }
      {c[$4]++; r[NR]=$0; p[NR]=$4}
      END{for(i=1;i<=NR;i++){split(r[i],a," "); printf "%-15s %-22s %-10s %-7s %s%s\n", cell(a[1],15),cell(a[2],22),cell(a[3],10),cell(a[4],7),a[5], (c[p[i]]>1?"   <-- DUPLICATE":"")}}'
    printf '\n%s published ports in total.\n' "$(wc -l <<<"$rows" | tr -d ' ')"
  fi
  local resv
  resv="$(awk -v r="${RESERVED_PORTS//,/ }" 'BEGIN{n=split(r,a," "); for(i=1;i<=n;i++) R[a[i]]=1} ($4 in R){print $1 "/" $2 " (port " $4 ")"}' <<<"$rows")"
  if [[ -n $resv ]]; then
    err "Reserved ports (${RESERVED_PORTS}) used by labs:"
    sed 's/^/    /' <<<"$resv" >&2
    err "    Change them in vuln-labs/<lab>/.env (or adjust VULNMACHINESCTL_RESERVED_PORTS)."
    return 1
  fi
  dups="$(awk '{k[$4]=k[$4] " " $1 "/" $2; c[$4]++} END{for(p in c) if(c[p]>1) print p ":" k[p]}' <<<"$rows")"
  wide="$(awk '$3!="127.0.0.1"{print $1 "/" $2 " (" $3 ":" $4 ")"}' <<<"$rows")"
  [[ -z $wide ]] || warn "Ports published outside 127.0.0.1: $(paste -sd' ' <<<"$wide")"
  if [[ -n $dups ]]; then
    err "Duplicate ports (cannot run simultaneously):"
    sed 's/^/    /' <<<"$dups" >&2
    return 1
  fi
  [[ $quiet == quiet ]] || ok "No port conflicts: all labs can run concurrently."
  return 0
}

# Describe browser-facing URLs without claiming that an installed lab is running.
# The proxy is reported as active only when its own container exists and the
# lab has an active managed route. A configured URL is not an availability check.
proxy_route_state() {
  local id=$1
  if [[ $PROXY_ENABLED != 1 ]]; then printf 'disabled'; return; fi
  if [[ ! -f $(proxy_state_dir)/active/$id ]]; then printf 'inactive'; return; fi
  if [[ -n "$(proxy_compose ps -q 2>/dev/null)" ]]; then
    printf 'active'
  else
    printf 'unavailable'
  fi
}

# List known short-name routes for installed labs, including extra OAuth apps.
# This shows intended URLs even when the containers have not been started.
show_web_urls() {
  local id state routes host port
  printf '\n%-15s %-17s %-30s %-13s %s\n' 'LAB' 'HOST' 'URL' 'PROXY' 'DIRECT'
  for id in "${LABS[@]}"; do
    installed_p "$id" || continue
    state="$(proxy_route_state "$id")"
    routes="$(proxy_routes_of "$id")" || continue
    while IFS='|' read -r host port; do
      [[ -n $host && -n $port ]] || continue
      printf '%-15s %-17s %-30s %-13s %s\n' \
        "$id" "$host" "http://$host" "$state" "http://127.0.0.1:$port"
    done <<< "$routes"
  done
  printf '%s\n' 'Proxy states: active=route configured and proxy container exists; inactive=not started; unavailable=proxy not running.'
  printf '%s\n' 'URLs are configuration information, not HTTP availability guarantees.'
}

cmd_ports() {
  local rc=0
  overlap_ok || rc=1
  show_web_urls
  return "$rc"
}

cmd_down() {
  local id failed=0 arg=${1:-}
  [[ $arg == all ]] || valid_lab "$arg" || die "Invalid lab: ${arg:-<missing>}" 2
  while IFS= read -r id; do down_lab "$id" || failed=1; done < <(targets_of "$arg" allow-all)
  exit "$failed"
}

cmd_restart() {
  local id; id="$(targets_of "${1:-}")"
  restart_lab "$id"
}

# Truncate only diagnostic summary cells; the complete port mappings remain
# available through `ports`. Bash string slicing is safe for ASCII values.
status_cell() {
  local value=$1 limit=$2
  if (( ${#value} > limit )); then
    printf '%s...' "${value:0:limit-3}"
  else
    printf '%s' "$value"
  fi
}

cmd_status() {
  local id state docker_ok=no web proxy containers health ports
  if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then docker_ok=yes; fi
  [[ $docker_ok == yes ]] || warn "Docker unavailable: showing installation state only."
  # Fixed widths must also be enforced on every value: printf minimum widths
  # alone do not truncate overlong values, causing subsequent columns to move.
  printf '%s%-15s %-11s %-17s %-10s %-20s %-13s %s%s\n' \
    "$C_B" ID INSTALLED CONTAINERS HEALTH PORTS PROXY URL "$C_R"
  for id in "${LABS[@]}"; do
    if installed_p "$id"; then state="yes"
    elif [[ -d $LABS_ROOT/$id ]]; then state="partial"
    else state="no"; fi
    proxy='-'; web='-'
    if [[ $state == yes ]]; then
      web="$(proxy_url_of "$id")"
      proxy="$(proxy_route_state "$id")"
    fi
    if [[ $docker_ok == yes ]]; then
      runtime_info "$id"
      if (( RT_TOTAL == 0 )); then containers="stopped"; else containers="$RT_RUN/$RT_TOTAL running"; fi
      health="$RT_HEALTH"
      ports="$RT_PORTS"
    else
      containers="n/a"; health="n/a"; ports="n/a"
    fi
    printf '%-15s %-11s %-17s %-10s %-20s %-13s %s\n' \
      "$(status_cell "$id" 15)" "$(status_cell "$state" 11)" \
      "$(status_cell "$containers" 17)" "$(status_cell "$health" 10)" \
      "$(status_cell "$ports" 20)" "$(status_cell "$proxy" 13)" "$web"
  done
  printf '\n%s\n' 'PORTS is abbreviated when needed; use ports for complete mappings.'
  printf '%s\n' 'URL is the configured browser entry point; proxy status is not an HTTP health check.'
  printf '%s\n' 'Use ports to see additional OAuth2 hostnames and direct localhost ports.'
}

cmd_logs() {
  local id; id="$(targets_of "${1:-}")"; shift || true
  local follow=no tail=200 svc="" a
  while (( $# )); do
    case $1 in
      -f|--follow) follow=yes ;;
      --tail) shift; tail=${1:-200}; [[ $tail =~ ^[0-9]+$ ]] || die "--tail requires a number" 2 ;;
      -*) die "Unknown option: $1" 2 ;;
      *) svc=$1 ;;
    esac
    shift
  done
  require_docker
  installed_p "$id" || die "[$id] is not installed. Use: $PROG install $id"
  local -a args=(logs --tail "$tail")
  [[ $follow == yes ]] && args+=(-f)
  [[ -n $svc ]] && args+=("$svc")
  DC_ALL_PROFILES=1 dc "$id" "${args[@]}"
}

cmd_shell() {
  local id; id="$(targets_of "${1:-}")"
  local svc=${2:-${L_SHELL[$id]}}
  [[ $svc =~ ^[A-Za-z0-9._-]+$ ]] || die "Invalid service name: $svc" 2
  require_docker
  installed_p "$id" || die "[$id] is not installed. Use: $PROG up $id"
  if [[ -z "$(dc "$id" ps -q "$svc" 2>/dev/null)" ]]; then
    err "Service '$svc' is not running. Lab services:"
    DC_ALL_PROFILES=1 dc "$id" config --services 2>/dev/null | sed 's/^/    /' >&2 || true
    die "Use: $PROG up $id   (or specify another service: $PROG shell $id <service>)"
  fi
  local sh
  for sh in bash sh ash; do
    if dc "$id" exec -T "$svc" "$sh" -c 'exit 0' >/dev/null 2>&1; then
      info "[$id] shell '$sh' for service '$svc' (type exit to quit)"
      dc "$id" exec "$svc" "$sh"
      exit $?
    fi
  done
  die "Service '$svc' has no bash/sh (minimal or distroless image). Try: $PROG logs $id" 1
}

cmd_remove() {
  local id; id="$(targets_of "${1:-}")"
  remove_lab "$id"
}

cmd_purge() { purge_all; }

main() {
  (( $# )) || { usage; exit 2; }
  case $1 in
    -h|--help|help) usage; exit 0 ;;
  esac
  resolve_root
  local cmd=$1; shift
  case $cmd in
    list)    cmd_list ;;
    info)    cmd_info "$@" ;;
    install) cmd_install "$@" ;;
    up)      cmd_up "$@" ;;
    down)    cmd_down "$@" ;;
    restart) cmd_restart "$@" ;;
    status)  cmd_status ;;
    ports)   cmd_ports ;;
    logs)    cmd_logs "$@" ;;
    shell)   cmd_shell "$@" ;;
    remove)  cmd_remove "$@" ;;
    purge)   cmd_purge ;;
    *)       err "Unknown command: $cmd"; usage >&2; exit 2 ;;
  esac
}

main "$@"
