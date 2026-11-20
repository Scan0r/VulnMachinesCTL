#!/usr/bin/env bash
# Command-level regression tests. No network access, Docker daemon, or real lab is required.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
SCRIPT="$PWD/vulnmachinesctl.sh"
TMP="$(mktemp -d)"
trap 'rm -rf -- "$TMP"' EXIT
mkdir -p "$TMP/bin"
export MOCK_LOG="$TMP/docker.log"
export LABS_DIR="$TMP/labs"
export VULNMACHINESCTL_OPEN=0
export VULNMACHINESCTL_PROXY=0
export WAIT_TIMEOUT=1
export VULNMACHINESCTL_BROWSER_DELAY=0
: > "$MOCK_LOG"

cp tests/mocks/docker "$TMP/bin/docker"
cat > "$TMP/bin/curl" <<'MOCK'
#!/usr/bin/env bash
[[ "${MOCK_HTTP_FAIL:-0}" == 1 ]] && exit 7
printf '200'
MOCK
# Isolate port checks from services running on the developer's machine.
# Without this stub, a real service using :5002 can break mocked Docker tests.
cat > "$TMP/bin/ss" <<'MOCK'
#!/usr/bin/env bash
exit 0
MOCK
chmod +x "$TMP/bin/docker" "$TMP/bin/curl" "$TMP/bin/ss"
export PATH="$TMP/bin:$PATH"

PASS=0
FAIL=0
run_ok() {
  local name=$1; shift
  if "$@" >"$TMP/out" 2>"$TMP/err"; then
    printf 'PASS %-48s\n' "$name"
    PASS=$((PASS+1))
  else
    printf 'FAIL %-48s (expected success)\n' "$name" >&2
    cat "$TMP/err" >&2
    FAIL=$((FAIL+1))
  fi
}
run_bad() {
  local name=$1; shift
  if "$@" >"$TMP/out" 2>"$TMP/err"; then
    printf 'FAIL %-48s (expected rejection)\n' "$name" >&2
    FAIL=$((FAIL+1))
  else
    printf 'PASS %-48s\n' "$name"
    PASS=$((PASS+1))
  fi
}
assert_file() {
  local label=$1 file=$2
  if [[ -f "$file" ]]; then printf 'PASS %s\n' "$label"; PASS=$((PASS+1))
  else printf 'FAIL %s (missing %s)\n' "$label" "$file" >&2; FAIL=$((FAIL+1)); fi
}
assert_log() {
  local label=$1 pattern=$2
  if grep -Fq -- "$pattern" "$MOCK_LOG"; then printf 'PASS %s\n' "$label"; PASS=$((PASS+1))
  else printf 'FAIL %s (missing Docker call: %s)\n' "$label" "$pattern" >&2; FAIL=$((FAIL+1)); fi
}

run_ok 'Bash syntax' bash -n "$SCRIPT"
run_ok 'help' bash "$SCRIPT" --help
run_ok 'help alias' bash "$SCRIPT" help
run_ok 'short help' bash "$SCRIPT" -h
run_bad 'no arguments returns usage error' bash "$SCRIPT"
run_ok 'list' bash "$SCRIPT" list
for lab in crapi dvga dvwa dvws-node juice-shop mutillidae oauth2 vampi vapi vulnbank vulndap vulnerableapp vulnlab webgoat webgoat7 xvwa; do
  run_ok "catalog info: $lab" bash "$SCRIPT" info "$lab"
done
# vuLnDAP catalog and installer regression (no actual network or Docker build).
run_ok 'vuLnDAP catalog registration' bash "$SCRIPT" info vulndap
if grep -Fq 'https://github.com/digininja/vuLnDAP' "$TMP/out"; then
  printf 'PASS vuLnDAP exposes upstream attribution\n'; PASS=$((PASS+1))
else
  printf 'FAIL vuLnDAP missing upstream attribution\n' >&2; FAIL=$((FAIL+1))
fi
run_ok 'status without installations' bash "$SCRIPT" status
run_ok 'info for uninstalled lab' bash "$SCRIPT" info vampi
run_bad 'unknown command' bash "$SCRIPT" not-a-command
run_bad 'unknown lab' bash "$SCRIPT" info nonexistent
run_bad 'invalid lab identifier' bash "$SCRIPT" install ../outside
# Simulated upstream git clone for the vuLnDAP installation contract.
cat > "$TMP/bin/git" <<'MOCKGIT'
#!/usr/bin/env bash
set -e
[[ $1 == clone ]] || exit 1
for last; do :; done
mkdir -p "$last/.git"
printf 'package main\nfunc main() {}\n' > "$last/main.go"
printf '[webserver]\nListenPort = 9090\n' > "$last/vulndap.cfg-sample"
MOCKGIT
chmod +x "$TMP/bin/git"
run_ok 'vuLnDAP install generates build files' bash "$SCRIPT" install vulndap
assert_file 'vuLnDAP Compose generated' "$LABS_DIR/vulndap/docker-compose.yml"
assert_file 'vuLnDAP Dockerfile generated' "$LABS_DIR/vulndap/Dockerfile"
assert_file 'vuLnDAP env generated' "$LABS_DIR/vulndap/.env"
if grep -Fq '127.0.0.1:${VULNDAP_PORT:-9093}:9090' "$LABS_DIR/vulndap/docker-compose.yml" && \
   grep -Fq 'go mod tidy' "$LABS_DIR/vulndap/Dockerfile" && \
   grep -Fq 'go build' "$LABS_DIR/vulndap/Dockerfile"; then
  printf 'PASS vuLnDAP build, binding and port templates\n'; PASS=$((PASS+1))
else
  printf 'FAIL vuLnDAP build template contract\n' >&2; FAIL=$((FAIL+1))
fi
# Ensure the generated Dockerfile actually rewrites the obsolete Go import
# before dependency resolution; a simple "go build" text check is insufficient.
if python3 - "$LABS_DIR/vulndap/Dockerfile" <<'PYTEST'
from pathlib import Path
import sys
content = Path(sys.argv[1]).read_text()
assert "find . -name '*.go' -type f -exec sed -i" in content
assert "'s|gopkg.in/russross/blackfriday.v2|github.com/russross/blackfriday/v2|g'" in content
assert content.index("find . -name '*.go'") < content.index('go mod tidy')
PYTEST
then printf 'PASS vuLnDAP legacy Blackfriday import patched before tidy\n'; PASS=$((PASS+1))
else printf 'FAIL vuLnDAP legacy dependency workaround missing\n' >&2; FAIL=$((FAIL+1)); fi
# The default proxy discovers lab routes from the generic wait_url function.
# Check that the vuLnDAP port is exposed through that same route mechanism.
if grep -Fq 'lab_vulndap_wait_url()' "$SCRIPT" && \
   grep -Fq 'proxy_routes_of()' "$SCRIPT" && \
   grep -Fq 'proxy_routes_of "$id"' "$SCRIPT"; then
  printf 'PASS vuLnDAP route registered through generic proxy resolver\n'; PASS=$((PASS+1))
else
  printf 'FAIL vuLnDAP proxy route discovery missing\n' >&2; FAIL=$((FAIL+1))
fi
run_ok 'vuLnDAP install is idempotent' bash "$SCRIPT" install vulndap
# Reproduce the exact Dockerfile generated by the previous release,
# then verify install migrates it without deleting the lab.
python3 - "$LABS_DIR/vulndap/Dockerfile" <<'PYTEST'
from pathlib import Path
import sys
p = Path(sys.argv[1])
s = p.read_text()
s = s.replace("# Upstream imports a legacy Blackfriday module alias. Current Go modules use\n# github.com/russross/blackfriday/v2; patch only the build-stage source copy.\n", "")
s = s.replace("    find . -name '*.go' -type f -exec sed -i \\\n      's|gopkg.in/russross/blackfriday.v2|github.com/russross/blackfriday/v2|g' {} + && \\\n", "")
# Normalize from updated template by removing the two inserted shell lines.
s = s.replace("    find . -name '*.go' -type f -exec sed -i \
      's|gopkg.in/russross/blackfriday.v2|github.com/russross/blackfriday/v2|g' {} + && \
", "")
p.write_text(s)
PYTEST
run_ok 'vuLnDAP reinstall migrates legacy Dockerfile' bash "$SCRIPT" install vulndap
if grep -Fq "'s|gopkg.in/russross/blackfriday.v2|github.com/russross/blackfriday/v2|g'" "$LABS_DIR/vulndap/Dockerfile"; then
  printf 'PASS vuLnDAP legacy Dockerfile upgraded\n'; PASS=$((PASS+1))
else printf 'FAIL vuLnDAP legacy Dockerfile remains unpatched\n' >&2; FAIL=$((FAIL+1)); fi
run_ok 'vuLnDAP ports command' bash "$SCRIPT" ports
if grep -Fq 'http://vulndap' "$TMP/out" && grep -Fq '127.0.0.1:9093' "$TMP/out"; then
  printf 'PASS vuLnDAP short and direct URLs\n'; PASS=$((PASS+1))
else
  printf 'FAIL vuLnDAP port/URL mapping\n' >&2; FAIL=$((FAIL+1))
fi
run_ok 'vuLnDAP remove fixture' bash -c 'printf "vulndap\n" | bash "$1" remove vulndap' _ "$SCRIPT"
if [[ ! -e "$LABS_DIR/vulndap" ]]; then
  printf 'PASS vuLnDAP remove cleans fixture\n'; PASS=$((PASS+1))
else
  printf 'FAIL vuLnDAP fixture was not removed\n' >&2; FAIL=$((FAIL+1))
fi
rm -f "$TMP/bin/git"
run_ok 'install (without Docker images)'  bash "$SCRIPT" install vampi
assert_file 'Compose generated' "$LABS_DIR/vampi/docker-compose.yml"
assert_file 'env generated' "$LABS_DIR/vampi/.env"
assert_file 'installation marker generated' "$LABS_DIR/vampi/.vulnmachinesctl-installed"
run_ok 'reinstall is idempotent' bash "$SCRIPT" install vampi
run_ok 'info for installed lab' bash "$SCRIPT" info vampi
run_ok 'up with --no-open' bash "$SCRIPT" up vampi --no-open
assert_log 'up triggers docker compose up' 'up -d'
run_ok 'up accepts --yes' bash "$SCRIPT" up vampi --yes --no-open
run_bad 'up all requires explicit confirmation' bash -c 'printf "wrong\n" | bash "$1" up all' _ "$SCRIPT"
run_bad 'up rejects unknown flag' bash "$SCRIPT" up vampi --unrecognized
run_ok 'status with installed lab' bash "$SCRIPT" status
if grep -Eq '^vampi[[:space:]]+yes.*disabled[[:space:]]+http://vampi/ui/' "$TMP/out"; then
  printf 'PASS status shows lab browser URL and disabled proxy\n'; PASS=$((PASS+1))
else printf 'FAIL status omitted short URL or proxy state\n' >&2; FAIL=$((FAIL+1)); fi

# Validate column positions, not only the presence of text. In particular,
# PORTS must not push PROXY and URL out of alignment.
run_ok 'status table layout' bash "$SCRIPT" status
if python3 -I - "$TMP/out" <<'PYTEST'
from pathlib import Path
import sys
lines = Path(sys.argv[1]).read_text().splitlines()
header = next(line for line in lines if line.startswith('ID ') and 'PROXY' in line and 'URL' in line)
row = next(line for line in lines if line.startswith('vampi '))
for title in ('INSTALLED', 'CONTAINERS', 'HEALTH', 'PORTS', 'PROXY', 'URL'):
    start = header.index(title)
    assert start < len(row), title
assert row[header.index('PROXY'):].strip().startswith('disabled '), row
assert row[header.index('URL'):].startswith('http://vampi/ui/'), row
PYTEST
then printf 'PASS status columns remain aligned\n'; PASS=$((PASS+1))
else printf 'FAIL status table columns shifted\n' >&2; FAIL=$((FAIL+1)); fi

run_ok 'ports reads Compose configuration' bash "$SCRIPT" ports
if grep -Fq 'http://vampi' "$TMP/out" && grep -Fq 'http://127.0.0.1:5002' "$TMP/out" && grep -Fq 'inactive' "$TMP/out"; then
  printf 'PASS ports shows configured short and direct URLs with inactive state\n'; PASS=$((PASS+1))
else printf 'FAIL ports omitted URL or inactive state\n' >&2; FAIL=$((FAIL+1)); fi

run_bad 'ports rejects reserved port' env VULNMACHINESCTL_RESERVED_PORTS=5002 bash "$SCRIPT" ports
run_ok 'logs default' bash "$SCRIPT" logs vampi
run_ok 'logs with tail and service' bash "$SCRIPT" logs vampi --tail 10 vampi
assert_log 'logs forwards tail' 'logs --tail 10 vampi'
run_ok 'logs follow option' bash "$SCRIPT" logs vampi -f
run_bad 'logs rejects nonnumeric tail' bash "$SCRIPT" logs vampi --tail invalid
run_bad 'logs rejects unknown flag' bash "$SCRIPT" logs vampi --wrong
run_bad 'shell rejects invalid service' bash "$SCRIPT" shell vampi '../bad'
run_bad 'shell requires running service' bash "$SCRIPT" shell vampi
run_ok 'shell with running service' env MOCK_RUNNING=1 bash "$SCRIPT" shell vampi vampi
assert_log 'shell uses docker compose exec' 'exec -T vampi bash -c exit 0'
run_ok 'restart (service already running)' env MOCK_RUNNING=1 bash "$SCRIPT" restart vampi
assert_log 'restart calls docker compose restart' 'restart'
run_ok 'restart (service stopped)' bash "$SCRIPT" restart vampi
run_ok 'down' bash "$SCRIPT" down vampi
assert_log 'down calls Docker Compose' 'down'
run_ok 'down all (non-destructive)' bash "$SCRIPT" down all
run_bad 'remove rejects incorrect confirmation' bash -c 'printf "wrong\n" | bash "$1" remove vampi' _ "$SCRIPT"
assert_file 'incorrect remove preserves data' "$LABS_DIR/vampi/docker-compose.yml"
run_ok 'remove with explicit confirmation' bash -c 'printf "vampi\n" | bash "$1" remove vampi' _ "$SCRIPT"
if [[ ! -d "$LABS_DIR/vampi" ]]; then printf 'PASS remove deletes managed directory\n'; PASS=$((PASS+1)); else printf 'FAIL remove retained directory\n' >&2; FAIL=$((FAIL+1)); fi
run_ok 'remove nonexistent lab is safe' bash "$SCRIPT" remove vampi
run_ok 'install for purge scenario' bash "$SCRIPT" install vampi
run_bad 'purge rejects incorrect confirmation' bash -c 'printf "wrong\n" | bash "$1" purge' _ "$SCRIPT"
assert_file 'incorrect purge preserves data' "$LABS_DIR/vampi/docker-compose.yml"
run_ok 'purge with explicit confirmation' bash -c 'printf "DELETE ALL\n" | bash "$1" purge' _ "$SCRIPT"
if [[ ! -e "$LABS_DIR/vampi" ]]; then printf 'PASS purge deletes managed lab\n'; PASS=$((PASS+1)); else printf 'FAIL purge retained lab\n' >&2; FAIL=$((FAIL+1)); fi
mkdir -p "$TMP/foreign/dvga"
run_bad 'foreign directory is never adopted' env LABS_DIR="$TMP/foreign" bash "$SCRIPT" install dvga
run_bad 'missing lab for restart is rejected' bash "$SCRIPT" restart vampi
run_bad 'missing lab for logs is rejected' bash "$SCRIPT" logs vampi
run_bad 'missing lab for shell is rejected' bash "$SCRIPT" shell vampi
run_ok 'HTTP failure handled without opening browser' env MOCK_HTTP_FAIL=1 bash "$SCRIPT" up vampi --no-open

# Regression: an already installed OAuth2 lab must have removed npm's missing
# array-set@0.1.2 dependency before any Docker build is invoked.
mkdir -p "$LABS_DIR/oauth2/repo/insecureapplication/gallery"
: > "$LABS_DIR/oauth2/.vulnmachinesctl-installed"
: > "$LABS_DIR/oauth2/docker-compose.yml"
cat > "$LABS_DIR/oauth2/repo/insecureapplication/gallery/package.json" <<'EOF'
{"name":"gallery","dependencies":{"array-set":"^0.1.2","express":"^4.16.3"}}
EOF
cat > "$LABS_DIR/oauth2/repo/insecureapplication/gallery/package-lock.json" <<'EOF'
{"name":"gallery","lockfileVersion":1,"dependencies":{"array-set":{"version":"0.1.2"},"express":{"version":"4.16.3"}}}
EOF
# Existing installs with the old seed build must migrate to matching MongoDB tools.
cat > "$LABS_DIR/oauth2/docker-compose.yml" <<'EOF'
services:
  mongoseed:
    build: ./repo/insecureapplication/mongo-seed
    restart: "no"
    command: mongorestore --host mongodb:27017 -d gallery2 mongodbdata/gallery2
    depends_on:
      mongodb:
        condition: service_healthy
EOF
run_ok 'oauth2 up fixes npm manifests before building' bash "$SCRIPT" up oauth2 --no-open
if grep -Fq 'image: mongo:4.0' "$LABS_DIR/oauth2/docker-compose.yml" \
  && grep -Fq 'mongo-seed/mongodbdata:/mongodbdata:ro' "$LABS_DIR/oauth2/docker-compose.yml" \
  && ! grep -Fq 'build: ./repo/insecureapplication/mongo-seed' "$LABS_DIR/oauth2/docker-compose.yml"; then
  printf 'PASS oauth2 mongoseed migration to mongo:4.0\n'; PASS=$((PASS+1))
else
  printf 'FAIL oauth2 mongoseed migration\n' >&2; FAIL=$((FAIL+1))
fi
# Install must repair a previously installed OAuth2 lab without running Docker.
# Verify that both npm manifests and Compose are migrated and that no Docker
# calls are made during 'install'.
cat > "$LABS_DIR/oauth2/repo/insecureapplication/gallery/package.json" <<'EOF'
{"dependencies":{"array-set":"^0.1.2","express":"^4.16.3"}}
EOF
cat > "$LABS_DIR/oauth2/repo/insecureapplication/gallery/package-lock.json" <<'EOF'
{"lockfileVersion":1,"dependencies":{"array-set":{"version":"0.1.2"},"express":{"version":"4.16.3"}}}
EOF
cat > "$LABS_DIR/oauth2/docker-compose.yml" <<'EOF'
services:
  mongoseed:
    build: ./repo/insecureapplication/mongo-seed
    restart: "no"
    command: mongorestore --host mongodb:27017 -d gallery2 mongodbdata/gallery2
    depends_on:
      mongodb:
        condition: service_healthy
EOF
: > "$MOCK_LOG"
run_ok 'oauth2 install repairs existing installation' bash "$SCRIPT" install oauth2
if python3 -I - "$LABS_DIR/oauth2" <<'PYTEST'
import json
from pathlib import Path
import sys
p = Path(sys.argv[1])
for name in ('package.json','package-lock.json'):
    deps = json.loads((p/'repo/insecureapplication/gallery'/name).read_text())['dependencies']
    assert 'array-set' not in deps and 'express' in deps
compose = (p/'docker-compose.yml').read_text()
assert 'image: mongo:4.0' in compose
assert 'mongo-seed/mongodbdata:/mongodbdata:ro' in compose
assert 'build: ./repo/insecureapplication/mongo-seed' not in compose
PYTEST
then printf 'PASS oauth2 install applies both fixes\n'; PASS=$((PASS+1))
else printf 'FAIL oauth2 install fixes incomplete\n' >&2; FAIL=$((FAIL+1)); fi
if [[ ! -s "$MOCK_LOG" ]]; then
  printf 'PASS oauth2 install does not invoke Docker\n'; PASS=$((PASS+1))
else
  printf 'FAIL oauth2 install unexpectedly invoked Docker\n' >&2; FAIL=$((FAIL+1))
fi
run_ok 'oauth2 install can be rerun safely' bash "$SCRIPT" install oauth2

run_ok 'oauth2 npm repair is idempotent' bash "$SCRIPT" up oauth2 --no-open
if python3 -I - "$LABS_DIR/oauth2/repo/insecureapplication/gallery" <<'PYTEST'
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
for name in ("package.json", "package-lock.json"):
    deps = json.loads((root / name).read_text())["dependencies"]
    assert "array-set" not in deps
    assert "express" in deps
PYTEST
then printf 'PASS oauth2 removes only missing dependency\n'; PASS=$((PASS+1))
else printf 'FAIL oauth2 npm manifest repair\n' >&2; FAIL=$((FAIL+1))
fi

# Lifecycle test with the proxy enabled and an isolated hosts fixture.
mkdir -p "$TMP/proxy-labs"
printf '127.0.0.1 localhost\n' > "$TMP/proxy-hosts"
run_ok 'install lab for proxy lifecycle' env LABS_DIR="$TMP/proxy-labs" bash "$SCRIPT" install vampi
run_ok 'proxy up registers localhost alias' env LABS_DIR="$TMP/proxy-labs" VULNMACHINESCTL_PROXY=1 VULNMACHINESCTL_HOSTS_FILE="$TMP/proxy-hosts" bash "$SCRIPT" up vampi --no-open
run_ok 'ports reports active proxy route' env LABS_DIR="$TMP/proxy-labs" VULNMACHINESCTL_PROXY=1 VULNMACHINESCTL_HOSTS_FILE="$TMP/proxy-hosts" MOCK_RUNNING=1 bash "$SCRIPT" ports
if grep -Eq '^vampi[[:space:]]+vampi[[:space:]]+http://vampi[[:space:]]+active[[:space:]]+http://127.0.0.1:5002' "$TMP/out"; then
  printf 'PASS ports reports active short hostname accurately\n'; PASS=$((PASS+1))
else printf 'FAIL ports active short hostname missing\n' >&2; FAIL=$((FAIL+1)); fi
run_ok 'status reports active proxy route' env LABS_DIR="$TMP/proxy-labs" VULNMACHINESCTL_PROXY=1 VULNMACHINESCTL_HOSTS_FILE="$TMP/proxy-hosts" MOCK_RUNNING=1 bash "$SCRIPT" status
if grep -Eq '^vampi[[:space:]]+yes.*active[[:space:]]+http://vampi/ui/' "$TMP/out"; then
  printf 'PASS status reports active short hostname accurately\n'; PASS=$((PASS+1))
else printf 'FAIL status active short hostname missing\n' >&2; FAIL=$((FAIL+1)); fi

if [[ -f "$TMP/proxy-labs/.proxy/active/vampi" ]] && grep -Fq '127.0.0.1 vampi' "$TMP/proxy-hosts" && grep -Fq 'http://vampi {' "$TMP/proxy-labs/.proxy/Caddyfile"; then
  printf 'PASS proxy up creates Caddy route and host mapping\n'; PASS=$((PASS+1))
else printf 'FAIL proxy up did not install route and hostname\n' >&2; FAIL=$((FAIL+1)); fi
run_ok 'proxy down clears localhost alias' env LABS_DIR="$TMP/proxy-labs" VULNMACHINESCTL_PROXY=1 VULNMACHINESCTL_HOSTS_FILE="$TMP/proxy-hosts" bash "$SCRIPT" down vampi
run_ok 'ports after down show inactive proxy' env LABS_DIR="$TMP/proxy-labs" VULNMACHINESCTL_PROXY=1 VULNMACHINESCTL_HOSTS_FILE="$TMP/proxy-hosts" bash "$SCRIPT" ports
if grep -Eq '^vampi[[:space:]]+vampi[[:space:]]+http://vampi[[:space:]]+inactive' "$TMP/out"; then
  printf 'PASS ports shows inactive after down\n'; PASS=$((PASS+1))
else printf 'FAIL ports still active after down\n' >&2; FAIL=$((FAIL+1)); fi

if [[ ! -f "$TMP/proxy-labs/.proxy/active/vampi" ]] && ! grep -Fq '127.0.0.1 vampi' "$TMP/proxy-hosts"; then
  printf 'PASS proxy down cleans only owned hostname\n'; PASS=$((PASS+1))
else printf 'FAIL proxy down failed to clean hostname\n' >&2; FAIL=$((FAIL+1)); fi

# Independent tests of hostname and Caddy helpers (no /etc/hosts mutation).
HOSTS_FIXTURE="$TMP/hosts"
printf '127.0.0.1 localhost\n127.0.0.1 gallery\n10.1.2.3 foreign-host\n' > "$HOSTS_FIXTURE"
run_ok 'hosts add new managed entries' python3 -I scripts/hosts-manager.py --file "$HOSTS_FIXTURE" crapi gallery attacker
if grep -Fq '127.0.0.1 attacker crapi' "$HOSTS_FIXTURE" && [[ $(grep -c 'BEGIN VULNMACHINESCTL MANAGED' "$HOSTS_FIXTURE") == 1 ]]; then
  printf 'PASS hosts register only newly managed names\n'; PASS=$((PASS+1))
else printf 'FAIL hosts register managed names\n' >&2; FAIL=$((FAIL+1)); fi
run_ok 'hosts synchronization is idempotent' python3 -I scripts/hosts-manager.py --file "$HOSTS_FIXTURE" crapi gallery attacker
run_bad 'hosts reject foreign name ownership' python3 -I scripts/hosts-manager.py --file "$HOSTS_FIXTURE" foreign-host crapi
run_ok 'hosts remove managed entries' python3 -I scripts/hosts-manager.py --file "$HOSTS_FIXTURE"
if grep -Fq '127.0.0.1 gallery' "$HOSTS_FIXTURE" && ! grep -q 'BEGIN VULNMACHINESCTL MANAGED' "$HOSTS_FIXTURE" && grep -Fq '10.1.2.3 foreign-host' "$HOSTS_FIXTURE"; then
  printf 'PASS hosts preserve foreign and manually added entries\n'; PASS=$((PASS+1))
else printf 'FAIL hosts cleanup changed unrelated entries\n' >&2; FAIL=$((FAIL+1)); fi
printf 'crapi|8888\ndvwa|4280\ngallery|3005\n' | python3 -I scripts/proxy-render.py > "$TMP/Caddyfile"
if grep -Fq 'http://crapi {' "$TMP/Caddyfile" && grep -Fq 'reverse_proxy 127.0.0.1:8888' "$TMP/Caddyfile" && grep -Fq 'bind 127.0.0.1' "$TMP/Caddyfile"; then
  printf 'PASS proxy renders short hostnames and localhost binding\n'; PASS=$((PASS+1))
else printf 'FAIL proxy render invalid\n' >&2; FAIL=$((FAIL+1)); fi
run_bad 'proxy rejects duplicate hostnames' bash -c "printf 'crapi|8888\\ncrapi|5000\\n' | python3 -I scripts/proxy-render.py >/dev/null"
run_bad 'proxy rejects unsafe domain names' bash -c "printf 'evil.test|5000\\n' | python3 -I scripts/proxy-render.py >/dev/null"

printf '\nTests: %d passed, %d failed\n' "$PASS" "$FAIL"
(( FAIL == 0 ))
