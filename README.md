# VulnMachinesCTL — Vulnerable Machines & Docker Pentesting Lab Manager

**VulnMachinesCTL** is an open-source Bash CLI for deploying and managing **15 intentionally vulnerable machines and Docker pentesting labs**, focused on **web application security, API security, OWASP training, and ethical hacking**. Install, start, inspect, stop, and remove vulnerable lab environments with Docker Compose v2.

> **Scope:** The project manages containerized vulnerable applications and services, not full virtual machines. “Vulnerable machines” describes the practice targets, not a VM hypervisor.

> [!WARNING]
> These applications deliberately contain security vulnerabilities. **Run them only on a trusted, isolated machine.** Never expose their services to the Internet or an untrusted network. Avoid running unrelated sensitive workloads on the same Docker host.

## Why VulnMachinesCTL?

Instead of manually cloning and configuring vulnerable Docker applications, run a single command to manage common web and API penetration testing labs. The tool focuses on local, repeatable lab orchestration for cybersecurity education and authorized practice.

## Features

- 15 curated labs covering web, REST APIs, GraphQL, OAuth 2.0, and more.
- Automatic repository cloning, Compose configuration, and dependency setup.
- Detached startup with HTTP readiness polling and an **extra 2-second delay before opening Firefox**.
- Configurable browser, readiness timeout, and port bindings.
- Port collision detection and reserved-port protection (8080 reserved by default for Burp Suite).
- Logs, interactive shells, service status, and access information.
- Explicit confirmation for destructive actions, with managed-directory markers.
- Short lab URLs such as **`http://crapi`**, **`http://dvwa`**, and **`http://gallery`** using a local Caddy reverse proxy.
- `/etc/hosts` entries are managed automatically and removed on `down`, `remove`, or `purge`; only this narrowly scoped operation may request `sudo`.
- Most lab services are bound to `127.0.0.1` by default; check upstream Compose configurations (especially crAPI) before starting.

## Requirements

- Linux with Bash 4.3+ (Bash 4.4+ recommended)
- Docker Engine with the **Docker Compose v2** plugin
- `git`, `curl`, `python3`, `realpath` (coreutils)
- `ss` (recommended, for port checks)
- Linux host networking and an available **localhost port 80** for the optional Caddy container
- `sudo` access to update `/etc/hosts` (for automatic hostnames; never needed to run Docker)
- Firefox or a configurable browser, and a graphical session (optional)
- Sufficient RAM and disk space (large labs may require several gigabytes)

> Docker Desktop, WSL, and headless sessions may require additional configuration for browser opening. Docker must already be installed, running, and accessible to your user. Membership in the Docker group is effectively root-equivalent: only grant it on machines you trust.

## Install VulnMachinesCTL on Linux

```bash
git clone https://github.com/Scan0r/VulnMachinesCTL.git
cd vulnmachinesctl
chmod +x vulnmachinesctl.sh
./vulnmachinesctl.sh --help
./vulnmachinesctl.sh list
```

This repository is maintained at [Scan0r/VulnMachinesCTL](https://github.com/Scan0r/VulnMachinesCTL). You can also run `bash vulnmachinesctl.sh` without making the file executable.

## Quick start: deploy a vulnerable Docker lab

```bash
# See available labs
./vulnmachinesctl.sh list

# See an individual lab's access details
./vulnmachinesctl.sh info vampi

# Install and start VAmPI
./vulnmachinesctl.sh up vampi

# Check running containers and port mappings
./vulnmachinesctl.sh status
./vulnmachinesctl.sh ports

# Stop without deleting persistent data
./vulnmachinesctl.sh down vampi

# Start without opening a browser
./vulnmachinesctl.sh up dvwa --no-open
```

### Browser behavior

On `up`, the script checks the lab's HTTP endpoint until it responds with a 2xx/3xx/4xx status, performs any configured post-start action, **waits 2 additional seconds**, and then attempts to open the URL in Firefox. The delay only applies when a graphical environment and supported browser are available. An HTTP response does not guarantee every internal component is fully initialized.

```bash
VULNMACHINESCTL_BROWSER_DELAY=5 ./vulnmachinesctl.sh up webgoat
VULNMACHINESCTL_BROWSER=chromium ./vulnmachinesctl.sh up juice-shop
VULNMACHINESCTL_OPEN=0 ./vulnmachinesctl.sh up crapi
WAIT_TIMEOUT=600 ./vulnmachinesctl.sh up vulnerableapp
```

## Short hostnames and automatic local proxy

With the proxy enabled (the Linux/Kali default), a successful `up` starts a separate **Caddy** container in host-network mode, listening **only on 127.0.0.1:80**. `up` registers the lab's short hostname in `/etc/hosts`, and `down`, `remove`, and `purge` remove only the entries created by VulnMachinesCTL. `restart` restores them if necessary. `install` **never modifies `/etc/hosts`**.

```bash
./vulnmachinesctl.sh up crapi       # http://crapi
./vulnmachinesctl.sh up dvwa        # http://dvwa
./vulnmachinesctl.sh up oauth2      # http://photoprint, http://gallery, http://attacker
./vulnmachinesctl.sh down oauth2    # Removes its managed host entries
```

Use `http://` explicitly in the browser: a bare single-label hostname may otherwise be interpreted as a search. Short hostnames **do not use `.test` or another suffix**. The original `127.0.0.1:PORT` addresses remain available. OAuth2's legacy redirect URLs may still refer to `gallery:3005`, `photoprint:3000`, and `attacker:1337`, so their original ports are also retained.

The proxy requires that port 80 is free, Docker is available, and your host can authorize a narrowly scoped `/etc/hosts` change. The helper preserves unrelated entries and refuses to override names assigned to a different address. If the proxy cannot start or host edits are denied, the labs still use their original port-based addresses. Existing manually added `127.0.0.1 gallery` mappings are respected, not removed.

```bash
# Disable automatic proxy and /etc/hosts management
VULNMACHINESCTL_PROXY=0 ./vulnmachinesctl.sh up crapi
```

This proxy mode is designed for **Linux/Kali**, not Docker Desktop on Windows or macOS. A reverse proxy does not make a vulnerable application safe: keep the machine isolated and avoid browsing untrusted content on the lab host.

## Supported vulnerable machines and security labs

| Lab ID | Project | Focus |
|---|---|---|
| `crapi` | [OWASP crAPI](https://github.com/OWASP/crAPI) | API security, microservices |
| `dvga` | [DVGA](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) | GraphQL |
| `dvwa` | [DVWA](https://github.com/digininja/DVWA) | Classic web vulnerabilities |
| `dvws-node` | [DVWS Node](https://github.com/snoopysecurity/dvws-node) | REST, SOAP, XML-RPC, GraphQL |
| `juice-shop` | [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | Web application security challenges |
| `mutillidae` | [OWASP Mutillidae II](https://github.com/webpwnized/mutillidae) | Web, SOAP/REST, LDAP |
| `oauth2` | [Vulnerable OAuth 2.0 Apps](https://github.com/koenbuyens/Vulnerable-OAuth-2.0-Applications) | OAuth 2.0 flows |
| `vampi` | [VAmPI](https://github.com/erev0s/VAmPI) | REST API security |
| `vapi` | [vAPI](https://github.com/roottusk/vapi) | OWASP API Top 10 |
| `vulnbank` | [VulnBank](https://github.com/Commando-X/vuln-bank) | JWT, BOLA, GraphQL, business logic |
| `vulnerableapp` | [OWASP VulnerableApp](https://github.com/SasanLabs/VulnerableApp) | Web vulnerability training |
| `vulnlab` | [Yavuzlar VulnLab](https://github.com/Yavuzlar/VulnLab) | Multiple web vulnerability categories |
| `webgoat` | [OWASP WebGoat](https://github.com/WebGoat/WebGoat) | **Latest** Docker image (`webgoat/webgoat:latest`); modern WebGoat with WebWolf (version not pinned to 8.x) |
| `webgoat7` | [WebGoat 7.1](https://hub.docker.com/r/webgoat/webgoat-7.1) | **Legacy 7.1** Docker image; classic WebGoat lessons |
| `xvwa` | [XVWA](https://github.com/SVelizDonoso/xvwa) | PHP web security challenges |

All credit for the vulnerable applications belongs to their respective maintainers and contributors. This project is an independent deployment manager and is not endorsed by those projects.

## CLI commands

| Command | Action |
|---|---|
| `list` | List available labs |
| `info <lab>` | Show setup, credentials, and access URLs |
| `install <lab\|all>` | Generate installation files without starting containers |
| `up <lab\|all> [--yes] [--no-open]` | Start one or all labs in detached mode |
| `down <lab\|all>` | Stop services without removing lab data |
| `restart <lab>` | Restart one lab |
| `status` | Display installation, container health, short browser URL, and proxy state |
| `ports` | Display port mappings, short hostnames, direct URLs, proxy states, and conflicts |
| `logs <lab> [-f] [--tail N] [service]` | Read service logs |
| `shell <lab> [service]` | Start an interactive shell when available |
| `remove <lab>` | Remove lab files, Docker resources, and volumes after confirmation |
| `purge` | Remove all managed labs after typed confirmation |

## Command examples

All commands below assume you are in the repository root. Use `./vulnmachinesctl.sh` to run the CLI. Replace lab IDs with any supported name from `list`.

### `help` — show available commands

```bash
./vulnmachinesctl.sh --help
# Equivalent:
./vulnmachinesctl.sh help
```

### `list` — list all 15 available labs

```bash
./vulnmachinesctl.sh list
```

### `info` — show a lab's details and access URLs

```bash
./vulnmachinesctl.sh info crapi
./vulnmachinesctl.sh info webgoat
```

### `install` — prepare files without starting containers

```bash
./vulnmachinesctl.sh install dvwa
# Prepare every supported lab (may clone external repositories):
./vulnmachinesctl.sh install all
```

### `up` — install (if necessary) and start a lab

```bash
./vulnmachinesctl.sh up vampi
# Start without automatically opening the browser:
./vulnmachinesctl.sh up webgoat --no-open
# Start all labs, explicitly accepting the resource warning:
./vulnmachinesctl.sh up all --yes --no-open
```

`up all` can consume substantial CPU, memory and storage. Use it only in an isolated environment with enough resources.

### `down` — stop containers without deleting persistent data

```bash
./vulnmachinesctl.sh down vampi
# Stop all managed labs:
./vulnmachinesctl.sh down all
```

### `restart` — restart an installed lab

```bash
./vulnmachinesctl.sh restart dvwa
```

### `status` — inspect installations, browser URLs, and proxy state

```bash
./vulnmachinesctl.sh status
```

The `URL` column shows each installed lab's browser entry point (for example,
`http://vampi/ui/` or `http://photoprint/` for OAuth2). The `PROXY` column
indicates whether the local short-hostname route is `active`, `inactive`,
`unavailable`, or `disabled`. Displaying a URL does **not** guarantee that
its HTTP server is reachable. Uninstalled labs display `-`.


### `ports` — inspect port mappings, hostnames, and conflicts

```bash
./vulnmachinesctl.sh ports
```

This command retains its existing `LAB / SERVICE / IP / PORT / TARGET` port
mapping and collision checks, and now adds a `LAB / HOST / URL / PROXY / DIRECT`
table. For example, after installing OAuth2 it includes `http://oauth2`,
`http://gallery`, `http://photoprint`, and `http://attacker`, plus their
corresponding direct `127.0.0.1:PORT` URLs. Routes are shown even when inactive;
use the `PROXY` column to distinguish a configured hostname from an active
proxy route. The command still returns a nonzero exit code for reserved or
conflicting ports.


### `logs` — read lab or service logs

```bash
# Show the last 200 log lines (default):
./vulnmachinesctl.sh logs dvwa
# Follow logs continuously:
./vulnmachinesctl.sh logs dvwa -f
# Show only the last 50 lines from the database service:
./vulnmachinesctl.sh logs dvwa --tail 50 db
```

Press `Ctrl+C` to stop following logs. The optional `service` is a Docker Compose service name, not a TCP port.

### `shell` — open an interactive shell inside a running service

```bash
# Enter the default DVWA service:
./vulnmachinesctl.sh shell dvwa
# Enter the database service instead:
./vulnmachinesctl.sh shell dvwa db
```

Type `exit` to leave the shell. Some minimal images, such as Juice Shop's distroless image, do not include a shell.

### `remove` — permanently delete one lab

```bash
./vulnmachinesctl.sh remove dvwa
# When prompted, type exactly: dvwa
```

**Destructive:** this removes the lab's managed files and associated Docker data, including persistent volumes; images shared with other labs are preserved.

### `purge` — permanently delete all managed labs

```bash
./vulnmachinesctl.sh purge
# When prompted, type exactly: DELETE ALL
```

**Destructive:** this deletes the managed labs' local directories, containers, networks and Docker volumes. It does not perform a global Docker cleanup.

### Environment variable examples

```bash
# Store labs in a custom dedicated folder:
LABS_DIR="$HOME/pentest/vuln-labs" ./vulnmachinesctl.sh install dvwa
# Wait up to 10 minutes for an HTTP readiness response:
WAIT_TIMEOUT=600 ./vulnmachinesctl.sh up vulnerableapp
# Delay browser opening by 5 seconds after the readiness check:
VULNMACHINESCTL_BROWSER_DELAY=5 ./vulnmachinesctl.sh up webgoat
# Disable automatic browser opening entirely:
VULNMACHINESCTL_OPEN=0 ./vulnmachinesctl.sh up crapi
# Reserve host ports 8080 and 9000:
VULNMACHINESCTL_RESERVED_PORTS="8080 9000" ./vulnmachinesctl.sh ports
```

## Configuration and browser startup

| Variable | Default | Purpose |
|---|---|---|
| `LABS_DIR` | `./vuln-labs` | Installation root |
| `WAIT_TIMEOUT` | `300` | Maximum HTTP readiness wait (seconds) |
| `VULNMACHINESCTL_BROWSER` | `firefox` | Browser command |
| `VULNMACHINESCTL_BROWSER_DELAY` | `2` | Extra seconds before launching the browser |
| `VULNMACHINESCTL_OPEN` | `1` | Set `0` to disable browser opening |
| `VULNMACHINESCTL_RESERVED_PORTS` | `8080` | Reserved host TCP ports (space-separated) |

Each installed lab also has its own `.env` file in `vuln-labs/<lab>`. Edit that file to adjust supported published ports. Note that some OAuth redirect URIs depend on fixed hostnames and ports.

## Privacy and safe publishing

This repository intentionally includes publicly documented **demo credentials** that certain upstream vulnerable labs require to run. They must never be used on real systems. It does **not** require any personal passwords, tokens, or private keys. Local `.env` files, key material and lab data are excluded by `.gitignore`. Run `bash tests/check-secrets.sh` and review `git diff --cached` before pushing. See [SECURITY.md](SECURITY.md) for disclosure and secret-handling guidance.

## Safety and limitations

- This tool is for **authorized local training only**.
- Legacy upstream Docker images and build dependencies may be unmaintained or unavailable; successful startup depends on those external projects.
- The `crapi` project uses its upstream Compose file and should be reviewed for port bindings before deployment.
- `remove` and `purge` delete **persistent Docker volumes and lab files**. Back up anything you need first.
- `install` does not build or launch containers; use `up` for that.
- `up all` may consume substantial system resources and should be used only on a machine sized for it.

## Verification

```bash
bash -n vulnmachinesctl.sh
bash tests/tests.sh
bash tests/check-secrets.sh
# Optional, if installed:
shellcheck vulnmachinesctl.sh
```

GitHub Actions runs syntax, secret-pattern, and CLI command tests on pull requests and pushes. **These checks do not deploy all 15 labs.** Live Docker deployment tests should be performed separately on a disposable, isolated machine.

## Contributing

Issues and pull requests are welcome. When adding a lab, update the catalog, its install/access/readiness functions, this README, and the command tests. Avoid changes that publish vulnerable services to external interfaces.

## License

See [LICENSE](LICENSE). The upstream lab projects have their own independent licenses.

## Related search terms

This project is relevant to **vulnerable machines**, **Docker pentesting labs**, **vulnerable web applications**, **API security labs**, **OWASP labs**, and **penetration testing lab management**. It is not a virtual-machine provisioning tool.
