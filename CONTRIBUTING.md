# Contributing to VulnMachinesCTL

Thanks for helping improve this vulnerable-machines and Docker lab manager.

## Before submitting a pull request

1. Open an issue describing the bug or proposed feature.
2. Keep vulnerable services bound to localhost wherever possible.
3. Never add real secrets, personal data, exploit data from unauthorized targets, or credentials from real systems.
4. Run the checks below:

```bash
bash -n vulnmachinesctl.sh
bash tests/tests.sh
bash tests/check-secrets.sh
```

## Adding a lab

Update the lab catalog, its installation/access/readiness handlers, the README lab table, and the command tests. Credit the upstream project and document any extra network exposure or dependencies.

## Testing

Command tests do not demonstrate that upstream Docker images are healthy. Test Docker changes on an isolated, disposable machine.

### Local proxy tests

The CLI regression suite includes an isolated `/etc/hosts` fixture and a mocked
Docker engine; it never needs root privileges. New lab entries should keep their
readiness URLs on `127.0.0.1` to support automatic Caddy route generation.
Do not expose lab ports or the proxy outside localhost.
