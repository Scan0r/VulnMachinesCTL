# Security policy

This repository deploys intentionally vulnerable software for authorized, local security training. Do not expose lab services to the public Internet or an untrusted network.

## Do not commit secrets

- Never commit real passwords, API keys, access tokens, SSH private keys, cloud credentials, personal details, or database backups.
- Keep environment-specific configuration in ignored `.env` files. Only commit sanitized `.env.example` templates.
- Treat usernames and passwords bundled with intentionally vulnerable upstream training apps as **public demonstration credentials**, not real secrets. Never reuse them for any real service.
- Inspect generated Docker Compose files and upstream projects before deploying. Some upstream images use intentionally insecure defaults.
- If a real secret is committed accidentally, revoke or rotate it immediately. Removing a commit does not make that secret safe again.

## Reporting

Please avoid posting exploits against real targets or credentials in public issues. Use GitHub's private vulnerability reporting feature, if enabled, for vulnerabilities in this manager.

## Local short-name reverse proxy

When enabled, VulnMachinesCTL launches Caddy with Linux host networking and
binds its HTTP listener only to `127.0.0.1:80`. Do not change the bind address
to a public interface. `/etc/hosts` updates are performed by the dedicated
`scripts/hosts-manager.py` helper; it preserves unrelated entries and refuses
to replace conflicting mappings. Only this helper may request `sudo`.

Short single-label domains (`http://crapi`, `http://gallery`) are local-only
names and are not suitable for public deployment. Legacy application routes
may still require their original port numbers. Use an isolated lab computer.
