#!/usr/bin/env python3
"""Render a localhost-bound Caddy configuration from validated route records."""
import re
import sys

rows = []
for line in sys.stdin:
    parts = line.strip().split('|')
    if not line.strip():
        continue
    if len(parts) != 2:
        sys.exit('Invalid proxy route record')
    host, port = parts
    if not re.fullmatch(r'[a-z][a-z0-9-]{0,62}', host):
        sys.exit(f'Invalid host: {host}')
    if not port.isdecimal() or not 1 <= int(port) <= 65535:
        sys.exit(f'Invalid port: {port}')
    rows.append((host, int(port)))
if len(set(h for h, _ in rows)) != len(rows):
    sys.exit('Conflicting proxy hostnames')
print('{\n    auto_https off\n    admin off\n}\n')
for host, port in sorted(rows):
    print(f'http://{host} {{')
    print('    bind 127.0.0.1')
    print(f'    reverse_proxy 127.0.0.1:{port}')
    print('}\n')
