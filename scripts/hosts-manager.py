#!/usr/bin/env python3
"""Safely synchronize only VulnMachinesCTL-owned /etc/hosts entries.

Reads hostnames from a generated route list; never alters foreign entries.
"""
import argparse
import os
from pathlib import Path
import re
import sys
import tempfile

BEGIN = '# BEGIN VULNMACHINESCTL MANAGED'
END = '# END VULNMACHINESCTL MANAGED'
VALID_HOST = re.compile(r'^[a-z][a-z0-9-]{0,62}$')


def sync(hosts_path: Path, names: list[str]) -> None:
    original = hosts_path.read_text(encoding='utf-8')
    if original.count(BEGIN) != original.count(END) or original.count(BEGIN) > 1:
        raise ValueError('Unexpected managed block structure; /etc/hosts left untouched')
    prior = original
    if BEGIN in original:
        a = original.index(BEGIN)
        b = original.index(END, a) + len(END)
        original = (original[:a] + original[b:]).strip('\n') + '\n'
    own_names = []
    for name in sorted(set(names)):
        if not VALID_HOST.fullmatch(name):
            raise ValueError(f'Invalid hostname {name!r}')
        already_local = False
        for line in original.splitlines():
            raw = line.split('#', 1)[0].split()
            if len(raw) >= 2 and name in raw[1:]:
                if raw[0] != '127.0.0.1':
                    raise ValueError(f'Hostname {name!r} already maps to {raw[0]}; refusing to override')
                already_local = True  # Respect manually added localhost mappings.
        if not already_local:
            own_names.append(name)
    if own_names:
        original = original.rstrip('\n') + f'\n{BEGIN}\n127.0.0.1 {" ".join(own_names)}\n{END}\n'
    if original == prior:
        return
    st = hosts_path.stat()
    fd, temp_name = tempfile.mkstemp(prefix='.vulnmachinesctl-hosts-', dir=hosts_path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            f.write(original)
        os.chmod(temp_name, st.st_mode & 0o777)
        os.chown(temp_name, st.st_uid, st.st_gid)
        os.replace(temp_name, hosts_path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--file', default='/etc/hosts')
    ap.add_argument('names', nargs='*')
    args = ap.parse_args()
    try:
        sync(Path(args.file), args.names)
    except (OSError, ValueError) as exc:
        print(f'Hosts update refused: {exc}', file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__':
    sys.exit(main())
