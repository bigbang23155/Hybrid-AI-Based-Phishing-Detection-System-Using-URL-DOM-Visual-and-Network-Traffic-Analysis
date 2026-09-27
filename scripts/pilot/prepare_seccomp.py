"""Retain upstream policy and allow Chromium's namespace-local chroot syscall.

With Docker --cap-drop ALL, upstream's CAP_SYS_CHROOT-conditional rule is omitted.
Chromium still needs chroot after entering its own unprivileged user namespace.
This syscall allowance grants no host/container capability; the kernel continues
to enforce namespace capabilities. No other syscall rule is changed.
"""
import json
from pathlib import Path
import sys

source, destination = map(Path, sys.argv[1:])
profile = json.loads(source.read_text())
profile['syscalls'].append({
    'names': ['chroot'], 'action': 'SCMP_ACT_ALLOW', 'args': [],
    'comment': 'Chromium chroot within its own user namespace; no capabilities granted',
    'includes': {}, 'excludes': {},
})
destination.write_text(json.dumps(profile, indent=2) + '\n')
