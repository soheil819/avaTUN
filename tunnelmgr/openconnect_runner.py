#!/usr/bin/env python3
"""Run an OpenConnect site peer in the foreground under systemd."""
import json
import pathlib
import shutil
import sys


def main():
    if len(sys.argv)!=2:
        raise SystemExit('usage: openconnect_runner.py CONFIG.json')
    config=json.loads(pathlib.Path(sys.argv[1]).read_text())
    binary=shutil.which('openconnect')
    if not binary:
        raise SystemExit('openconnect executable is missing')
    args=[binary,'--protocol=anyconnect','--non-inter','--interface='+config['interface'],
          '--cafile='+config['cafile'],'--certificate='+config['certificate'],
          '--sslkey='+config['key'],f"https://{config['server']}:{int(config['port'])}"]
    import os
    os.execv(binary,args)


if __name__=='__main__':
    main()
