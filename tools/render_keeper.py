#!/usr/bin/env python3
"""Embed the reviewed keeper source in CloudFormation, or verify it is in sync."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
p = ROOT / 'infra/frontend.yaml'
text = p.read_text()
start = text.index('      Code:\n        ZipFile: |\n', text.index('\n  Keeper:\n'))
start += len('      Code:\n        ZipFile: |\n')
end = text.index('\n  KeeperOnNewLog:', start)
source = (ROOT / 'infra/keeper.py').read_text()
expected = text[:start] + ''.join(('          ' + line if line else '') + '\n' for line in source.splitlines()) + text[end:]
if '--check' in sys.argv:
    if text != expected:
        sys.exit('Keeper inline source differs: run python3 tools/render_keeper.py')
else:
    p.write_text(expected)
