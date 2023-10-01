#!/bin/sh

# Stabilize shell

command -v python3 >/dev/null 2>&1 && python3 -c 'import pty; pty.spawn("/bin/bash")'
command -v python >/dev/null 2>&1 && python -c 'import pty; pty.spawn("/bin/bash")'

# Find all Flags on system
cd ~
find ./ -type f -exec grep -o -i shc20\d\d{.*};

exit