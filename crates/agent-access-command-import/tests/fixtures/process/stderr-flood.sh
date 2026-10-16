#!/bin/sh
# Writes far more stderr than a pipe holds before it reads its request.
head -c 1048576 /dev/zero | tr '\0' 'e' >&2
cat >/dev/null
printf '{"ok":true}\n'
