#!/bin/sh
# Writes more stdout than a pipe holds before it reads its request.
head -c 262144 /dev/zero | tr '\0' 'o'
cat >/dev/null
