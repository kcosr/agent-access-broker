#!/bin/sh
# Consume the complete request and return one independently validated file.
cat >/dev/null
printf '%s\n' '{"ok":true,"result":{},"download":{"content":"AAECAw==","filename":"report.bin","contentType":"application/octet-stream"}}'
