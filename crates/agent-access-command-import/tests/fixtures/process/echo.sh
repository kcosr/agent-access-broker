#!/bin/sh
# Reads the whole request, then answers with its size.
bytes=$(wc -c)
printf '{"ok":true,"result":{"bytes":%s}}\n' "$bytes"
