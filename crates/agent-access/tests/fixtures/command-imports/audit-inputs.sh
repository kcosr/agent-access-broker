#!/bin/sh
# Synthetic command: independently controlled describe and invoke documents.
set -eu
if [ "$1" = describe ]; then
    cat "$MANIFEST"
else
    umask 077
    cat > "$REQUEST"
    if [ -f "${RESPONSE}.signal" ]; then kill -KILL $$; fi
    cat "$RESPONSE"
fi
