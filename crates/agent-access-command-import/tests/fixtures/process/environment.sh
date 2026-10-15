#!/bin/sh
# Reports its arguments and working directory on stderr, and the
# environment it was started with on stdout.
printf '%s\n' "$#" "$@" "$(pwd -P)" >&2
cat >/dev/null
cat "/proc/$$/environ"
