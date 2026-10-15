#!/bin/sh
# Starts another member of its process group, then runs past the deadline.
sleep 30 &
echo "$!" > "$MEMBER_PID_FILE"
exec sleep 30
