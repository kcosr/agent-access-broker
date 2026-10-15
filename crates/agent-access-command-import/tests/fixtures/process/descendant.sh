#!/bin/sh
# Leaves a descendant outside its process group holding stdout and stderr,
# then exits once the descendant has left the group.
setsid sh -c 'echo "$$" > "$DESCENDANT_PID_FILE"; exec sleep 5' &
while [ ! -s "$DESCENDANT_PID_FILE" ]; do
  sleep 0.01
done
printf '{"ok":true}\n'
