#!/bin/sh
# Writes past a small output cap, then keeps running.
head -c 65536 /dev/zero | tr '\0' 'x'
exec sleep 30
