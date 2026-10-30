#!/bin/sh
set -eu
tor -f /etc/tor/torrc --DisableNetwork 1 >/tmp/tor-init.log 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT INT TERM
attempt=0
while [ ! -f /var/lib/tor/onion/hostname ]; do
  if ! kill -0 "$pid" 2>/dev/null; then cat /tmp/tor-init.log >&2; exit 1; fi
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 50 ]; then echo 'Tor identity initialization timed out.' >&2; exit 1; fi
  sleep 0.1
done
cat /var/lib/tor/onion/hostname
