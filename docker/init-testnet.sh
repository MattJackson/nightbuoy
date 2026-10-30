#!/bin/sh
set -eu
# This is an isolated development network: four containers, one operator.
ready=0
partial=0
for index in 0 1 2 3; do
  if [ -f "/nodes/node$index/.network-ready" ]; then ready=$((ready + 1)); fi
  if [ -f "/nodes/node$index/comet/config/genesis.json" ]; then partial=$((partial + 1)); fi
done
if [ "$ready" -eq 4 ]; then echo 'Existing test network retained.'; exit 0; fi
if [ "$partial" -gt 0 ]; then
  echo 'Partial or existing network found. Refusing to replace validator keys; inspect the volumes before recovery.' >&2
  exit 1
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cometbft testnet --v 4 --o "$work/network" --hostname-prefix node
for index in 0 1 2 3; do
  mkdir -p "/nodes/node$index/comet" "/nodes/node$index/app"
  cp -a "$work/network/node$index/." "/nodes/node$index/comet/"
  config="/nodes/node$index/comet/config/config.toml"
  sed -i 's/^allow_duplicate_ip = .*/allow_duplicate_ip = true/' "$config"
  sed -i 's/^timeout_commit = .*/timeout_commit = "500ms"/' "$config"
  sed -i 's/^max_tx_bytes = .*/max_tx_bytes = 8500000/' "$config"
  sed -i 's/^timeout_broadcast_tx_commit = .*/timeout_broadcast_tx_commit = "10s"/' "$config"
  chown -R 10001:10001 "/nodes/node$index"
  chmod 700 "/nodes/node$index" "/nodes/node$index/comet" "/nodes/node$index/app"
done
for index in 0 1 2 3; do touch "/nodes/node$index/.network-ready"; done
echo 'Initialized four-node development network; no independent-operator fault tolerance is implied.'
