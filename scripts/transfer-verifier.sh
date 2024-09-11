#!/usr/bin/env bash
# Before running this script, ensure that anvil is running, e.g.:
#
# anvil --host 0.0.0.0 --base-fee 0 --fork-url $(worm info rpc mainnet ethereum) --mnemonic "myth like bonus scare over problem client lizard pioneer submit female collect" --fork-block-number 20641947 --fork-chain-id 1 --chain-id 1 --steps-tracing --auto-impersonate

set -xeuo pipefail

# mainnet core contract
CORE_CONTRACT="0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B"
# mainnet token bridge contract
TOKEN_BRIDGE_CONTRACT="0x3ee18B2214AFF97000D974cf647E7C347E8fa585"

# Needs to be websockets so that the eth connector can get notifications
ETH_RPC_DEVNET="ws://localhost:8545" # from Tilt, via Anvil

# RPC="${ALCHEMY_RPC}"
RPC="${ETH_RPC_DEVNET}"

LOG_LEVEL="debug"

# Do `make node` first to compile transfer-verifier into guardiand
./build/bin/guardiand transfer-verifier --ethRPC "${RPC}" \
   --ethContract "${CORE_CONTRACT}" \
   --tokenContract "${TOKEN_BRIDGE_CONTRACT}" \
   --logLevel "${LOG_LEVEL}"
