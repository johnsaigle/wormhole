#!/usr/bin/env bash
# Before running this script, ensure that anvil is running, e.g.:
#
# anvil --host 0.0.0.0 --base-fee 0 --fork-url $(worm info rpc mainnet ethereum) --mnemonic "myth like bonus scare over problem client lizard pioneer submit female collect" --fork-block-number 20641947 --fork-chain-id 1 --chain-id 1 --steps-tracing --auto-impersonate

set -xeuo pipefail

# mainnet core contract
CORE_CONTRACT="0x5306f64e312b581766351c07af79c72fcb1cd25147157fdc2f8ad76de9a3fb6a"
# mainnet token bridge contract
TOKEN_BRIDGE_CONTRACT="0x26efee2b51c911237888e5dc6702868abca3c7ac12c53f76ef8eba0697695e3d"

TOKEN_BRIDGE_EMITTER="0xccceeb29348f71bdd22ffef43a2a19c1f5b5e17c5cca5411529120182672ade5"

RPC=<RPC_HERE>

LOG_LEVEL="info"


# Do `make node` first to compile transfer-verifier into guardiand
/guardiand transfer-verifier-sui --suiRPC "${RPC}" \
   --suiCoreContract "${CORE_CONTRACT}" \
   --suiTokenBridgeContract "${TOKEN_BRIDGE_CONTRACT}" \
   --suiTokenBridgeEmitter "${TOKEN_BRIDGE_EMITTER}" \
   --logLevel "${LOG_LEVEL}"
