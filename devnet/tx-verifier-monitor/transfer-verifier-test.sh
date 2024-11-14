#!/usr/bin/env bash
set -uo pipefail

RPC="${RPC_URL:-ws://eth-devnet:8545}"

# mainnet core contract
# export CORE_CONTRACT="0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B"
# mainnet token bridge contract
# export TOKEN_BRIDGE_CONTRACT="0x3ee18B2214AFF97000D974cf647E7C347E8fa585"

# TODO these can be CLI params from the sh/devnet script
CORE_BRIDGE_CONTRACT=0xC89Ce4735882C9F0f0FE26686c53074E09B0D550
TOKEN_BRIDGE_CONTRACT=0x0290FB167208Af455bB137780163b7B7a9a10C16

# export ETH_FROM="0x3ee18B2214AFF97000D974cf647E7C347E8fa585"
# TODO these can be a CLI params from the sh/devnet script
MNEMONIC=0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d

# TODO change to one of the deployed test tokens. Maybe a CLI param
ERC20_ADDR="0x47bdB2D7d6528C760b6f228b3B8F9F650169a10f" # Test token A
# 0xFFcf8FDEE72ac11b5c542428B35EEF5769C409f0; # account1 from anvil
# Wei value sent as msg.value
VALUE="1000"
TRANSFER_AMOUNT="10"
# USDC_WHALE="0x40ec5B33f54e0E8A33A975908C5BA1c14e5BbbDf" # Polygon's ERC20 Bridge contract address on Ethereum Mainnet, used as a whale account

ANVIL_USER0="0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1" # Account0 reported by anvil when run using $MNEMONIC
ANVIL_USER1="0xFFcf8FDEE72ac11b5c542428B35EEF5769C409f0" 
# TODO this may not be necessary when funding these accounts with vm.deal
ETH_WHALE="${ANVIL_USER0}" # this account should have a bunch of Eth (?)
FROM="${ETH_WHALE}"
RECIPIENT="0x00000000000000000000000090F8bf6A479f320ead074411a4B0e7944Ea8c9C1" # Anvil user0 normalized to Wormhole size. Doesn't matter what the value is
NONCE="234" # arbitrary

# Build the payload for token transfers. Declared on multiple lines to
# be more legible. Data pulled from an arbitrary LogMessagePublished event
# on etherscan. Metadata and fees commented out, leaving only the payload
# TODO does this encode USDC or something else?
PAYLOAD="0x"
declare -a SLOTS=(
   # "0000000000000000000000000000000000000000000000000000000000055baf"
   # "0000000000000000000000000000000000000000000000000000000000000000"
   # "0000000000000000000000000000000000000000000000000000000000000080"
   # "0000000000000000000000000000000000000000000000000000000000000001"
   # "00000000000000000000000000000000000000000000000000000000000000ae"
   "030000000000000000000000000000000000000000000000000000000005f5e1"
   "000000000000000000000000002260fac5e5542a773aa44fbcfedf7c193bc2c5"
   "9900020000000000000000000000000000000000000000000000000000000000"
   "000816001000000000000000000000000044eca3f6295d6d559ca1d99a5ef5a8"
   "f72b4160f10001010200c91f01004554480044eca3f6295d6d559ca1d99a5ef5"
   "a8f72b4160f10000000000000000000000000000000000000000000000000000"
)
for i in "${SLOTS[@]}"
do
   PAYLOAD="$PAYLOAD$i"
done

# Try reading a value from each of the contracts. If this fails, we can't continue.
# echo "Checking environment..."
# cast call $CORE_CONTRACT "chainId" &> /dev/null || (echo "Liveness check for core bridge failed. Is anvil running? Did you fork mainnet?" && exit 1)
# cast call $TOKEN_BRIDGE_CONTRACT "chainId" &> /dev/null || (echo "Liveness check for token bridge failed. Is anvil running? Did you fork mainnet?" && exit 1)

echo "DEBUG:"
echo "- RPC=${RPC}"
echo "- CORE_BRIDGE_CONTRACT=${CORE_BRIDGE_CONTRACT}"
echo "- TOKEN_BRIDGE_CONTRACT=${TOKEN_BRIDGE_CONTRACT}"
echo "- MNEMONIC=${MNEMONIC}"
echo "- FROM=${FROM}"
echo "- VALUE=${VALUE}" 
echo "- RECIPIENT=${RECIPIENT}" 
echo 

# Fund the token bridge from User0
echo "Funding token bridge using user0's balance"
cast send --unlocked \
   --rpc-url "${RPC}" \
   --from $ANVIL_USER0 \
   --value 10000000000 \
   ${TOKEN_BRIDGE_CONTRACT}
echo ""

   \
BALANCE_CORE=$(cast balance --rpc-url "${RPC}" $CORE_BRIDGE_CONTRACT)
BALANCE_TOKEN=$(cast balance --rpc-url "${RPC}" $TOKEN_BRIDGE_CONTRACT)
BALANCE_USER0=$(cast balance --rpc-url "${RPC}" $ANVIL_USER0)
echo "BALANCES:"
echo "- CORE_BRIDGE_CONTRACT=${BALANCE_CORE}"
echo "- TOKEN_BRIDGE_CONTRACT=${BALANCE_TOKEN}"
echo "- ANVIL_USER0=${BALANCE_USER0}"
echo 
# === [[ BEGIN HAPPY PATH TESTING ]] ====

# === Call wrapAndTransferETH()
# echo "Calling wrapAndTransferETH() as ${FROM}"
# NONCE=100
# cast send --unlocked \
#    --json \
#    --unlocked \
#    --from "${FROM}" \
#    --value "$VALUE" \
#    --private-key "$MNEMONIC" \
#    "$TOKEN_BRIDGE_CONTRACT" \
#    "wrapAndTransferETH(uint16,bytes32,uint256,uint32)" \
#    1 "$RECIPIENT" 1 "${NONCE}"
# echo ""
#
# # === Call wrapAndTransferETHWithPayload()
# echo "Calling wrapAndTransferETHWithPayload() as ${FROM}"
# cast send --unlocked \
#    --json \
#    --from "${FROM}" \
#    --value "$VALUE" \
#    --private-key "$MNEMONIC" \
#    "${TOKEN_BRIDGE_CONTRACT}" \
#    "wrapAndTransferETHWithPayload(uint16,bytes32,uint32,bytes)" \
#    1 "${RECIPIENT}" 1 "${PAYLOAD}"
# echo ""
#
# # approve() so that the token bridge can move funds
# echo "Calling approve() (to prep transferTokens endpoints) as ${FROM}"
# cast send --unlocked \
#    --json \
#    --from "$FROM" \
#    --value "0" \
#    --private-key "$MNEMONIC" \
#    "$ERC20_ADDR" \
#    "approve(address, uint256)" \
#    "$TOKEN_BRIDGE_CONTRACT" $((1000 * $TRANSFER_AMOUNT))
# echo ""
#
# # === Call transferTokens()
# # Note:
# # - that msg.value() for this type of transaction must be 0
# # - the final payload bytes are arbitrary
# echo "Calling transferTokens() as ${FROM}"
# cast send --unlocked \
#    --json \
#    --from "$FROM" \
#    --value "0" \
#    --private-key "$MNEMONIC" \
#    "${TOKEN_BRIDGE_CONTRACT}" \
#    "transferTokens(address,uint256,uint16,bytes32,uint256,uint32)" \
#    "${ERC20_ADDR}" "${TRANSFER_AMOUNT}" 1 "${RECIPIENT}" 1 ${NONCE}
# echo ""
#
# # === Call transferTokensWithPayload()
# # Note:
# # - that msg.value() for this type of transaction must be 0
# # - the final payload bytes are arbitrary
# echo "Calling transferTokensWithPayload() as ${FROM}"
# cast send --unlocked \
#    --json \
#    --from "${FROM}" \
#    --value "0" \
#    --private-key "$MNEMONIC" \
#    "${TOKEN_BRIDGE_CONTRACT}" \
#    "transferTokensWithPayload(address,uint256,uint16,bytes32,uint32,bytes)" \
#    "${ERC20_ADDR}" "${TRANSFER_AMOUNT}" 1 "${RECIPIENT}" "${NONCE}" "${PAYLOAD}"
# echo ""
#
# === [[ BEGIN ERROR PATH TESTING ]] ====

# === Malicious call to transferTokensWithPayload()
# This is the exploit scenario: the token bridge has called publishMessage() without a ERC20 Transfer or Deposit
# being present in the same receipt.
# This is done by impersonating the token bridge contract and sending a message directly to the core bridge.
# Ensure that anvil is using `--auto-impersonate` or else that account impersonation is enabled in your local environment.
echo "Calling publishMessage as ${TOKEN_BRIDGE_CONTRACT}" 
   # --private-key "$MNEMONIC" \
   # --max-fee 500000 \
cast send --unlocked \
   --rpc-url "${RPC}" \
   --json \
   --gas-limit 10000000 \
   --priority-gas-price 1 \
   --from "${TOKEN_BRIDGE_CONTRACT}" \
   --value "0" \
   "${CORE_BRIDGE_CONTRACT}" \
   "publishMessage(uint32,bytes,uint8)" \
   0 "${PAYLOAD}" 1
echo ""

# TODO we want to test the 'multicall' scenario encoded in the forge script

echo "Done Transfer Verifier integration test."
echo "Exiting."
