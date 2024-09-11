#!/usr/bin/env bash
set -uo pipefail

# mainnet core contract
export CORE_CONTRACT="0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B"
# mainnet token bridge contract
export TOKEN_BRIDGE_CONTRACT="0x3ee18B2214AFF97000D974cf647E7C347E8fa585"
# export ETH_FROM="0x3ee18B2214AFF97000D974cf647E7C347E8fa585"
export MNEMONIC="myth like bonus scare over problem client lizard pioneer submit female collect" # wormhole test account

USDC_ADDR="0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
# Wei value sent as msg.value
VALUE="1000"
USDC_AMOUNT="10"
# USDC_WHALE="0x40ec5B33f54e0E8A33A975908C5BA1c14e5BbbDf" # Polygon's ERC20 Bridge contract address on Ethereum Mainnet, used as a whale account
ANVIL_ACCOUNT="0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1" # Account0 reported by anvil when run using $MNEMONIC
ETH_WHALE="0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" # vitalik.eth
FROM="${ETH_WHALE}"
RECIPIENT="0x00000000000000000000000090F8bf6A479f320ead074411a4B0e7944Ea8c9C1" # $ANVIL_ACCOUNT normalized to Wormhole size
NONCE="234" # arbitrary
PAYLOAD="0x616263313233" # arbitrary bytes (not well-formed)

# Try reading a value from each of the contracts. If this fails, we can't continue.
echo "Checking environment..."
cast call $CORE_CONTRACT "chainId" &> /dev/null || (echo "Liveness check for core bridge failed. Is anvil running? Did you fork mainnet?" && exit 1)
cast call $TOKEN_BRIDGE_CONTRACT "chainId" &> /dev/null || (echo "Liveness check for token bridge failed. Is anvil running? Did you fork mainnet?" && exit 1)

echo "DEBUG:"
echo "- CORE_CONTRACT=${CORE_CONTRACT}"
echo "- TOKEN_BRIDGE_CONTRACT=${TOKEN_BRIDGE_CONTRACT}"
echo "- MNEMONIC=${MNEMONIC}"
echo "- FROM=${FROM}"
echo "- VALUE=${VALUE}" 
echo "- RECIPIENT=${RECIPIENT}" 
echo 

# === Call wrapAndTransferETH()
echo "Calling wrapAndTransferETH() as ${FROM}"
cast send --unlocked \
   --json \
   --from "${FROM}" \
   --value "$VALUE" \
   --mnemonic-passphrase "$MNEMONIC" \
   "$TOKEN_BRIDGE_CONTRACT" \
   "wrapAndTransferETH(uint16,bytes32,uint256,uint32)" \
   1 "$RECIPIENT" 1 1 
echo ""
#
# === Call wrapAndTransferETHWithPayload()
echo "Calling wrapAndTransferETHWithPayload() as ${FROM}"
cast send --unlocked \
   --json \
   --from "${FROM}" \
   --value "$VALUE" \
   --mnemonic-passphrase "$MNEMONIC" \
   "$TOKEN_BRIDGE_CONTRACT" \
   "wrapAndTransferETHWithPayload(uint16,bytes32,uint32,bytes)" \
   1 "${RECIPIENT}" 1 "${PAYLOAD}"
echo ""

# USDC.approve() so that the token bridge can move funds
echo "Calling USDC.approve() (to prep transferTokens endpoints) as ${FROM}"
cast send --unlocked \
   --json \
   --from "$FROM" \
   --value "0" \
   --mnemonic-passphrase "$MNEMONIC" \
   "$USDC_ADDR" \
   "approve(address, uint256)" \
   "$TOKEN_BRIDGE_CONTRACT" $((1000 * $USDC_AMOUNT))
echo ""

# === Call transferTokens()
# Note:
# - that msg.value() for this type of transaction must be 0
# - the final payload bytes are arbitrary
echo "Calling transferTokens() as ${FROM}"
cast send --unlocked \
   --json \
   --from "$FROM" \
   --value "0" \
   --mnemonic-passphrase "$MNEMONIC" \
   "$TOKEN_BRIDGE_CONTRACT" \
   "transferTokens(address,uint256,uint16,bytes32,uint256,uint32)" \
   "${USDC_ADDR}" "${USDC_AMOUNT}" 1 "${RECIPIENT}" 1 ${NONCE}
echo ""

# === Call transferTokensWithPayload()
# Note:
# - that msg.value() for this type of transaction must be 0
# - the final payload bytes are arbitrary
echo "Calling transferTokensWithPayload() as ${FROM}"
cast send --unlocked \
   --json \
   --from "$FROM" \
   --value "0" \
   --mnemonic-passphrase "$MNEMONIC" \
   "$TOKEN_BRIDGE_CONTRACT" \
   "transferTokensWithPayload(address,uint256,uint16,bytes32,uint32,bytes)" \
   "${USDC_ADDR}" "${USDC_AMOUNT}" 1 "${RECIPIENT}" "${NONCE}" "${PAYLOAD}"
echo ""

# === Malicious call to transferTokensWithPayload()
# This is the exploit scenario: the token bridge has called publishMessage() without a ERC20 Transfer
# This is done by impersonating the token bridge contract and sending a message directly to the core bridge.
# Ensure that anvil is using `--auto-impersonate` or else that account impersonation is enabled in your local environment.
FROM="${TOKEN_BRIDGE_CONTRACT}"
echo "Calling publishMessage as ${FROM}" 
cast send --unlocked \
   --json \
   --from "${FROM}" \
   --value "0" \
   --mnemonic-passphrase "$MNEMONIC" \
   "$CORE_CONTRACT" \
   "publishMessage(uint32,bytes,uint8)" \
   0 "${PAYLOAD}" 1
echo ""
