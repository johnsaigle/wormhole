#!/bin/bash

if [ $CI ]; then
  if [ $CHAIN_ID -eq 4 ]; then
    RPC_URL='http://eth-devnet2:8545'
  else 
    RPC_URL='http://eth-devnet:8545'
  fi
else 
  if [ $CHAIN_ID -eq 4 ]; then
    RPC_URL='http://localhost:8546'
  else 
    RPC_URL='http://localhost:8545'
  fi
fi

PRIVATE_KEY=0x4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d

PRIVATE_KEY=$PRIVATE_KEY RPC_URL=$RPC_URL npm run deploy-contracts 

forge script ./forge-scripts/DeployTestToken.s.sol:DeployTestToken --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast

# Get Token Bridge and NFT Bridge addresses

returnInfo=$(cat ./broadcast/DeployTokenBridge.s.sol/1/run-latest.json)
TOKEN_BRIDGE_ADDRESS=$(jq -r '.returns.deployedAddress.value' <<< "$returnInfo")

returnInfo=$(cat ./broadcast/DeployNFTBridge.s.sol/1/run-latest.json)
NFT_BRIDGE_ADDRESS=$(jq -r '.returns.deployedAddress.value' <<< "$returnInfo")

# Registration of chains
token_bridge_registration_vaas_arr=()
nft_bridge_registration_vaas_arr=()
while IFS= read -r line; do
  # Use a regular expression to match the desired pattern
  if [[ "$line" =~ ^REGISTER_.*_TOKEN_BRIDGE_VAA=([^[:space:]]+) ]]; then
    token_bridge_registration_vaas_arr+=("0x${BASH_REMATCH[1]}")
  fi
  if [[ "$line" =~ ^REGISTER_.*_NFT_BRIDGE_VAA=([^[:space:]]+) ]]; then
    nft_bridge_registration_vaas_arr+=("0x${BASH_REMATCH[1]}")
  fi
done < ".env"

token_bridge_registration_vaas="[$(IFS=','; echo "${token_bridge_registration_vaas_arr[*]}")]";
nft_bridge_registration_vaas="[$(IFS=','; echo "${nft_bridge_registration_vaas_arr[*]}")]";

echo 'token bridge address';
echo $TOKEN_BRIDGE_ADDRESS;
echo 'token bridge registrations';
echo $token_bridge_registration_vaas;

forge script ./forge-scripts/RegisterChainsTokenBridge.s.sol:RegisterChainsTokenBridge --sig "run(address,bytes[])" $TOKEN_BRIDGE_ADDRESS $token_bridge_registration_vaas --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
echo 'Registration of token bridges done';
forge script ./forge-scripts/RegisterChainsNFTBridge.s.sol:RegisterChainsNFTBridge --sig "run(address,bytes[])" $NFT_BRIDGE_ADDRESS $nft_bridge_registration_vaas --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
echo 'Registration of NFT bridges done';

npm run deploy-relayers-evm1

nc -lkn 2000