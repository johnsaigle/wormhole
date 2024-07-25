// This file contains the token and chain config to be used in the devnet environment.

package governor

import (
	"github.com/wormhole-foundation/wormhole/sdk/vaa"
)

func (gov *ChainGovernor) initDevnetConfig() ([]tokenConfigEntry, []tokenConfigEntry, []chainConfigEntry) {
	gov.logger.Info("setting up devnet config")

	gov.dayLengthInMinutes = 5

	tokens := []tokenConfigEntry{
		{chain: 1, addr: "069b8857feab8184fb687f634618c035dac439dc1aeb3b5598a0f00000000001", symbol: "SOL", coinGeckoId: "wrapped-solana", decimals: 8, price: 34.94}, // Addr: So11111111111111111111111111111111111111112, Notional: 4145006
		{chain: 1, addr: "3b442cb3912157f13a933d0134282d032b5ffecd01a2dbf1b7790608df002ea7", symbol: "USDC", coinGeckoId: "usdc", decimals: 6, price: 1},              // Addr: 4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU, Notional: 1
		{chain: 2, addr: "000000000000000000000000DDb64fE46a91D46ee29420539FC25FD07c5FEa3E", symbol: "WETH", coinGeckoId: "weth", decimals: 8, price: 1174},
	}

	flowCancelTokens := []tokenConfigEntry{}
	if gov.flowCancelEnabled {
		flowCancelTokens = []tokenConfigEntry{
			{chain: 1, addr: "3b442cb3912157f13a933d0134282d032b5ffecd01a2dbf1b7790608df002ea7", symbol: "USDC", coinGeckoId: "usdc", decimals: 6, price: 1}, // Addr: 4zMMC9srt5Ri5X14GAgXhaHii3GnPAEERYPJgZJDncDU, Notional: 1
		}
	}

	chains := []chainConfigEntry{
		{emitterChainID: vaa.ChainIDSolana, dailyLimit: 100, bigTransactionSize: 75},
		{emitterChainID: vaa.ChainIDEthereum, dailyLimit: 100000},
	}

	return tokens, flowCancelTokens, chains
}
