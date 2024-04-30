package governor

// FlowCancelTokenList Returns a list of `tokenConfigEntry`s representing tokens that can 'Flow Cancel'. This means that incoming transfers
// that use these tokens can reduce the 'daily usage' of the Governor configured for the destination chain.
// The list of tokens was generated by grepping the file `generated_mainnet_tokens.go` for "USDC", "USDT", and "DAI".
//
// Only tokens that are configured in the mainnet token list should be able to flow cancel. That is, if a token is 
// present in this list but not in the mainnet token lists, it should not flow cancel. 
//
// Note that the field `symbol` is unused. It is retained in this file only for convenience.
func FlowCancelTokenList() []tokenConfigEntry {
	return []tokenConfigEntry{
		// USDC variants
		{chain: 2, addr: "000000000000000000000000bcca60bb61934080951369a648fb03df4f96263c", symbol: "aUSDC"},
		{chain: 4, addr: "0000000000000000000000004268b8f0b87b6eae5d897996e6b845ddbd99adf3", symbol: "axlUSDC"},
		{chain: 5, addr: "0000000000000000000000001a13f4ca1d028320a707d99520abfefca3998b7f", symbol: "amUSDC"},
		{chain: 5, addr: "000000000000000000000000750e4c4984a9e0f12978ea6742bc1c5d248f40ed", symbol: "axlUSDC"},
		{chain: 6, addr: "000000000000000000000000fab550568c688d5d8a52c7d794cb93edc26ec0ec", symbol: "axlUSDC"},
		{chain: 6, addr: "000000000000000000000000a7d7079b0fead91f3e65f86e8915cb59c1a4c664", symbol: "USDC.e"},
		{chain: 10, addr: "0000000000000000000000001b6382dbdea11d97f24495c9a90b7c88469134a4", symbol: "axlUSDC"},
		{chain: 10, addr: "00000000000000000000000028a92dde19d9989f39a49905d7c9c2fac7799bdf", symbol: "USDC"},
		{chain: 10, addr: "00000000000000000000000027e611fd27b276acbd5ffd632e5eaebec9761e40", symbol: "DAI+USDC"},
		{chain: 13, addr: "000000000000000000000000754288077d0ff82af7a5317c7cb8c444d421d103", symbol: "oUSDC"},
		{chain: 14, addr: "000000000000000000000000eb466342c4d449bc9f53a865d5cb90586f405215", symbol: "axlUSDC"},
		{chain: 16, addr: "000000000000000000000000ca01a1d0993565291051daff390892518acfad3a", symbol: "axlUSDC"},
		{chain: 23, addr: "000000000000000000000000625e7708f30ca75bfd92586e17077590c60eb4cd", symbol: "aArbUSDC"},
		{chain: 24, addr: "000000000000000000000000625e7708f30ca75bfd92586e17077590c60eb4cd", symbol: "aOptUSDC"},
		{chain: 30, addr: "000000000000000000000000eb466342c4d449bc9f53a865d5cb90586f405215", symbol: "axlUSDC"},

		// USDT variants
		{chain: 1, addr: "b7db4e83eb727f1187bd7a50303f5b4e4e943503da8571ad6564a51131504792", symbol: ""},
		{chain: 1, addr: "ce010e60afedb22717bd63192f54145a3f965a33bb82d2c7029eb2ce1e208264", symbol: "USDT"},
		{chain: 2, addr: "000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7", symbol: "USDT"},
		{chain: 4, addr: "00000000000000000000000055d398326f99059ff775485246999027b3197955", symbol: "USDT"},
		{chain: 5, addr: "000000000000000000000000c2132d05d31c914a87c6611c10748aeb04b58e8f", symbol: "USDT"},
		{chain: 6, addr: "0000000000000000000000009702230a8ea53601f5cd2dc00fdbc13d4df4a8c7", symbol: "USDt"},
		{chain: 6, addr: "000000000000000000000000c7198437980c041c805a1edcba50c1ce5db95118", symbol: "USDT.e"},
		{chain: 8, addr: "000000000000000000000000000000000000000000000000000000000004c5c1", symbol: "USDt"},
		{chain: 9, addr: "0000000000000000000000004988a896b1227218e4a686fde5eabdcabd91571f", symbol: "USDT"},
		{chain: 10, addr: "000000000000000000000000cc1b99ddac1a33c201a742a1851662e87bc7f22c", symbol: "USDT"},
		{chain: 10, addr: "000000000000000000000000049d68029688eabf473097a2fc38ef61633a3c7a", symbol: "fUSDT"},
		{chain: 13, addr: "000000000000000000000000cee8faf64bb97a73bb51e115aa89c17ffa8dd167", symbol: "oUSDT"},
		{chain: 16, addr: "000000000000000000000000efaeee334f0fd1712f9a8cc375f427d9cdd40d73", symbol: "USDT"},
		{chain: 16, addr: "000000000000000000000000ffffffffea09fb06d082fd1275cd48b191cbcd1d", symbol: "xcUSDT"},
		{chain: 23, addr: "000000000000000000000000fd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9", symbol: "USDT"},
		{chain: 24, addr: "00000000000000000000000094b008aa00579c1307b0ef2c499ad98a8ce58e58", symbol: "USDT"},

		// DAI variants (DAI+USDC is included under the USDC list above)
		{chain: 2, addr: "0000000000000000000000006b175474e89094c44da98b954eedeac495271d0f", symbol: "DAI"},
		{chain: 4, addr: "0000000000000000000000001af3f329e8be154074d8769d1ffa4ee058b1dbc3", symbol: "DAI"},
		{chain: 5, addr: "0000000000000000000000008f3cf7ad23cd3cadbd9735aff958023239c6a063", symbol: "DAI"},
		{chain: 6, addr: "000000000000000000000000d586e7f844cea2f87f50152665bcbc2c279d8d70", symbol: "DAI.e"},
		{chain: 10, addr: "0000000000000000000000008d11ec38a3eb5e956b052f67da8bdc9bef8abf3e", symbol: "DAI"},
		{chain: 13, addr: "0000000000000000000000005c74070fdea071359b86082bd9f9b3deaafbe32b", symbol: "KDAI"},
		{chain: 16, addr: "000000000000000000000000765277eebeca2e31912c9946eae1021199b39c61", symbol: "DAI"},
		{chain: 23, addr: "000000000000000000000000da10009cbd5d07dd0cecc66161fc93d7c9000da1", symbol: "DAI"},
		{chain: 24, addr: "000000000000000000000000da10009cbd5d07dd0cecc66161fc93d7c9000da1", symbol: "DAI"},
		{chain: 30, addr: "00000000000000000000000050c5725949a6f0c72e6c4a641f24049a917db0cb", symbol: "DAI"},
	}
}
