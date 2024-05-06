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

		// USDT variants
		{chain: 1, addr: "b7db4e83eb727f1187bd7a50303f5b4e4e943503da8571ad6564a51131504792", symbol: ""},
		{chain: 1, addr: "ce010e60afedb22717bd63192f54145a3f965a33bb82d2c7029eb2ce1e208264", symbol: "USDT"},
		{chain: 2, addr: "000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7", symbol: "USDT"},

		// DAI variants
		{chain: 2, addr: "0000000000000000000000006b175474e89094c44da98b954eedeac495271d0f", symbol: "DAI"},
	}
}
