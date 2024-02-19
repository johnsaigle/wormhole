package governor

// FlowCancelTokenList function  
// Returns a list of `tokenConfigEntry`s representing tokens that can 'Flow Cancel'. This means that incoming transfers
// that use these tokens can reduce the 'daily limit' of the Governor configured for the destination chain.
func FlowCancelTokenList() []tokenConfigEntry {
	// TODO: Remove price?
	return []tokenConfigEntry{
		// USDC variants
		{chain: 2, addr: "000000000000000000000000bcca60bb61934080951369a648fb03df4f96263c", symbol: "aUSDC", coinGeckoId: "aave-usdc", decimals: 6, price: 0.998114},                          // Addr: 0xbcca60bb61934080951369a648fb03df4f96263c, Notional: 6.995219087818
		{chain: 4, addr: "0000000000000000000000004268b8f0b87b6eae5d897996e6b845ddbd99adf3", symbol: "axlUSDC", coinGeckoId: "axlusdc", decimals: 6, price: 0.999198},                          // Addr: 0x4268b8f0b87b6eae5d897996e6b845ddbd99adf3, Notional: 19.587891901572
		{chain: 5, addr: "0000000000000000000000001a13f4ca1d028320a707d99520abfefca3998b7f", symbol: "amUSDC", coinGeckoId: "aave-polygon-usdc", decimals: 6, price: 1.006},                    // Addr: 0x1a13f4ca1d028320a707d99520abfefca3998b7f, Notional: 19.381652336
		{chain: 5, addr: "000000000000000000000000750e4c4984a9e0f12978ea6742bc1c5d248f40ed", symbol: "axlUSDC", coinGeckoId: "axlusdc", decimals: 6, price: 0.999198},                          // Addr: 0x750e4c4984a9e0f12978ea6742bc1c5d248f40ed, Notional: 76.498300119798
		{chain: 6, addr: "000000000000000000000000fab550568c688d5d8a52c7d794cb93edc26ec0ec", symbol: "axlUSDC", coinGeckoId: "axlusdc", decimals: 6, price: 0.999198},                          // Addr: 0xfab550568c688d5d8a52c7d794cb93edc26ec0ec, Notional: 0.5995188
		{chain: 6, addr: "000000000000000000000000a7d7079b0fead91f3e65f86e8915cb59c1a4c664", symbol: "USDC.e", coinGeckoId: "usd-coin-avalanche-bridged-usdc-e", decimals: 6, price: 0.994848}, // Addr: 0xa7d7079b0fead91f3e65f86e8915cb59c1a4c664, Notional: 29645.521614457244
		{chain: 10, addr: "0000000000000000000000001b6382dbdea11d97f24495c9a90b7c88469134a4", symbol: "axlUSDC", coinGeckoId: "axlusdc", decimals: 6, price: 0.999198},                         // Addr: 0x1b6382dbdea11d97f24495c9a90b7c88469134a4, Notional: 1.0991178000000001
		{chain: 10, addr: "00000000000000000000000028a92dde19d9989f39a49905d7c9c2fac7799bdf", symbol: "USDC", coinGeckoId: "layerzero-usdc", decimals: 6, price: 0.995952},                     // Addr: 0x28a92dde19d9989f39a49905d7c9c2fac7799bdf, Notional: 1562.644697220336
		{chain: 10, addr: "00000000000000000000000027e611fd27b276acbd5ffd632e5eaebec9761e40", symbol: "DAI+USDC", coinGeckoId: "curve-fi-dai-usdc", decimals: 18, price: 1},                    // Addr: 0x27e611fd27b276acbd5ffd632e5eaebec9761e40, Notional: 8.51097737
		{chain: 13, addr: "000000000000000000000000754288077d0ff82af7a5317c7cb8c444d421d103", symbol: "oUSDC", coinGeckoId: "orbit-bridge-klaytn-usdc", decimals: 6, price: 0.492307},          // Addr: 0x754288077d0ff82af7a5317c7cb8c444d421d103, Notional: 2.0682663838039996
		{chain: 14, addr: "000000000000000000000000eb466342c4d449bc9f53a865d5cb90586f405215", symbol: "axlUSDC", coinGeckoId: "axlusdc", decimals: 6, price: 0.999198},                         // Addr: 0xeb466342c4d449bc9f53a865d5cb90586f405215, Notional: 0.22678297407
		{chain: 16, addr: "000000000000000000000000ca01a1d0993565291051daff390892518acfad3a", symbol: "axlUSDC", coinGeckoId: "axlusdc", decimals: 6, price: 0.999198},                         // Addr: 0xca01a1d0993565291051daff390892518acfad3a, Notional: 14.98797
		{chain: 23, addr: "000000000000000000000000625e7708f30ca75bfd92586e17077590c60eb4cd", symbol: "aArbUSDC", coinGeckoId: "aave-usdc", decimals: 6, price: 0.998114},                      // Addr: 0x625e7708f30ca75bfd92586e17077590c60eb4cd, Notional: 0.00998114
		{chain: 24, addr: "000000000000000000000000625e7708f30ca75bfd92586e17077590c60eb4cd", symbol: "aOptUSDC", coinGeckoId: "aave-usdc", decimals: 6, price: 0.998114},                      // Addr: 0x625e7708f30ca75bfd92586e17077590c60eb4cd, Notional: 6.594714866064
		{chain: 30, addr: "000000000000000000000000eb466342c4d449bc9f53a865d5cb90586f405215", symbol: "axlUSDC", coinGeckoId: "axlusdc", decimals: 6, price: 0.999198},                         // Addr: 0xeb466342c4d449bc9f53a865d5cb90586f405215, Notional: 130.56240690399602

		// USDT variants
		{chain: 1, addr: "b7db4e83eb727f1187bd7a50303f5b4e4e943503da8571ad6564a51131504792", symbol: "", coinGeckoId: "wrapped-usdt-allbridge-from-polygon", decimals: 6, price: 0.99381},    // Addr: DNhZkUaxHXYvpxZ7LNnHtss8sQgdAfd1ZYS1fB7LKWUZ, Notional: 41.933567478929994
		{chain: 1, addr: "ce010e60afedb22717bd63192f54145a3f965a33bb82d2c7029eb2ce1e208264", symbol: "USDT", coinGeckoId: "tether", decimals: 6, price: 0.999123},                            // Addr: Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB, Notional: 1383106.683319508
		{chain: 2, addr: "000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7", symbol: "USDT", coinGeckoId: "tether", decimals: 6, price: 0.999123},                            // Addr: 0xdac17f958d2ee523a2206206994597c13d831ec7, Notional: 81478717.16563272
		{chain: 4, addr: "00000000000000000000000055d398326f99059ff775485246999027b3197955", symbol: "USDT", coinGeckoId: "tether", decimals: 18, price: 0.999123},                           // Addr: 0x55d398326f99059ff775485246999027b3197955, Notional: 482006.42150044587
		{chain: 5, addr: "000000000000000000000000c2132d05d31c914a87c6611c10748aeb04b58e8f", symbol: "USDT", coinGeckoId: "tether", decimals: 6, price: 0.999123},                            // Addr: 0xc2132d05d31c914a87c6611c10748aeb04b58e8f, Notional: 183198.24637116797
		{chain: 6, addr: "0000000000000000000000009702230a8ea53601f5cd2dc00fdbc13d4df4a8c7", symbol: "USDt", coinGeckoId: "tether", decimals: 6, price: 0.999123},                            // Addr: 0x9702230a8ea53601f5cd2dc00fdbc13d4df4a8c7, Notional: 26675.718128123965
		{chain: 6, addr: "000000000000000000000000c7198437980c041c805a1edcba50c1ce5db95118", symbol: "USDT.e", coinGeckoId: "tether-avalanche-bridged-usdt-e", decimals: 6, price: 0.996588}, // Addr: 0xc7198437980c041c805a1edcba50c1ce5db95118, Notional: 6117.304061632644
		{chain: 8, addr: "000000000000000000000000000000000000000000000000000000000004c5c1", symbol: "USDt", coinGeckoId: "tether", decimals: 6, price: 1.002},                               // Addr: 312769, Notional: 22.31747085
		{chain: 9, addr: "0000000000000000000000004988a896b1227218e4a686fde5eabdcabd91571f", symbol: "USDT", coinGeckoId: "tether", decimals: 6, price: 0.999123},                            // Addr: 0x4988a896b1227218e4a686fde5eabdcabd91571f, Notional: 506.743421925798
		{chain: 10, addr: "000000000000000000000000cc1b99ddac1a33c201a742a1851662e87bc7f22c", symbol: "USDT", coinGeckoId: "bridged-tether-stargate", decimals: 6, price: 1},                 // Addr: 0xcc1b99ddac1a33c201a742a1851662e87bc7f22c, Notional: 1
		{chain: 10, addr: "000000000000000000000000049d68029688eabf473097a2fc38ef61633a3c7a", symbol: "fUSDT", coinGeckoId: "tether", decimals: 6, price: 0.999123},                          // Addr: 0x049d68029688eabf473097a2fc38ef61633a3c7a, Notional: 2337.86050664103
		{chain: 13, addr: "000000000000000000000000cee8faf64bb97a73bb51e115aa89c17ffa8dd167", symbol: "oUSDT", coinGeckoId: "orbit-bridge-klaytn-usd-tether", decimals: 6, price: 0.490247},  // Addr: 0xcee8faf64bb97a73bb51e115aa89c17ffa8dd167, Notional: 1.5499198124759999
		{chain: 16, addr: "000000000000000000000000efaeee334f0fd1712f9a8cc375f427d9cdd40d73", symbol: "USDT", coinGeckoId: "tether", decimals: 6, price: 0.999123},                           // Addr: 0xefaeee334f0fd1712f9a8cc375f427d9cdd40d73, Notional: 120.423742674981
		{chain: 16, addr: "000000000000000000000000ffffffffea09fb06d082fd1275cd48b191cbcd1d", symbol: "xcUSDT", coinGeckoId: "xcusdt", decimals: 6, price: 1.014},                            // Addr: 0xffffffffea09fb06d082fd1275cd48b191cbcd1d, Notional: 25.308089352
		{chain: 23, addr: "000000000000000000000000fd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9", symbol: "USDT", coinGeckoId: "tether", decimals: 6, price: 0.999123},                           // Addr: 0xfd086bc7cd5c481dcc9c85ebe478a1c0b69fcbb9, Notional: 751789.0060614113
		{chain: 24, addr: "00000000000000000000000094b008aa00579c1307b0ef2c499ad98a8ce58e58", symbol: "USDT", coinGeckoId: "tether", decimals: 6, price: 0.999123},                           // Addr: 0x94b008aa00579c1307b0ef2c499ad98a8ce58e58, Notional: 314425.3312945398

		// DAI variants (DAI+USDC is included under the USDC list above)
		{chain: 2, addr: "0000000000000000000000006b175474e89094c44da98b954eedeac495271d0f", symbol: "DAI", coinGeckoId: "dai", decimals: 18, price: 0.998076},          // Addr: 0x6b175474e89094c44da98b954eedeac495271d0f, Notional: 2433067.726108511
		{chain: 4, addr: "0000000000000000000000001af3f329e8be154074d8769d1ffa4ee058b1dbc3", symbol: "DAI", coinGeckoId: "dai", decimals: 18, price: 0.998076},          // Addr: 0x1af3f329e8be154074d8769d1ffa4ee058b1dbc3, Notional: 1005.9995281042593
		{chain: 5, addr: "0000000000000000000000008f3cf7ad23cd3cadbd9735aff958023239c6a063", symbol: "DAI", coinGeckoId: "dai", decimals: 18, price: 0.998076},          // Addr: 0x8f3cf7ad23cd3cadbd9735aff958023239c6a063, Notional: 2396.319029870252
		{chain: 6, addr: "000000000000000000000000d586e7f844cea2f87f50152665bcbc2c279d8d70", symbol: "DAI.e", coinGeckoId: "dai", decimals: 18, price: 0.998076},        // Addr: 0xd586e7f844cea2f87f50152665bcbc2c279d8d70, Notional: 871.4975717042859
		{chain: 10, addr: "0000000000000000000000008d11ec38a3eb5e956b052f67da8bdc9bef8abf3e", symbol: "DAI", coinGeckoId: "dai", decimals: 18, price: 0.998076},         // Addr: 0x8d11ec38a3eb5e956b052f67da8bdc9bef8abf3e, Notional: 16450.35695329643
		{chain: 13, addr: "0000000000000000000000005c74070fdea071359b86082bd9f9b3deaafbe32b", symbol: "KDAI", coinGeckoId: "klaytn-dai", decimals: 18, price: 0.490008}, // Addr: 0x5c74070fdea071359b86082bd9f9b3deaafbe32b, Notional: 0.00980016
		{chain: 16, addr: "000000000000000000000000765277eebeca2e31912c9946eae1021199b39c61", symbol: "DAI", coinGeckoId: "dai", decimals: 18, price: 0.998076},         // Addr: 0x765277eebeca2e31912c9946eae1021199b39c61, Notional: 23.953823999999997
		{chain: 23, addr: "000000000000000000000000da10009cbd5d07dd0cecc66161fc93d7c9000da1", symbol: "DAI", coinGeckoId: "dai", decimals: 18, price: 0.998076},         // Addr: 0xda10009cbd5d07dd0cecc66161fc93d7c9000da1, Notional: 1506.0572037763789
		{chain: 24, addr: "000000000000000000000000da10009cbd5d07dd0cecc66161fc93d7c9000da1", symbol: "DAI", coinGeckoId: "dai", decimals: 18, price: 0.998076},         // Addr: 0xda10009cbd5d07dd0cecc66161fc93d7c9000da1, Notional: 158.3252767530168
		{chain: 30, addr: "00000000000000000000000050c5725949a6f0c72e6c4a641f24049a917db0cb", symbol: "DAI", coinGeckoId: "dai", decimals: 18, price: 0.998076},         // Addr: 0x50c5725949a6f0c72e6c4a641f24049a917db0cb, Notional: 633.7033195932898
	}
}
