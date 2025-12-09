# CoinGecko API Client

This package provides a client for interacting with the CoinGecko API.

## Usage

### Basic Usage

```go
import "github.com/certusone/wormhole/node/pkg/governor/coingecko"

// Create a client (with API key and logger)
client := coingecko.NewClient("your-api-key", logger)

// Or without API key (free tier)
client := coingecko.NewClient("", nil)

// Fetch all asset platforms
platforms, err := client.AssetPlatforms()
if err != nil {
    log.Fatal(err)
}

// Fetch token prices
prices, err := client.SimpleTokenPrice("ethereum",
    []string{"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"}) // USDC
if err != nil {
    log.Fatal(err)
}

fmt.Printf("USDC price: $%.4f\n", prices[0].Prices["usd"])
```

### Chain to Platform Mapping

Map Wormhole ChainIDs to CoinGecko platform IDs:

```go
import (
    "github.com/certusone/wormhole/node/pkg/governor/coingecko"
    "github.com/wormhole-foundation/wormhole/sdk/vaa"
)

// Create client
client := coingecko.NewClient("", logger)

// Build the mapping (fetches from CoinGecko API)
count, err := client.BuildChainToPlatformMap()
if err != nil {
    log.Fatal(err)
}
fmt.Printf("Mapped %d chains to CoinGecko platforms\n", count)

// Get platform ID for a specific chain
platformID := client.GetPlatformForChain(vaa.ChainIDEthereum)
fmt.Printf("Ethereum platform: %s\n", platformID) // "ethereum"

platformID = client.GetPlatformForChain(vaa.ChainIDBSC)
fmt.Printf("BSC platform: %s\n", platformID) // "binance-smart-chain"

// Get the entire mapping
mapping := client.GetChainToPlatformMap()
for chainID, platformID := range mapping {
    fmt.Printf("Chain %s -> Platform %s\n", chainID, platformID)
}
```

## Features

- **Client-based API**: Create a reusable client with optional API key
- **Optional logging**: Pass a `*zap.Logger` for debug/error logging
- **Free & Pro tier support**: Automatically uses the correct endpoint based on API key presence
- **Type-safe**: Struct-based response parsing
- **Chain mapping**: Map Wormhole ChainIDs to CoinGecko platform IDs using `chain_identifier`

## Methods

### Price & Platform Queries

#### `AssetPlatforms() ([]AssetPlatform, error)`
Returns a list of all asset platforms supported by CoinGecko.

#### `SimpleTokenPrice(platformID string, contractAddresses []string) ([]TokenPrice, error)`
Queries the price of one or more tokens by contract address. Currency is hard-coded to USD.

### Chain to Platform Mapping

#### `BuildChainToPlatformMap() (int, error)`
Fetches all asset platforms and builds a mapping from `vaa.ChainID` to CoinGecko platform ID using the `chain_identifier` field. Returns the number of chains successfully mapped.

**Note:** This method caches the mapping in the client. Call this once during initialization.

#### `GetPlatformForChain(chainID vaa.ChainID) string`
Returns the CoinGecko platform ID for a given Wormhole ChainID. Returns empty string if not found.

**Prerequisite:** Must call `BuildChainToPlatformMap()` first.

#### `GetChainToPlatformMap() map[vaa.ChainID]string`
Returns a copy of the entire chain-to-platform mapping for inspection.

**Prerequisite:** Must call `BuildChainToPlatformMap()` first.

## How Chain Mapping Works

CoinGecko's `/asset_platforms` endpoint returns a `chain_identifier` field for each platform that corresponds to the EVM chain ID (e.g., 1 for Ethereum, 56 for BSC, 137 for Polygon).

The `BuildChainToPlatformMap()` method:
1. Fetches all platforms via `AssetPlatforms()`
2. Filters platforms that have a `chain_identifier`
3. Casts the `chain_identifier` to `vaa.ChainID`
4. Maps `vaa.ChainID` → CoinGecko platform ID (e.g., `1 → "ethereum"`)
5. Caches the mapping for fast lookups

**Example Mappings:**
- `vaa.ChainIDEthereum` (1) → `"ethereum"`
- `vaa.ChainIDBSC` (56) → `"binance-smart-chain"`
- `vaa.ChainIDPolygon` (137) → `"polygon-pos"`
- `vaa.ChainIDAvalanche` (43114) → `"avalanche"`

**Note:** Not all Wormhole chains have a CoinGecko platform (e.g., Solana, Aptos). Use `GetPlatformForChain()` and check for empty string.

## API Key

- **Free tier**: Pass empty string `""` to `NewClient()`
- **Pro tier**: Pass your API key to `NewClient()`

The client automatically uses the correct endpoint based on whether an API key is provided.
