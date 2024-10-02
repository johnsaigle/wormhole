package transferverifier

/*
	TODOs
	- Clean up structs
	- Object ownership checks
	- Make code more testable for amount comparisons
	- Fix CLI flags
*/

import (
	// "bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	// "github.com/ethereum/go-ethereum/log"

	ipfslog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/wormhole-foundation/wormhole/sdk/vaa"
)

type TransferDetailsSui struct {
	TokenAddress vaa.Address
	TokenChain   uint16
	Amount       *big.Int
	EventID      string
}
type SuiAmountChanged struct {
	Amount         *big.Int
	Decimals       uint8       // Decimals on Sui
	NativeDecimals uint8       // Decimals on origin chain
	TokenChain     uint16      // Origin chain
	TokenAddress   vaa.Address // Origin address
	CoinType       string
}

type SuiTokenChangeInformation struct {
	CoinType        string
	FullField       string
	Version         string
	PreviousVersion string
	ID              string
	IsWrapped       bool
}

type SuiTransactionBlockResponse struct {
	Jsonrpc string                          `json:"jsonrpc"`
	Result  SuiTransactionBlockResponseData `json:"result"`
	ID      int                             `json:"id"`
}

type SuiTransactionBlockResponseData struct {
	Digest        string             `json:"digest"`
	Transaction   string             `json:"transaction"`
	Events        []SuiResult        `json:"events"`
	ObjectChanges []SuiObjectChanges `json:"objectChanges"`
}

type SuiPastVersionResponse struct {
	Jsonrpc string                       `json:"jsonrpc"`
	Result  []SuiPastVersionResponseData `json:"result"`
	ID      int                          `json:"id"`
}

/*
This is terribly ugly but fine for a PoC.

From a design perspective, we're currently using this for TWO objects at once: native_asset and wrapped_asset

Personally, I don't like this and would like to have a seperate object for this in the future.
*/
type SuiPastVersionResponseData struct { // Could use the JsonRawMessage type for this
	Status  string `json:"status"`
	Details struct {
		Content struct {
			Fields struct {
				Value struct {
					Type   string `json:"type"`
					Fields struct {
						Decimals     uint8  `json:"decimals"`
						Custody      string `json:"custody"`
						TokenAddress struct {
							Fields struct {
								Value struct {
									Fields struct {
										Data []uint8 `json:"data"`
									} `json:"fields"`
								} `json:"value"`
							} `json:"fields"`
						} `json:"token_address"`
						Info struct {
							Fields struct {
								NativeDecimals uint8  `json:"native_decimals"`
								Symbol         string `json:"symbol"`
								TokenChain     uint16 `json:"token_chain"`
								TokenAddress   struct {
									Fields struct {
										Value struct {
											Fields struct {
												Data []uint8 `json:"data"`
											} `json:"fields"`
										} `json:"value"`
									} `json:"fields"`
								} `json:"token_address"`
							}
						}
						TreasuryCap struct {
							Fields struct {
								TotalSupply struct {
									Fields struct {
										Value string // Funds stored in here
									} `json:"fields"`
								} `json:"total_supply"`
							} `json:"fields"`
						} `json:"treasury_cap"`
					} `json:"fields"`
				} `json:"value"`
			} `json:"fields"`
		} `json:"content"`
	} `json:"details"`
}

type SuiEventResponse struct {
	Jsonrpc string               `json:"jsonrpc"`
	Result  SuiEventResponseData `json:"result"`
	ID      int                  `json:"id"`
}

type SuiEventResponseData struct {
	Data       []SuiResult `json:"data"`
	NextCursor struct {
		TxDigest string `json:"txDigest"`
		EventSeq string `json:"eventSeq"`
	} `json:"nextCursor"`
	HasNextPage bool   `json:"hasNextPage"`
	Status      string `json:"status"`
}

type SuiObjectChanges struct {
	ObjectId        string `json:"objectId"`
	ObjectType      string `json:"objectType"`
	Version         string `json:"version"`
	PreviousVersion string `json:"previousVersion"`
	Owner           struct {
		Owner string `json:"AddressOwner"`
	} `json:"owner"`
}

type SuiResult struct {
	ID struct {
		TxDigest *string `json:"txDigest"`
		EventSeq *string `json:"eventSeq"`
	} `json:"id"`
	PackageID         *string          `json:"packageId"`
	TransactionModule *string          `json:"transactionModule"`
	Sender            *string          `json:"sender"`
	Type              *string          `json:"type"`
	Bcs               *string          `json:"bcs"`
	Timestamp         *string          `json:"timestampMs"`
	Fields            *json.RawMessage `json:"parsedJson"`
}

//type SuiTransactionBlockResponse {}

var TransferVerifierCmdSui = &cobra.Command{
	Use:   "transfer-verifier-sui",
	Short: "transfer verifier-sui",
	Run:   runTransferVerifierSui,
}

type FieldsData struct {
	ConsistencyLevel *uint8  `json:"consistency_level"`
	Nonce            *uint64 `json:"nonce"`
	Payload          []byte  `json:"payload"`
	Sender           *string `json:"sender"`
	Sequence         *string `json:"sequence"`
	Timestamp        *string `json:"timestamp"`
}

// CLI args
var (
	// envStr *string
	suiLogLevel            string
	suiRPC                 string
	suiCoreContract        string
	suiTokenBridgeEmitter  string
	suiMoveEventType       string
	suiTokenBridgeContract string
)

/*
Wormhole Core Constants
- PackageID - 0x5306f64e312b581766351c07af79c72fcb1cd25147157fdc2f8ad76de9a3fb6a
- State Object - 0xaeab97f96cf9877fee2883315d459552b2b921edc16d7ceac6eab944dd88919c

Wormhole Token Bridge Constants
- PackageId - 0x26efee2b51c911237888e5dc6702868abca3c7ac12c53f76ef8eba0697695e3d
- State Object - 0xc57508ee0d4595e5a8728974a4a93a787d38f339757230d441e895422c07aba9
- Emitter ID - ccceeb29348f71bdd22ffef43a2a19c1f5b5e17c5cca5411529120182672ade5
	- https://github.com/wormhole-foundation/wormhole/blob/91ec4d1dc01f8b690f0492815407505fb4587520/sdk/mainnet_consts.go#L124

TokenRegistry Objects:
- USDC - https://suiscan.xyz/mainnet/object/0xf8f80c0d569fb076adb5fdc3a717dcb9ac14f7fd7512dc17efbf0f80a8b7fa8a
- wBTC
- Sui - https://suiscan.xyz/mainnet/object/0x831c45a8d512c9cf46e7a8a947f7cbbb5e0a59829aa72450ff26fb1873fd0e94

Function pattern for testability
- Function that gets RPC data for listening for events. Passes this information to function.
- Function that processs an individual event. Makes it possible to add in our own data for it.

Strategy:
- Get full transaction from hash.
- Find all events for postMessage. Parse out all of the tokens that must be processed for types and amounts.
- From the events, find all 'tokens' that should be processed. Need to do a look up here for origin to native.
- From the tokens, find all of the objects that were modified that are associated with the dynamic fields of the token registry.
- Get version of object AFTER
- Get version of object BEFORE
- Do decimal conversions
- Compare VAA to amount actually processed

Web requests this needs:
- Look up for TX hash (once)
- Version lookup for BEFORE and AFTER for two requests which can be done in one using MultiGetPastObjects:
	- Can do done in a single API call with 'https://docs.sui.io/sui-api-ref#sui_trymultigetpastobjects'.
	- Includes the following...
	- Native decimals
	- Local decimals
	- Custody amount/total supply
	- Native token address

curl --request POST \
     --url https://rpc.ankr.com/sui/22fe735acb187df41c2e84b758d081aa48b31e69cce2dee73951b5bbfb88b403 \
     --header 'accept: application/json' \
     --header 'content-type: application/json' \
     --data '{"jsonrpc":"2.0", "id": 1, "method": "sui_getTransactionBlock", "params": ["68VDcgx9YcpPkgaa3S16vdnWLhKUyFZTysQQ8RCprT1H", {"showEvents": true, "showBalanceChanges" : true}]}'

Object owned by registry:
- The 'custody' field is what we're after
- https://suiscan.xyz/mainnet/object/0x0063d37cdce648a7c6f72f69a75a114fbcc81ef23300e4ace60c7941521163db

Get previous transaction hash:
- sui client tx-block GQPK6LoVFuUPZC6Lbf2a8MT65q8R1QhCZ65dbJHDMWoa

https://stackoverflow.com/questions/77604935/request-historical-information-in-sui-api
Get the objects previous versions:
- sui client tx-block 7s12Zpx7J2SgKDtmNHJ5o7NzoAJ6J5WSvGdcjYeCfan2 --json | jq '.objectChanges.[] | select(.objectId == "0x027da174fa818508cbb0d421ac624f21fa419586920c4ddde5cfcf26b47201eb").previousVersion'

Get object at previous version
- sui_tryGetPastObject
- Warning about the data getting pruned... seems to happen in an example that I just got
- https://docs.shinami.com/reference/sui-api#sui_trygetpastobject

curl --location 'https://sui-rpc.publicnode.com' \
--header 'Content-Type: application/json' \
--data '{
  "jsonrpc": "2.0",
  "id": 1,   "method": "sui_tryGetPastObject",
  "params": [
    "0xf8f80c0d569fb076adb5fdc3a717dcb9ac14f7fd7512dc17efbf0f80a8b7fa8a",
    337699901,
    {
      "showPreviousTransaction": true,
      "showContent": true
    }
  ]
}' | jq


Get a particular token (currently doesn't work?)
curl --request POST \
     --url https://rpc.ankr.com/sui/22fe735acb187df41c2e84b758d081aa48b31e69cce2dee73951b5bbfb88b403 \
     --header 'accept: application/json' \
     --header 'content-type: application/json' \
     --data '{"jsonrpc":"2.0", "id": 1, "method": "suix_getDynamicFieldObject", "params": ["0x334881831bd89287554a6121087e498fa023ce52c037001b53a4563a00a281a5", {"type" : "0x26efee2b51c911237888e5dc6702868abca3c7ac12c53f76ef8eba0697695e3d::wrapped_asset::WrappedAsset<0x5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93bf::coin::COIN>", "value": {"dummy_field": false}} ]}'



Example
====================
- 155 dollar transfer out of WH of USDC
- https://wormholescan.io/#/tx/GQPK6LoVFuUPZC6Lbf2a8MT65q8R1QhCZ65dbJHDMWoa?network=Mainnet


Get the particular token that need. I guess there's an API for this on the token bridge - go from remote to local but I haven't tried finding this yet.

Get versioning data for TX lookups. Previous in 'previousVersion' and this made 'version'.
sui client tx-block GQPK6LoVFuUPZC6Lbf2a8MT65q8R1QhCZ65dbJHDMWoa --json | jq '.objectChanges.[] | select(.objectId == "0xf8f80c0d569fb076adb5fdc3a717dcb9ac14f7fd7512dc17efbf0f80a8b7fa8a")'

TotalSupply after:
curl --location 'https://sui-rpc.publicnode.com' \
--header 'Content-Type: application/json' \
--data '{
  "jsonrpc": "2.0",
  "id": 1,   "method": "sui_tryGetPastObject",
  "params": [
    "0xf8f80c0d569fb076adb5fdc3a717dcb9ac14f7fd7512dc17efbf0f80a8b7fa8a",
   337700277,
    {
      "showPreviousTransaction": true,
      "showContent": true
    }
  ]
}' | jq .result.details.content.fields.value.fields.treasury_cap.fields.total_supply.fields.value --raw-output
262304572736734

TotalSupply before:
url --location 'https://sui-rpc.publicnode.com' \
--header 'Content-Type: application/json' \
--data '{
  "jsonrpc": "2.0",
  "id": 1,   "method": "sui_tryGetPastObject",
  "params": [
    "0xf8f80c0d569fb076adb5fdc3a717dcb9ac14f7fd7512dc17efbf0f80a8b7fa8a",
    337699901,
    {
      "showPreviousTransaction": true,
      "showContent": true
    }
  ]
}' | jq .result.details.content.fields.value.fields.treasury_cap.fields.total_supply.fields.value --raw-output
262304728415336

262304728415336 - 262304572736734 = 155678602 (difference in value that we can allow)


Hash test cases:
- Missing version information:
	- 8DuaQgvkPJJyhDojYRb5wFcFUFk3DpM2V2KnYq6UcZeF
	- 73e9s6BxJnMCSHeA6nE367z2mUYP25cVicq7hNpKcgTV
-
*/

// CLI parameters
func init() {
	// envStr = TransferVerifierCmd.Flags().String("env", "", `environment (may be "testnet" or "mainnet")`)

	// TODO - fix the flag handling
	suiRPC = *TransferVerifierCmdSui.Flags().String("suiRPC", "<RPC HERE>", "Sui RPC url")
	logLevel = TransferVerifierCmdSui.Flags().String("logLevel", "info", "Logging level (debug, info, warn, error, dpanic, panic, fatal)")
	suiCoreContract = *TransferVerifierCmdSui.Flags().String("suiCoreContract", "0x5306f64e312b581766351c07af79c72fcb1cd25147157fdc2f8ad76de9a3fb6a", "Event to listen to in Sui")
	suiTokenBridgeEmitter = *TransferVerifierCmdSui.Flags().String("suiTokenBridgeEmitter", "0xccceeb29348f71bdd22ffef43a2a19c1f5b5e17c5cca5411529120182672ade5", "Token bridge emitter on Sui. Tied to the token bridge package.")
	suiTokenBridgeContract = *TransferVerifierCmdSui.Flags().String("suiTokenBridgeContract", "0x26efee2b51c911237888e5dc6702868abca3c7ac12c53f76ef8eba0697695e3d", "Token bridge emitter on Sui. Tied to the token bridge package.")

	suiMoveEventType = fmt.Sprintf("%s::publish_message::WormholeMessage", suiCoreContract)

}

// Note: logger.Error should be reserved only for conditions that break the invariants of the Token Bridge
func runTransferVerifierSui(cmd *cobra.Command, args []string) {

	// Setup logging
	lvl, err := ipfslog.LevelFromString("info") // TODO - use *logLevel* for this
	if err != nil {
		fmt.Println("Invalid log level")
		os.Exit(1)
	}

	logger := ipfslog.Logger("wormhole-transfer-verifier-sui").Desugar()

	ipfslog.SetAllLoggers(lvl)
	logger.Info("Starting transfer verifier")
	logger.Debug("rpc connection", zap.String("url", suiRPC))
	logger.Debug("Sui core contract", zap.String("address", suiCoreContract))
	logger.Debug("Sui Token bridge contract", zap.String("address", suiTokenBridgeContract))
	logger.Debug("Token Bridge Event Emitter", zap.String("object ID", suiTokenBridgeEmitter))

	// Single hardcoded hash test
	//processDigest(*logger)

	// Process ALL of the incoming ones
	//processAllEvents(*logger)
	processEventsLive(*logger)
}

// https://github.com/wormhole-foundation/wormhole/blob/e297d96d101857f98e0fbba10168b6dc7b55d9c0/node/pkg/watchers/sui/watcher.go#L449
func processEventsLive(logger zap.Logger) {
	cursor := "null"
	prevFirstDigest := ""

	for true {
		time.Sleep(10 * time.Second) // Sleep a little bit to let things get processed

		queryEventsCmd := fmt.Sprintf(`{"jsonrpc":"2.0", "id": 1, "method": "suix_queryEvents", "params": [{ "MoveEventType": "%s" }, %s, %d, %t]}`,
			suiMoveEventType, cursor, 10, true)

		res, err := suiQueryEvents(suiRPC, queryEventsCmd)

		if err != nil {
			logger.Error(fmt.Sprintf("suiQueryEvents failed: %s", err))
			return
		}
		//cursor = fmt.Sprintf(`{"txDigest":"%s", "eventSeq":"%s"}`, res.Result.NextCursor.TxDigest, res.Result.NextCursor.EventSeq)

		if len(res.Result.Data) == 0 { // Empty query
			continue
		}

		txDigestCurrent := res.Result.Data[0].ID.TxDigest
		if prevFirstDigest == *txDigestCurrent { // No new data
			logger.Info(fmt.Sprintf("No new events for hash %s", *txDigestCurrent))
			continue
		}

		entries := res.Result.Data

		for _, entry := range entries {

			if prevFirstDigest == *entry.ID.TxDigest { // Already seen the TX. Don't need to process again. Should be sequential so we can leave this loop.
				break
			}
			fmt.Println("============================================")
			logger.Info("", zap.String("Hash", *entry.ID.TxDigest))
			err = processIncomingEvent(*entry.ID.TxDigest, logger)
			if err != nil {
				logger.Error(fmt.Sprintf("Unable to process event: %s", err.Error()))
			}
		}

		prevFirstDigest = *txDigestCurrent
	}
}

func processDigest(logger zap.Logger) {
	txList := []string{
		"8iLiTjfMdXkxJ4E5GBnFjmoZdCyhJVt8Am6FwWh2GL4D", // Non-native 6 decimal token (kept at 6 on Sui)
		"BajHPKD7Bpo8AJVb88D3Pe8D4W4xcv5uv92ueFKXo2Dk", // Non-native 18 decimals (scaled to 8 on Sui)
		"FQeckzjDjBEpiTZ4btC8My5ygDsaNSf5nNixpHTo5msh", // Native Sui transfer
		"G1dB96HxwddzNsgNJrcfLznRwGaBSsDh6W1dh1d7pa9T", // Native SCA transfer
	}

	for _, txDigest := range txList {
		err := processIncomingEvent(txDigest, logger)
		if err != nil {
			logger.Error(fmt.Sprintf("Unable to process event: %s", err.Error()))
		}
	}
}

func processAllEvents(logger zap.Logger) {
	// The event type data
	cursor := "null"

	for true {
		fmt.Println("Beginning of loop")
		queryEventsCmd := fmt.Sprintf(`{"jsonrpc":"2.0", "id": 1, "method": "suix_queryEvents", "params": [{ "MoveEventType": "%s" }, %s, %d, %t]}`,
			suiMoveEventType, cursor, 10000, true)

		res, err := suiQueryEvents(suiRPC, queryEventsCmd)
		if err != nil {
			logger.Fatal("Sui query failed")
		}

		cursor = fmt.Sprintf(`{"txDigest":"%s", "eventSeq":"%s"}`, res.Result.NextCursor.TxDigest, res.Result.NextCursor.EventSeq)

		// Stick query results into a list for each of them
		var results []SuiResult
		var txs []string
		for _, datum := range res.Result.Data {
			txs = append(txs, *datum.ID.TxDigest)
			results = append(results, datum)
		}

		for _, result := range results {
			body := result
			fmt.Println("======================================")
			logger.Info("", zap.String("Hash", *body.ID.TxDigest))

			txDigest := body.ID.TxDigest

			err = processIncomingEvent(*txDigest, logger)
			time.Sleep(3 * time.Second)
			if err != nil {
				logger.Error(fmt.Sprintf("Unable to process event: %s", err.Error()))
			}
		}
	}
}

func processIncomingEvent(txDigest string, logger zap.Logger) error {

	/*
		Get full transaction data from RPC. This is the important stuff that we want to handle!
	*/
	queryPTB := fmt.Sprintf(`{"jsonrpc":"2.0", "id": 1, "method": "sui_getTransactionBlock", "params": ["%s", {"showEvents": true, "showObjectChanges" : true}]}`, txDigest)

	ptbResults, err := suiTransactionBlock(suiRPC, queryPTB)
	if err != nil {
		return fmt.Errorf("cannot find PTB: %w", err)
	}

	// Get the event information. Convert from WH type to token transfer type
	events := ptbResults.Result.Events
	wormholeEventData, err := parseEventsForWormhole(events, suiMoveEventType, logger)
	if err != nil {
		return fmt.Errorf("cannot parse wormhole events: %w", err)
	}

	// No events matching our criteria
	if len(wormholeEventData) == 0 {
		logger.Debug("No wormhole token bridge events found")
		return nil
	}

	// Get the token data required to perform this
	changeList, err := parseTxForCoinTypes(ptbResults.Result.ObjectChanges, logger)
	if err != nil {
		return fmt.Errorf("cannot parse coin types: %w", err)
	}

	// TODO - refactor this call to make it more testable.
	// Ideas are passing in a function pointer for the query call and using a separate function to query the data then pass this in are part of the inputs for this
	amountChanged := fillAmountProcesssed(changeList, suiRPC, &logger)

	// Compare amounts being processed
	err = compareTransfers(amountChanged, wormholeEventData, logger)
	if err != nil {
		return fmt.Errorf("transfer verification failed: %w", err)
	}

	// TODO - handle edge case of mismatch by looking up VAA information of TXs gone IN for the same TX

	return nil
}

/*
Compare the tracked changes from viewing objects and Wormhole events to see if they match up.

TODO - how to handle differences here? Should we just return an error and stop the processing of the TX?
Right now, if there's a difference, it is returning an error.
*/
func compareTransfers(amountChangedTracked map[string]SuiAmountChanged, wormholeTransferEvents []TransferDetailsSui, logger zap.Logger) error {

	txProcessedCounter := 0
	for _, transfer := range wormholeTransferEvents {

		// Get coin object that was changed
		coinKey := fmt.Sprintf("%d-%s", transfer.TokenChain, transfer.TokenAddress.String())
		coinData, found := amountChangedTracked[coinKey]
		if !found {
			logger.Error("Event emission but no token transfer", zap.String("CoinKey", coinKey), zap.String("VAA ID", transfer.EventID))
			continue
		}

		// Checks should be redundant not it's a cheap check so we do it again
		if coinData.TokenAddress != transfer.TokenAddress {
			logger.Error("Origin Token Addresses don't match", zap.String("CoinData token address", coinData.TokenAddress.String()), zap.String("VAA token address", transfer.TokenAddress.String()), zap.String("CoinKey", coinKey), zap.String("VAA ID", transfer.EventID))
			continue
		}
		if coinData.TokenChain != transfer.TokenChain {
			logger.Error("Origin Token Chain IDs don't match", zap.Uint16("CoinData Chain ID", coinData.TokenChain), zap.Uint16("VAA Chain ID", transfer.TokenChain), zap.String("CoinKey", coinKey), zap.String("VAA ID", transfer.EventID))
			continue
		}

		/*
			The AMOUNT for a wrapped token implementation being deployed to Sui will be 8 or less.
			The amount is only decimal scaled if it's greater than 8 decimals.
			Practically, this means that scaling is not required for deployed wrapped tokens.

			For the native assets, token denormalization is required though.
		*/
		denormalizedTransferAmount := denormalize(transfer.Amount, coinData.Decimals)

		//if coinData.Amount != denormalizedTransferAmount.Uint64() { // Exact amount checks for sanity testing but should NOT be used for the real thing.
		if coinData.Amount.Cmp(denormalizedTransferAmount) == -1 { // TODO - use this one instead
			logger.Error("Token amount Withdrawal amount too much", zap.Uint64("CoinData Amount", coinData.Amount.Uint64()), zap.Uint64("Event Token Amount", denormalizedTransferAmount.Uint64()), zap.String("VAA ID", transfer.EventID))

			// TODO - need to return information or alert watchdog. Depends on what we want to do.
			continue
		}

		logger.Info("Transfer Passed verification", zap.String("VAA ID", transfer.EventID))
		txProcessedCounter += 1

		// Subtract from the amount to prevent duplicate usage of the same CoinData on multiple Wormhole events
		coinData.Amount = coinData.Amount.Sub(coinData.Amount, denormalizedTransferAmount)
		amountChangedTracked[coinKey] = coinData
	}

	// Everything at this point should have an equal amount of changes in the Coin verification and Wormhole Events
	// It should be noted that leftovers in 'SuiAmountChanged' is okay. This may happen if from normal usage of the tokens in other ways.
	if txProcessedCounter == 0 || len(wormholeTransferEvents) != txProcessedCounter {
		return fmt.Errorf("mismatch in events counts. found %d but expected %d", txProcessedCounter, len(wormholeTransferEvents))
	}
	return nil
}

/*
Get newest version
Get old version

Compare the supply
Return values

TODO - make this more testable for processing inputs. Right now, it has two RPC tests which
makes it impossible to use in a unit test framework. Could replace the 'function' that is
doing the querying with a function that returns static data?
*/
func fillAmountProcesssed(tokenChangeList []SuiTokenChangeInformation, rpc string, logger *zap.Logger) map[string]SuiAmountChanged {

	// Key is a string of '<OriginChaindId>-<OriginTokenAddress>
	amountChanged := make(map[string]SuiAmountChanged)

	for _, entry := range tokenChangeList {

		// TODO - add ownership checks for object. Fail if we can't find either of the objects
		// Owner is the 'parent' object - https://suiscan.xyz/mainnet/object/0xf8f80c0d569fb076adb5fdc3a717dcb9ac14f7fd7512dc17efbf0f80a8b7fa8a
		// The parent object no longer exists according to this though. I'm confused on A) what happened and B) how to do an ownership check then
		objectVersionInfo, err := suiQueryObjectByVersion(rpc, entry.ID, entry.Version, entry.PreviousVersion)

		if err != nil {
			logger.Error("suiQueryObjectByVersion failed on new version lookup", zap.String("Object ID", entry.ID), zap.String("Version", entry.Version))
			continue
		}

		objectVersionNew := objectVersionInfo.Result[0]
		objectVersionOld := objectVersionInfo.Result[1]

		// TODO - handle case where the previousVersion and current version are the same. Could happen if the attestation and transfer happen in the same PTB. Is this case even worth considering?
		// Is this was the ONLY version of an object then what would the API return?
		// Object changes also have a 'Status' in them. Could use the 'Status' to see if the object was created in that case too

		// These two fields are the same in both objects
		localDecimals := objectVersionNew.Details.Content.Fields.Value.Fields.Decimals

		//objectVersionOld, err := suiQueryObjectByVersion(rpc, entry.ID, entry.PreviousVersion)
		if err != nil {
			logger.Error("suiQueryObjectByVersion failed on old version lookup", zap.String("Object ID", entry.ID), zap.String("Version", entry.PreviousVersion))
			continue
		}

		// Parse out the necessary information depending on whether it's native or wrapped
		amountAfter := new(big.Int)
		amountBefore := new(big.Int)
		amountDiff := new(big.Int)
		var tokenChain uint16
		var tokenAddress vaa.Address
		var nativeDecimals uint8
		if !entry.IsWrapped {
			amountAfter, errAmountAfterUsage := amountAfter.SetString(objectVersionNew.Details.Content.Fields.Value.Fields.Custody, 10)
			amountBefore, errAmountBeforeUsage := amountBefore.SetString(objectVersionOld.Details.Content.Fields.Value.Fields.Custody, 10)
			if !errAmountAfterUsage || !errAmountBeforeUsage {
				logger.Warn("Unable to decode amount into BigInt", zap.String("TxDigest", entry.ID), zap.String("Version", entry.Version), zap.String("PreviousVersion", entry.PreviousVersion))
				continue
			}

			tokenChain = 21 // Wormhole chain id
			tokenAddressBytes := vaa.Address(objectVersionNew.Details.Content.Fields.Value.Fields.TokenAddress.Fields.Value.Fields.Data)
			tokenAddress, _ = vaa.BytesToAddress(tokenAddressBytes[:])

			if amountAfter.Cmp(amountBefore) == -1 { // Tokens sent OUT not in for this case
				continue
			}

			amountDiff = amountAfter.Sub(amountAfter, amountBefore)
			nativeDecimals = localDecimals
		} else if entry.IsWrapped {
			amountAfter, errAmountAfterUsage := amountAfter.SetString(objectVersionNew.Details.Content.Fields.Value.Fields.TreasuryCap.Fields.TotalSupply.Fields.Value, 10)
			amountBefore, errAmountBeforeUsage := amountBefore.SetString(objectVersionOld.Details.Content.Fields.Value.Fields.TreasuryCap.Fields.TotalSupply.Fields.Value, 10)
			if !errAmountAfterUsage || !errAmountBeforeUsage {
				logger.Warn("Unable to decode amount into BigInt", zap.String("TxDigest", entry.ID), zap.String("Version", entry.Version), zap.String("PreviousVersion", entry.PreviousVersion))
				continue
			}

			tokenChain = objectVersionNew.Details.Content.Fields.Value.Fields.Info.Fields.TokenChain
			tokenAddressBytes := objectVersionNew.Details.Content.Fields.Value.Fields.Info.Fields.TokenAddress.Fields.Value.Fields.Data
			tokenAddress, _ = vaa.BytesToAddress(tokenAddressBytes[:])

			if amountBefore.Cmp(amountAfter) == -1 { // Tokens sent OUT not in for this case
				continue
			}

			amountDiff = amountBefore.Sub(amountBefore, amountAfter)

			nativeDecimals = objectVersionNew.Details.Content.Fields.Value.Fields.Info.Fields.NativeDecimals
		} else {
			logger.Error("Processing an invalid asset type - neither Wrapped nor Native", zap.String("Type", entry.FullField))
		}

		// Store the difference
		suiAmountChangedObj := SuiAmountChanged{
			Amount:         amountDiff, // Token difference between the object versions
			Decimals:       localDecimals,
			NativeDecimals: nativeDecimals,
			TokenChain:     tokenChain,
			TokenAddress:   tokenAddress,
			CoinType:       entry.CoinType,
		}

		coinKey := fmt.Sprintf("%d-%s", tokenChain, tokenAddress.String())
		amountChanged[coinKey] = suiAmountChangedObj

		logger.Info("Token Change Found", zap.Uint64("Amount Difference", amountDiff.Uint64()))
	}

	return amountChanged
}

func parseTxForCoinTypes(changes []SuiObjectChanges, logger zap.Logger) ([]SuiTokenChangeInformation, error) {
	var tokenChangeList []SuiTokenChangeInformation

	for _, change := range changes {
		// TODO - how do we do an object ownership check here? I'm confused on WHO actually owns the registry.
		// SuiScan says that the token registry is owned by '0x334881831bd89287554a6121087e498fa023ce52c037001b53a4563a00a281a5'.
		// This is confusing since this object no longer exists.

		// Expecting a Sui move type similar to this: 0x2::dynamic_field::Field<0x26efee2b51c911237888e5dc6702868abca3c7ac12c53f76ef8eba0697695e3d::token_registry::Key<0x5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93bf::coin::COIN>, 0x26efee2b51c911237888e5dc6702868abca3c7ac12c53f76ef8eba0697695e3d::wrapped_asset::WrappedAsset<0x5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93bf::coin::COIN>>
		// First part is the fact that it's owned by the dynamic field type, which is a native Sui module
		// The second part is a 'key' and 'value' portion for generic types. Type definition is here - https://move-book.com/programmability/dynamic-fields.html#definition

		if !strings.HasPrefix(change.ObjectType, "0x2::dynamic_field::Field") { // Not a dynamic field.
			logger.Debug(fmt.Sprintf("Object type not dynamic field: %s", change.ObjectType))
			continue
		}

		// 0x26efee2b51c911237888e5dc6702868abca3c7ac12c53f76ef8eba0697695e3d::token_registry::Key<0x5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93bf::coin::COIN>
		dynamicFieldKeyParseEnding := strings.Split(change.ObjectType, "0x2::dynamic_field::Field<")[1]
		dynamicFieldKey := strings.Split(dynamicFieldKeyParseEnding, ">")[0]

		// Check type ownership belongs to Wormhole Token Bridge
		keyPackageId := strings.Split(dynamicFieldKey, "::")[0]
		keyModule := strings.Split(dynamicFieldKey, "::")[1]
		if keyPackageId != suiTokenBridgeContract { // Dynamic type from wrong package id
			logger.Debug(fmt.Sprintf("Wrong package key: %s", keyPackageId))
			continue
		}

		if keyModule != "token_registry" { // Dynamic type wrong module
			logger.Debug(fmt.Sprintf("Wrong module key: %s", keyModule))
			continue
		}

		/*
			Wrapped tokens come in the format 'ADDRESS::coin::COIN'.
			Native tokens come in the format 'ADDRESS::module_name::type_name'. Because of the
			large difference in representation between these and the amount of values these
			could possibly be, verification cannot be done until later on this field.
		*/
		keyCoinType := strings.Split(strings.Split(dynamicFieldKey, "::Key<")[1], ">")[0]

		// Parse the value type from the dynamic field
		dynamicFieldValueParseEnding := strings.Split(change.ObjectType, ", ")[1] // Need extra slice to account for the space between generic types, which is why the space is here
		dynamicFieldValue := strings.Split(dynamicFieldValueParseEnding, ">")[0]

		// 0x26efee2b51c911237888e5dc6702868abca3c7ac12c53f76ef8eba0697695e3d::wrapped_asset::WrappedAsset<0x5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93bf::coin::COIN>
		valuePackageId := strings.Split(dynamicFieldValue, "::")[0]
		valueModule := strings.Split(dynamicFieldValue, "::")[1]
		valueType := strings.Split(dynamicFieldValue, "::")[2]
		if valuePackageId != suiTokenBridgeContract { // Dynamic type from wrong package id
			logger.Debug(fmt.Sprintf("Wrong package value: %s, %s", valuePackageId, dynamicFieldValue))
			continue
		}

		if valueModule != "wrapped_asset" && valueModule != "native_asset" { // Wrong module
			logger.Debug(fmt.Sprintf("Wrong module value: %s", valueModule))
			continue
		}

		var newTokenData SuiTokenChangeInformation

		// Native case
		if strings.HasPrefix(valueType, "NativeAsset") {
			newTokenData = SuiTokenChangeInformation{
				Version:         change.Version,
				PreviousVersion: change.PreviousVersion,
				FullField:       change.ObjectType,
				ID:              change.ObjectId,
				CoinType:        keyCoinType,
				IsWrapped:       false,
			}
		} else if strings.HasPrefix(valueType, "WrappedAsset") {
			newTokenData = SuiTokenChangeInformation{
				Version:         change.Version,
				PreviousVersion: change.PreviousVersion,
				FullField:       change.ObjectType,
				ID:              change.ObjectId,
				CoinType:        keyCoinType,
				IsWrapped:       true,
			}
		} else {
			logger.Error("Invalid Asset. Neither native nor wrapped", zap.String("Type", change.ObjectType))
			continue
		}

		logger.Info("CoinType Object Found", zap.String("ObjectID", newTokenData.ID), zap.String("Token", newTokenData.CoinType))
		tokenChangeList = append(tokenChangeList, newTokenData)
	}

	return tokenChangeList, nil
}

func parseEventsForWormhole(events []SuiResult, listenedType string, logger zap.Logger) ([]TransferDetailsSui, error) {
	var fieldDataList []TransferDetailsSui

	// https://github.com/wormhole-foundation/wormhole/blob/91ec4d1dc01f8b690f0492815407505fb4587520/node/pkg/watchers/sui/watcher.go#L197
	// TODO - add 'outgoing' transfer checks to this as well for the weird flow issue.

	for _, event := range events {
		if event.ID.TxDigest == nil {
			logger.Debug("event.ID.TxDigest is nil")
			continue
		}

		/*
			Events in Move have the format 'PACKAGE_ID::MODULE_ID::EventName'
			Hence, if we check the EventType we are checking the type of event
			AND the contract emitting the event. This is why just using the 'type' here
			and not looking at the contract address specifically is good for verification.

			The PackageId and TransactionModule fields are for the CALLING MODULE and are
			not the ORIGINATORS of the call. So, these two values can be set by anybody, meaing that we should not worry about it.

			An example is here: https://suiscan.xyz/mainnet/tx/HAX8wPV4MMrHHdFUuKrAVFuAiwv56WTyScSjojbxLsvb
			- TransactionModule: lending_core_wormhole_adapter
			- PackageID: 0x826915f8ca6d11597dfe6599b8aa02a4c08bd8d39674855254a06ee83fe7220e
			- Type: 0x5306f64e312b581766351c07af79c72fcb1cd25147157fdc2f8ad76de9a3fb6a::publish_message::WormholeMessage (PackageId here is the core bridge)
		*/
		if event.Type == nil {
			logger.Debug("event.Type is nil")
			continue
		}

		// There may be moveEvents caught without these params.
		if event.Fields == nil {
			logger.Debug("event.Fields is nil")
			continue
		}

		if listenedType != *event.Type {
			logger.Debug("Listened type is not the same as the event type", zap.String("ListenedType", listenedType), zap.String("EventType", *event.Type))
			continue
		}

		// Convert the fields into an object we can handle.
		var fields FieldsData
		err := json.Unmarshal(*event.Fields, &fields)
		if err != nil { // Unable to parse JSON
			logger.Debug("Unable to parse JSON fields", zap.String("JSON", string(*event.Fields)))
			continue
		}
		data := fields.Payload

		// Do we need a sanity check on the fields before using them? Otherwise, an array OOB or a nil pointer dereference could happen.
		/*
			In Wormhole Sui, the 'emitter' on Wormhle Core is not the sender itself.
			A user creates an emitter object. This object ID is the 'sender' or 'emitter'
			object in Sui.

			There is an emitter object owned by the token bridge. This object ID is
			what is being checked below.

			There are also TWO senders within this context. On the EVENT object above
			there is a sender that corresponds to the address that initiated the PTB.
			The sender we want here is from the event output.
		*/
		if *fields.Sender != suiTokenBridgeEmitter {
			logger.Debug("Sender is not token bridge emitter", zap.String("Sender", *fields.Sender), zap.String("Expected Sender", suiTokenBridgeEmitter))
			continue
		}

		// Parse transfer information
		t := TransferDetailsSui{}

		if data[0] != 1 && data[0] != 3 {
			logger.Debug("Invalid token payload type for processing. Expected 1 or 3.", zap.ByteString("Byte", data[0:1]))
			continue
		}

		// Handle the amount parsing
		amount := big.NewInt(0).SetBytes(data[1 : 1+32])
		t.Amount = amount

		// Handle the token address parsing from the event
		rawTokenAddress := data[33 : 33+32]
		t.TokenAddress, _ = vaa.BytesToAddress(rawTokenAddress)

		// Handle the chain parsing
		tokenChain := binary.BigEndian.Uint16(data[65 : 65+2])
		t.TokenChain = tokenChain

		// Add the ID for logging. Slice on the sender is necessary to get rid of the '0x' on the address for the VAA ID
		t.EventID = fmt.Sprintf("%d/%s/%s", 21, (*fields.Sender)[2:], *fields.Sequence)
		logger.Info("Found WH Token Bridge Event", zap.String("ID", t.EventID), zap.Uint16("Token Origin Chain ID", tokenChain), zap.String("Token Origin Address", t.TokenAddress.String()), zap.String("Token Amount", t.Amount.String()))
		fieldDataList = append(fieldDataList, t)
	}

	return fieldDataList, nil
}

func suiQueryObjectByVersion(suiRpc string, objectId string, newObjectVersion string, previousObjectVersion string) (SuiPastVersionResponse, error) {

	//payload := fmt.Sprintf(`{"jsonrpc":"2.0", "id": 1, "method": "sui_tryGetPastObject", "params": ["%s", %s, {"showContent": true}]}`, objectId, objectVersion)

	payload := fmt.Sprintf(`{"jsonrpc":"2.0", "id": 1, "method": "sui_tryMultiGetPastObjects", "params": [
		[
			{"objectId" : "%s", "version" : "%s"}, {"objectId" : "%s", "version" : "%s"}
		], 
		{"showContent": true}
		]}`, objectId, newObjectVersion, objectId, previousObjectVersion)

	retVal := SuiPastVersionResponse{}

	body, err := createAndExecReq(suiRpc, payload)
	if err != nil {
		return retVal, fmt.Errorf("suix_queryEvents failed to create and execute request: %w", err)
	}

	err = json.Unmarshal(body, &retVal)
	if err != nil {
		return retVal, fmt.Errorf("suix_queryEvents failed to unmarshal body: %s, error: %w", string(body), err)
	}

	if len(retVal.Result) != 2 {
		return retVal, fmt.Errorf("result count not 2")
	}

	if retVal.Result[0].Status != "VersionFound" || retVal.Result[1].Status != "VersionFound" {
		return retVal, fmt.Errorf("cannot find version")
	}

	return retVal, nil
}

func suiQueryEvents(suiRpc string, payload string) (SuiEventResponse, error) {
	retVal := SuiEventResponse{}

	body, err := createAndExecReq(suiRpc, payload)
	if err != nil {
		return retVal, fmt.Errorf("suix_queryEvents failed to create and execute request: %w", err)
	}

	err = json.Unmarshal(body, &retVal)
	if err != nil {
		return retVal, fmt.Errorf("suix_queryEvents failed to unmarshal body: %s, error: %w", string(body), err)
	}
	return retVal, nil
}

func suiTransactionBlock(suiRpc string, payload string) (SuiTransactionBlockResponse, error) {
	retVal := SuiTransactionBlockResponse{}

	body, err := createAndExecReq(suiRpc, payload)
	if err != nil {
		return retVal, fmt.Errorf("suix_queryEvents failed to create and execute request: %w", err)
	}

	err = json.Unmarshal(body, &retVal)
	if err != nil {
		return retVal, fmt.Errorf("suix_queryEvents failed to unmarshal body: %s, error: %w", string(body), err)
	}

	if retVal.Result.Digest == "" { // TODO - is there a better way to tell if this is working or not?
		return retVal, fmt.Errorf("tx hash not found")
	}

	return retVal, nil
}

func createAndExecReq(suiRPC, payload string) ([]byte, error) {
	var retVal []byte
	ctx, cancel := context.WithTimeout(context.Background(), 200000000000)
	defer cancel()
	// Create a new request with the context
	req, err := http.NewRequestWithContext(ctx, "POST", suiRPC, strings.NewReader(payload))
	if err != nil {
		return retVal, fmt.Errorf("createAndExecReq failed to create request: %w, payload: %s", err, payload)
	}

	// Set the Content-Type header
	req.Header.Set("Content-Type", "application/json")

	// Send the request using DefaultClient
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return retVal, fmt.Errorf("createAndExecReq failed to post: %w", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return retVal, fmt.Errorf("createAndExecReq failed to read: %w", err)
	}
	resp.Body.Close()
	return body, nil
}
