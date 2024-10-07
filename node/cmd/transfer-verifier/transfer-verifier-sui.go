package transferverifier

// TODOs:
//	* balances on Sui are stored as u64's. Consider using uint64 instead of big.Int
//  * create a utils.go to share functionality between transfer verifiers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	ipfslog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"
	"github.com/wormhole-foundation/wormhole/sdk/vaa"
	"go.uber.org/zap"
)

// Global constants
const (
	MAX_DECIMALS = 8
)

// Global variables
var (
	suiModule    = "publish_message"
	suiEventName = "WormholeMessage"
	suiEventType = ""
)

// CLI args
var (
	suiRPC                *string
	suiCoreContract       *string
	suiTokenBridgeEmitter *string
	// TODO: rename to package ID
	suiTokenBridgeContract  *string
	suiProcessInitialEvents *bool
)

var TransferVerifierCmdSui = &cobra.Command{
	Use:   "sui",
	Short: "Transfer Verifier for Sui",
	Run:   runTransferVerifierSui,
}

// CLI parameters
func init() {
	suiRPC = TransferVerifierCmdSui.Flags().String("suiRPC", "", "Sui RPC url")
	suiCoreContract = TransferVerifierCmdSui.Flags().String("suiCoreContract", "", "Event to listen to in Sui")
	suiTokenBridgeEmitter = TransferVerifierCmdSui.Flags().String("suiTokenBridgeEmitter", "", "Token bridge emitter on Sui")
	suiTokenBridgeContract = TransferVerifierCmdSui.Flags().String("suiTokenBridgeContract", "", "Token bridge contract on Sui")
	suiProcessInitialEvents = TransferVerifierCmdSui.Flags().Bool("suiProcessInitialEvents", false, "Indicate whether the Sui transfer verifier should process the initial events it fetches")
}

// Note: logger.Error should be reserved only for conditions that break the invariants of the Token Bridge
func runTransferVerifierSui(cmd *cobra.Command, args []string) {
	ctx := context.Background()

	// Setup logging
	lvl, err := ipfslog.LevelFromString(*logLevel)
	if err != nil {
		fmt.Println("Invalid log level")
		os.Exit(1)
	}

	logger := ipfslog.Logger("wormhole-transfer-verifier-sui").Desugar()

	ipfslog.SetAllLoggers(lvl)
	logger.Info("Starting Sui transfer verifier")
	logger.Debug("Sui rpc connection", zap.String("url", *suiRPC))
	logger.Debug("Sui core contract", zap.String("address", *suiCoreContract))
	logger.Debug("Sui token bridge contract", zap.String("address", *suiTokenBridgeContract))
	logger.Debug("token bridge event emitter", zap.String("object id", *suiTokenBridgeEmitter))

	// Verify CLI parameters
	if *suiRPC == "" || *suiCoreContract == "" || *suiTokenBridgeEmitter == "" || *suiTokenBridgeContract == "" {
		logger.Fatal("One or more CLI parameters are empty",
			zap.String("suiRPC", *suiRPC),
			zap.String("suiCoreContract", *suiCoreContract),
			zap.String("suiTokenBridgeEmitter", *suiTokenBridgeEmitter),
			zap.String("suiTokenBridgeContract", *suiTokenBridgeContract))
	}

	suiEventType = fmt.Sprintf("%s::%s::%s", *suiCoreContract, suiModule, suiEventName)

	// Filter to be used for querying events
	// The `MoveEventType` filter doesn't seem to be available in the documentation. However, there is an example
	// showing the inclusion of `type` in the `MoveModule` filter.
	// Reference: https://docs.sui.io/guides/developer/sui-101/using-events#query-events-with-rpc
	eventFilter := fmt.Sprintf(`
		{
			"MoveModule":{
				"package":"%s",
				"module":"%s",
				"type":"%s"
			}
		}`, *suiCoreContract, suiModule, suiEventType)

	// Initial event fetching
	initialEvents, err := suixQueryEvents(*suiRPC, eventFilter, "null", 25, true)
	if err != nil {
		logger.Fatal("Error in querying initial events", zap.Error(err))
	}

	// Use the latest timestamp to determine the starting point for live processing
	var latestTimestamp int
	for _, event := range initialEvents {
		if event.Timestamp != nil {
			timestampInt, err := strconv.Atoi(*event.Timestamp)
			if err != nil {
				logger.Error("Error converting timestamp to int", zap.Error(err))
				continue
			}
			if timestampInt > latestTimestamp {
				latestTimestamp = timestampInt
			}
		}
	}
	logger.Info("Initial events fetched", zap.Int("number of initial events", len(initialEvents)), zap.Int("latestTimestamp", latestTimestamp))

	if *suiProcessInitialEvents {
		logger.Info("Processing initial events")
		for _, event := range initialEvents {
			if event.ID.TxDigest != nil {
				processDigest(ctx, logger, *event.ID.TxDigest)
			}
		}
	}
	// decrement latestTimestamp to trigger processing the most recent event
	// var latestTimestamp

	// Ticker for live processing
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Context cancelled")
		case <-ticker.C:
			// Fetch new events
			newEvents, err := suixQueryEvents(*suiRPC, eventFilter, "null", 25, true)
			if err != nil {
				logger.Error("Error in querying new events", zap.Error(err))
				continue
			}

			// List of transaction digests for transactions in which the WormholeMessage
			// event was emitted.
			var txDigests []string

			// Iterate over all events and get the transaction digests for events younger
			// than latestTimestamp. Also update latestTimestamp.
			for _, event := range newEvents {
				if event.Timestamp != nil {
					timestampInt, err := strconv.Atoi(*event.Timestamp)
					if err != nil {
						logger.Error("Error converting timestamp to int", zap.Error(err))
						continue
					}
					if timestampInt > latestTimestamp {
						latestTimestamp = timestampInt
						if event.ID.TxDigest != nil {
							txDigests = append(txDigests, *event.ID.TxDigest)
						}
					}
				}
			}

			for _, txDigest := range txDigests {
				processDigest(ctx, logger, txDigest)
			}

			logger.Info("New events processed", zap.Int("latestTimestamp", latestTimestamp), zap.Int("txDigestCount", len(txDigests)))

		}
	}
}

func processDigest(ctx context.Context, logger *zap.Logger, digest string) (int, error) {
	// Get the transaction block
	txBlock, err := suiGetTransactionBlock(*suiRPC, digest)

	if err != nil {
		logger.Fatal("Error in getting transaction block", zap.Error(err))
	}

	var numProcessed int
	transferredIntoBridge := make(map[string]*big.Int)
	requestedOutOfBridge := make(map[string]*big.Int)
	keyFormat := "%s-%d"

	// Filter events that have the sui token bridge emitter as the sender in the message. The events indicate
	// how much is going to leave the network.
	for _, event := range txBlock.Events {

		// If any of these event parameters are nil, skip the event
		if event.Message == nil || event.Message.Sender == nil || event.Type == nil {
			continue
		}

		// Only process the event if it is a WormholeMessage event from the token bridge emitter
		if *event.Type == suiEventType && *event.Message.Sender == *suiTokenBridgeEmitter {
			logger.Info("Processing event from token bridge emitter", zap.String("txDigest", digest), zap.String("eventSeq", *event.ID.EventSeq))

			// Parse the wormhole message. vaa.IsTransfer can be omitted, since this is done
			// inside `DecodeTransferPayloadHdr` already.
			hdr, err := vaa.DecodeTransferPayloadHdr(event.Message.Payload)

			if err != nil {
				logger.Fatal("Error in decoding transfer payload", zap.Error(err))
			}

			// Add the key if it does not exist yet
			key := fmt.Sprintf(keyFormat, hdr.OriginAddress.String(), hdr.OriginChain)
			if _, exists := requestedOutOfBridge[key]; !exists {
				requestedOutOfBridge[key] = big.NewInt(0)
			}

			// Add the amount requested out of the bridge
			requestedOutOfBridge[key] = new(big.Int).Add(requestedOutOfBridge[key], hdr.Amount)

			numProcessed++
		}
	}

	// Iterate over all object changes, and find changes to objects that are wrapped or native assets.
	// Two object changes are of interest:
	// * native assets - the amount in custody of the native asset increases to show the funds were received
	// * wrapped assets - the balance of the wrapped asset decreases to show the funds were burned
	for _, objectChange := range txBlock.ObjectChanges {
		// Check that the type information is correct.
		if !objectChange.ValidateTypeInformation(*suiTokenBridgeContract) {
			continue
		}

		// Get the past objects
		resp, err := suiTryMultiGetPastObjects(*suiRPC, objectChange.ObjectId, objectChange.Version, objectChange.PreviousVersion)

		if err != nil {
			logger.Error("Error in getting past objects", zap.Error(err))
			continue
		}

		decimals, err := resp.GetDecimals()
		if err != nil {
			logger.Error("Error in getting decimals", zap.Error(err))
			continue
		}

		address, err := resp.GetTokenAddress()
		if err != nil {
			logger.Error("Error in getting token address", zap.Error(err))
			continue
		}

		chain, err := resp.GetTokenChain()
		if err != nil {
			logger.Error("Error in getting token chain", zap.Error(err))
			continue
		}

		// Get the balance difference
		balanceDiff, err := resp.GetBalanceDiff()
		if err != nil {
			logger.Error("Error in getting balance difference", zap.Error(err))
			continue
		}

		normalized := normalize(big.NewInt(int64(balanceDiff)), decimals)

		// Add the key if it does not exist yet
		key := fmt.Sprintf(keyFormat, address, chain)
		if _, exists := transferredIntoBridge[key]; !exists {
			transferredIntoBridge[key] = big.NewInt(0)
		}

		// Add the normalized amount to the transferredIntoBridge map
		transferredIntoBridge[key] = new(big.Int).Add(transferredIntoBridge[key], normalized)
	}

	// TODO: Using `Warn` for testing purposes. Update to Fatal? when ready to go into PR.
	// TODO: Revisit error handling here.
	for key, amountOut := range requestedOutOfBridge {
		if _, exists := transferredIntoBridge[key]; !exists {
			logger.Warn("transfer-out request for tokens that were never deposited",
				zap.String("tokenAddress", key))
			// TODO: Is it better to return or continue here?
			return numProcessed, errors.New("transfer-out request for tokens that were never deposited")
			// continue
		}

		amountIn := transferredIntoBridge[key]

		if amountOut.Cmp(amountIn) > 0 {
			logger.Warn("requested amount out is larger than amount in")
			return numProcessed, errors.New("requested amount out is larger than amount in")
		}

		keyParts := strings.Split(key, "-")
		logger.Info("bridge request processed",
			zap.String("tokenAddress", keyParts[0]),
			zap.String("chain", keyParts[1]),
			zap.String("amountOut", amountOut.String()),
			zap.String("amountIn", amountIn.String()))
	}

	return numProcessed, nil

}

type SuiApiResponse interface {
	GetError() error
}

func suiApiRequest[T SuiApiResponse](rpc string, method string, params string) (T, error) {
	var defaultT T

	// Create the request
	requestBody := fmt.Sprintf(`{"jsonrpc":"2.0", "id": 1, "method": "%s", "params": %s}`, method, params)

	req, err := http.NewRequest("POST", rpc, strings.NewReader(requestBody))
	if err != nil {
		return defaultT, fmt.Errorf("cannot create request: %w", err)
	}

	// Add headers
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return defaultT, fmt.Errorf("cannot send request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return defaultT, fmt.Errorf("cannot read response: %w", err)
	}

	// Parse the response
	var res T
	err = json.Unmarshal(body, &res)
	if err != nil {
		return defaultT, fmt.Errorf("cannot parse response: %w", err)
	}

	// Check if an error message exists
	if res.GetError() != nil {
		return defaultT, fmt.Errorf("error from Sui RPC: %w", res.GetError())
	}

	return res, nil
}

func suiGetTransactionBlock(rpc string, txDigest string) (SuiGetTransactionBlockResult, error) {

	method := "sui_getTransactionBlock"
	params := fmt.Sprintf(`[
				"%s", 
				{
					"showObjectChanges":true,
					"showEvents": true
				}
			]`, txDigest)

	resp, err := suiApiRequest[SuiGetTransactionBlockResponse](rpc, method, params)

	return resp.Result, err
}

func suixQueryEvents(rpc string, filter string, cursor string, limit int, descending bool) ([]SuiEvent, error) {
	method := "suix_queryEvents"
	params := fmt.Sprintf(`[%s, %s, %d, %t]`, filter, cursor, limit, descending)

	resp, err := suiApiRequest[SuiQueryEventsResponse](rpc, method, params)

	return resp.Result.Data, err
}

func suiTryMultiGetPastObjects(rpc string, objectId string, version string, previousVersion string) (SuiTryMultiGetPastObjectsResponse, error) {
	method := "sui_tryMultiGetPastObjects"
	params := fmt.Sprintf(`[
			[
				{"objectId" : "%s", "version" : "%s"},
				{"objectId" : "%s", "version" : "%s"}
			],
			{"showContent": true}
		]`, objectId, version, objectId, previousVersion)

	return suiApiRequest[SuiTryMultiGetPastObjectsResponse](rpc, method, params)
}
