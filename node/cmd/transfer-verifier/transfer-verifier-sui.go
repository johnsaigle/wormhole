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

	suiApiConnection := NewSuiApiConnection(*suiRPC)

	// Initial event fetching
	resp, err := suiApiConnection.QueryEvents(eventFilter, "null", 25, true)
	if err != nil {
		logger.Fatal("Error in querying initial events", zap.Error(err))
	}

	initialEvents := resp.Result.Data

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
				processDigest(*event.ID.TxDigest, suiApiConnection, logger)
			}
		}
	}

	// Ticker for live processing
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Context cancelled")
		case <-ticker.C:
			// Fetch new events
			resp, err := suiApiConnection.QueryEvents(eventFilter, "null", 25, true)
			if err != nil {
				logger.Error("Error in querying new events", zap.Error(err))
				continue
			}

			newEvents := resp.Result.Data

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
				processDigest(txDigest, suiApiConnection, logger)
			}

			logger.Info("New events processed", zap.Int("latestTimestamp", latestTimestamp), zap.Int("txDigestCount", len(txDigests)))

		}
	}
}

// processEvents takes a list of events and processes them to determine the amount requested out of the bridge. It returns a mapping
// that maps the token address and chain ID to the amount requested out of the bridge. It does not return an error, because any faulty
// events can be skipped, since they would likely fail being processed by the guardian as well. Debug level logging can be used to
// reveal any potential locations where errors are occurring.
func processEvents(events []SuiEvent, logger *zap.Logger) (requestedOutOfBridge map[string]*big.Int, numEventsProcessed int) {
	// Initialize the map to store the amount requested out of the bridge
	requestedOutOfBridge = make(map[string]*big.Int)

	// Filter events that have the sui token bridge emitter as the sender in the message. The events indicate
	// how much is going to leave the network.
	for _, event := range events {

		// If any of these event parameters are nil, skip the event
		if event.Message == nil || event.Message.Sender == nil || event.Type == nil {
			continue
		}

		// Only process the event if it is a WormholeMessage event from the token bridge emitter
		if *event.Type == suiEventType && *event.Message.Sender == *suiTokenBridgeEmitter {

			// Parse the wormhole message. vaa.IsTransfer can be omitted, since this is done
			// inside `DecodeTransferPayloadHdr` already.
			hdr, err := vaa.DecodeTransferPayloadHdr(event.Message.Payload)

			// If there is an error decoding the payload, skip the event
			if err != nil {
				logger.Debug("Error decoding payload", zap.Error(err))
				continue
			}

			// Add the key if it does not exist yet
			key := fmt.Sprintf(KEY_FORMAT, hdr.OriginAddress.String(), hdr.OriginChain)
			if _, exists := requestedOutOfBridge[key]; !exists {
				requestedOutOfBridge[key] = big.NewInt(0)
			}

			// Add the amount requested out of the bridge
			requestedOutOfBridge[key] = new(big.Int).Add(requestedOutOfBridge[key], hdr.Amount)

			numEventsProcessed++
		} else {
			logger.Debug("Event does not match the criteria", zap.String("event type", *event.Type), zap.String("event sender", *event.Message.Sender))
		}
	}

	return requestedOutOfBridge, numEventsProcessed
}

func processObjectUpdates(objectChanges []ObjectChange, suiApiConnection SuiApiInterface, logger *zap.Logger) (transferredIntoBridge map[string]*big.Int, numChangesProcessed int, err error) {
	transferredIntoBridge = make(map[string]*big.Int)

	for _, objectChange := range objectChanges {
		// Check that the type information is correct.
		if !objectChange.ValidateTypeInformation(*suiTokenBridgeContract) {
			continue
		}

		// Get the past objects
		resp, err := suiApiConnection.TryMultiGetPastObjects(objectChange.ObjectId, objectChange.Version, objectChange.PreviousVersion)

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

		normalized := normalize(balanceDiff, decimals)

		// Add the key if it does not exist yet
		key := fmt.Sprintf(KEY_FORMAT, address, chain)

		// Add the normalized amount to the transferredIntoBridge map
		// Intentionally use 'Set' instead of 'Add' because there should only be a single objectChange per token
		var amount big.Int
		transferredIntoBridge[key] = amount.Set(normalized)

		// Increment the number of changes processed
		numChangesProcessed++
	}

	return transferredIntoBridge, numChangesProcessed, nil
}

func processDigest(digest string, suiApiConnection SuiApiInterface, logger *zap.Logger) (uint, error) {
	// Get the transaction block
	txBlock, err := suiApiConnection.GetTransactionBlock(digest)

	if err != nil {
		logger.Fatal("Error in getting transaction block", zap.Error(err))
	}

	// process all events, indicating funds that are leaving the chain
	requestedOutOfBridge, numEventsProcessed := processEvents(txBlock.Result.Events, logger)

	// process all object changes, indicating funds that are entering the chain
	transferredIntoBridge, numChangesProcessed, err := processObjectUpdates(txBlock.Result.ObjectChanges, suiApiConnection, logger)

	if err != nil {
		logger.Fatal("Error in processing object changes", zap.Error(err))
	}

	// TODO: Using `Warn` for testing purposes. Update to Fatal? when ready to go into PR.
	// TODO: Revisit error handling here.
	for key, amountOut := range requestedOutOfBridge {

		if _, exists := transferredIntoBridge[key]; !exists {
			logger.Warn("transfer-out request for tokens that were never deposited",
				zap.String("tokenAddress", key))
			// TODO: Is it better to return or continue here?
			return 0, errors.New("transfer-out request for tokens that were never deposited")
			// continue
		}

		amountIn := transferredIntoBridge[key]

		if amountOut.Cmp(amountIn) > 0 {
			logger.Warn("requested amount out is larger than amount in")
			return 0, errors.New("requested amount out is larger than amount in")
		}

		keyParts := strings.Split(key, "-")
		logger.Info("bridge request processed",
			zap.String("tokenAddress", keyParts[0]),
			zap.String("chain", keyParts[1]),
			zap.String("amountOut", amountOut.String()),
			zap.String("amountIn", amountIn.String()))
	}

	logger.Info("Digest processed", zap.String("txDigest", digest), zap.Int("numEventsProcessed", numEventsProcessed), zap.Int("numChangesProcessed", numChangesProcessed))

	return uint(numEventsProcessed), nil
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

type SuiApiConnection struct {
	rpc string
}

func NewSuiApiConnection(rpc string) SuiApiInterface {
	return &SuiApiConnection{rpc: rpc}
}

func (s *SuiApiConnection) GetTransactionBlock(txDigest string) (SuiGetTransactionBlockResponse, error) {
	method := "sui_getTransactionBlock"
	params := fmt.Sprintf(`[
				"%s", 
				{
					"showObjectChanges":true,
					"showEvents": true
				}
			]`, txDigest)

	return suiApiRequest[SuiGetTransactionBlockResponse](s.rpc, method, params)
}

func (s *SuiApiConnection) QueryEvents(filter string, cursor string, limit int, descending bool) (SuiQueryEventsResponse, error) {
	method := "suix_queryEvents"
	params := fmt.Sprintf(`[%s, %s, %d, %t]`, filter, cursor, limit, descending)

	return suiApiRequest[SuiQueryEventsResponse](s.rpc, method, params)
}

func (s *SuiApiConnection) TryMultiGetPastObjects(objectId string, version string, previousVersion string) (SuiTryMultiGetPastObjectsResponse, error) {
	method := "sui_tryMultiGetPastObjects"
	params := fmt.Sprintf(`[
			[
				{"objectId" : "%s", "version" : "%s"},
				{"objectId" : "%s", "version" : "%s"}
			],
			{"showContent": true}
		]`, objectId, version, objectId, previousVersion)

	return suiApiRequest[SuiTryMultiGetPastObjectsResponse](s.rpc, method, params)
}
