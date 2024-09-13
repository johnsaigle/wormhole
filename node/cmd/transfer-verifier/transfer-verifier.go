package transferverifier

import (
	// "bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	// "github.com/ethereum/go-ethereum/log"
	ipfslog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	connectors "github.com/certusone/wormhole/node/pkg/watchers/evm/connectors"
	"github.com/certusone/wormhole/node/pkg/watchers/evm/connectors/ethabi"
)

// LogMessagePublished(address indexed sender, uint64 sequence, uint32 nonce, bytes payload, uint8 consistencyLevel);
const EVENTHASH_WORMHOLE_LOG_MESSAGE_PUBLISHED = "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2"

// Transfer(address,address,uint256)
const EVENTHASH_ERC20_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

// Deposit(address,uint256)
const EVENTHASH_WETH_DEPOSIT = "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c"

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000000000000000000000000000"

// Standard ERC20 Transfer constants. Note that `_value` (amount) is not indexed.
// event Transfer(address indexed _from, address indexed _to, uint256 _value)

// The expected total number of indexed topics for an ERC20 Transfer event
const TOPICS_COUNT_TRANSFER = 3

// Which index within the topics slice contains the destination for the ERC20 Transfer transaction
const DESTINATION_INDEX_TRANSFER = 2

// WETH Deposit constants. Note that `wad` (amount) is not indexed.
// https://etherscan.io/token/0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2#code
//     event  Deposit(address indexed dst, uint wad);

// Which index within the topics slice contains the destination for the WETH Deposit transaction
const DESTINATION_INDEX_DEPOSIT = 1

// The expected total number of indexed topics for a WETH Deposit event
const TOPICS_COUNT_DEPOSIT = 2

const EVM_FIELD_LENGTH = 32

type TransferType int64

const (
	Unknown TransferType = iota
	WrapAndTransferETH
	WrapAndTransferETHWithPayload
	TransferTokensWithPayload
	TransferTokens
	WrapAndTransferEthWithRelay
	TransferTokensWithRelay
)

// CLI args
var (
	// envStr *string
	logLevel            *string
	RPC                 *string
	coreContract        *string
	tokenBridgeContract *string
)

var TransferVerifierCmd = &cobra.Command{
	Use:   "transfer-verifier",
	Short: "transfer verifier",
	Run:   runTransferVerifier,
}

type TransferDetails struct {
	TokenAddress common.Address
	Amount       *big.Int
}

// Parse the amount and token address from a raw Ethereum transfer payload
func parseLogMessagePublishedPayload(data []byte) (*TransferDetails, error) {
	t := TransferDetails{}
	// https://docs.wormhole.com/wormhole/explore-wormhole/vaa

	// struct Transfer {
	//     uint8 payloadID;
	//     uint256 amount;
	//     bytes32 tokenAddress;
	//     uint16 tokenChain;
	//     bytes32 to;
	//     uint16 toChain;
	//     uint256 fee;
	// }

	// struct TransferWithPayload {
	//     uint8 payloadID;
	//     uint256 amount;
	//     bytes32 tokenAddress;
	//     uint16 tokenChain;
	//     bytes32 to;
	//     uint16 toChain;
	//     bytes32 fromAddress;
	//     bytes payload;
	// }

	// we are only interested in the amount and the token address
	// amount is at data[1:1 + 32]
	// tokenAddress is at data[33:33 + 32]

	// ensure we don't panic due to index out of bounds. We're indexing up to 1 uint8 and two EVM fields
	if len(data) < 2*EVM_FIELD_LENGTH+1 {
		return nil, errors.New("payload data is too short")
	}
	t.Amount = big.NewInt(0).SetBytes(data[1 : 1+32])
	t.TokenAddress = common.BytesToAddress(data[33 : 33+32])

	return &t, nil
}

func init() {
	// envStr = TransferVerifierCmd.Flags().String("env", "", `environment (may be "testnet" or "mainnet")`)
	logLevel = TransferVerifierCmd.Flags().String("logLevel", "info", "Logging level (debug, info, warn, error, dpanic, panic, fatal)")
	RPC = TransferVerifierCmd.Flags().String("ethRPC", "ws://localhost:8545", "Ethereum RPC url")
	coreContract = TransferVerifierCmd.Flags().String("ethContract", "", "Ethereum core bridge address for verifying VAAs (required if ethRPC is specified)")
	tokenBridgeContract = TransferVerifierCmd.Flags().String("tokenContract", "", "token bridge contract deployed on Ethereum")
}

// Note: logger.Error should be reserved only for conditions that break the invariants of the Token Bridge
func runTransferVerifier(cmd *cobra.Command, args []string) {

	// Setup logging
	lvl, err := ipfslog.LevelFromString(*logLevel)
	if err != nil {
		fmt.Println("Invalid log level")
		os.Exit(1)
	}

	logger := ipfslog.Logger("wormhole-transfer-verifier").Desugar()

	ipfslog.SetAllLoggers(lvl)
	logger.Info("Starting transfer verifier")
	logger.Debug("rpc connection", zap.String("url", *RPC))
	logger.Debug("core contract", zap.String("address", *coreContract))
	logger.Debug("token bridge contract", zap.String("address", *tokenBridgeContract))

	// Verify parameters
	if *RPC == "" || *coreContract == "" || *tokenBridgeContract == "" {
		logger.Fatal(
			"Must supply RPC, coreContract, and tokenContract",
			zap.String("RPC", *RPC),
			zap.String("coreContract", *coreContract),
			zap.String("tokenContract", *tokenBridgeContract),
		)
	}
	*coreContract = strings.ToLower(*coreContract)
	*tokenBridgeContract = strings.ToLower(*tokenBridgeContract)

	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()

	coreBridgeAddr := common.HexToAddress(*coreContract)
	ethConnector, err := connectors.NewEthereumBaseConnector(ctx, "eth", *RPC, coreBridgeAddr, logger)
	if err != nil {
		logger.Fatal("could not create new ethereum base connector",
			zap.Error(err))
	}

	tokenBridgeAddr := common.HexToAddress(*tokenBridgeContract)

	logs := make(chan *ethabi.AbiLogMessagePublished)
	errC := make(chan error)

	sub, err := ethConnector.WatchLogMessagePublished(context.Background(), errC, logs)
	if err != nil {
		logger.Fatal("Error on WatchLogMessagePublished",
			zap.Error(err))
	}
	if sub == nil {
		logger.Fatal("WatchLogMessagePublished returned nil")
	}

	// TODO: Store processed TXs in map
	// NOTE: Add a timer to clear the map
	countLogsProcessed := int(0)
	livenessInterval := int(2)
	for {
		select {
		case err := <-sub.Err():
			logger.Fatal("got error on ethConnector's error channel", zap.Error(err))
		case vLog := <-logs:

			logger.Debug("detected LogMessagePublished event",
				zap.String("txHash", vLog.Raw.TxHash.String()))
			if vLog.Sender != tokenBridgeAddr {
				logger.Debug("skip: sender is not token bridge",
					zap.String("txHash", vLog.Raw.TxHash.String()),
					zap.String("sender", vLog.Sender.Hex()))
				continue
			}

			logger.Debug("processing LogMessagePublished event",
				zap.String("txHash", vLog.Raw.TxHash.String()))

			logger.Debug("parsing LogMessagePublished payload",
				zap.String("payload", fmt.Sprintf("%x", vLog.Payload)))
			transferDetails, err := parseLogMessagePublishedPayload(vLog.Payload)
			if err != nil {
				// This should never occur when parsing well-formed payloads from the Token Bridge
				logger.Warn("error when parsing LogMessagePublished payload", zap.Error(err))
			}
			if transferDetails != nil {
				// nil check should be redundant after checking err, but this avoids nil pointer deref
				logger.Debug("expected transfer token", zap.String("tokenAddress", transferDetails.TokenAddress.Hex()))
				logger.Debug("expected transfer amount", zap.String("amount", transferDetails.Amount.String()))
			}

			receipt, err := ethConnector.TransactionReceipt(ctx, vLog.Raw.TxHash)
			if err != nil {
				logger.Warn("could not find core bridge receipt", zap.Error(err))
				continue
			}

			numProcessed, err := validateReceipt(receipt, tokenBridgeAddr, transferDetails, logger)
			if numProcessed == 0 {
				logger.Warn("receipt logs empty for tx", zap.String("txHash", vLog.Raw.TxHash.Hex()))
				continue
			}
			if err != nil {
				logger.Warn("could not parse core bridge receipt", zap.Error(err), zap.String("txHash", vLog.Raw.TxHash.String()))
				continue
			}

			// Basic liveness report and statistics
			countLogsProcessed += int(numProcessed)
			// TODO fix with a total count and a trigger
			if countLogsProcessed%livenessInterval == 0 {
				logger.Info("total logs processed:", zap.Int("count", countLogsProcessed))
			}
		}
	}
}

// validateReceipt Parses the receipt for a transaction that emits a LogMessagePublished event. Based on the other logs
// in the receipt, determines whether the receipt "looks normal".
// "Normal" for EVM means that at some point in the receipt, tokens were sent to the Token Bridge contract. This can happen
// either via an ERC20 transfer or WETH Deposit where the recipient is the Token Bridge.
// Note that more complex interactions with the Token Bridge contract, e.g. relays or higher-level swap protocols,
// the may contain many Transfers or Deposits.
// Returns the number of logs parsed from the receipt.
func validateReceipt(
	receipt *types.Receipt,
	tokenBridgeAddr common.Address,
	// The uint256 amount parsed from the payload of LogMessagePublished
	transferDetails *TransferDetails,
	logger *zap.Logger) (numProcessed int, err error) {

	// Sanity check. Shouldn't be necessary but no harm
	if receipt.Status != 1 {
		return 0, fmt.Errorf("non-success transaction status: %d", receipt.Status)
	}

	// The number of ERC20 Transfer() events that occurred in this receipt
	transferCount := 0
	// The number of WETH Deposit() events that occurred in this receipt
	depositCount := 0

	// Whether a Transfer or Deposit has the token bridge as the destination
	tokensWentIn := false
	// Whether the transfer overall is benign
	looksNormal := false

	logger.Debug("processing logs for receipt",
		zap.Int("logCountForReceipt", len(receipt.Logs)))

	// If transferDetails is nil, there is no valid payload
	hasValidPayload := transferDetails != nil
	if !hasValidPayload {
		logger.Warn("validating receipt with nil transfer details")
	}

	for i, log := range receipt.Logs {
		if log == nil {
			logger.Warn("receipt log is nil. skipping.",
				zap.Int("index", i))
			continue
		}

		// Debug information for the log and its topics
		logger.Debug("processing receipt log",
			zap.Int("index", i),
			zap.String("emittedBy", log.Address.Hex()))
		for i, topic := range log.Topics {
			logger.Debug("topic info", zap.String("topic", topic.Hex()), zap.Int("index", i))
		}

		// Process a Deposit() log
		if log.Topics[0] == common.HexToHash(EVENTHASH_WETH_DEPOSIT) {
			logger.Debug("topic found: Deposit()",
				zap.Int("logIndex", i))
			depositCount += 1

			logger.Debug("deposit data:",
				zap.String("data", fmt.Sprintf("%x", log.Data)),
				zap.Int("length", len(log.Data)))

			structureError := validateDeposit(log)
			if structureError != nil {
				logger.Warn("invalid Deposit() logs: ", zap.Error(structureError))
				continue
			}

			// Extra logging
			if !hasValidPayload {
				// This can happen if the LogMessagePublished emitted an invalid payload that this
				// program could not parse. Note that this payload refers to the payload of the
				// EVM log, and not to Wormhole's use of the term in the context of VAAs.
				logger.Warn("transfer details could not be parsed from LogMessagePublished payload. skipping verification of payload's tokenAddress")
			} else {
				logPayloadStatus(transferDetails.TokenAddress, log.Address, logger)
			}

			tokensWentIn = depositRecipientIsTokenBridge(log, &tokenBridgeAddr, logger)
			amountsMatch := amountsCorrespond(log, transferDetails.Amount, logger)

			if tokensWentIn && amountsMatch {
				logger.Info("marking receipt as 'normal' based on processed logs")
				looksNormal = true
				continue
			}
		} // end check Deposit()

		// Process a Transfer() log
		if log.Topics[0] == common.HexToHash(EVENTHASH_ERC20_TRANSFER) {
			logger.Debug("topic found: Transfer()",
				zap.Int("logIndex", i))
			transferCount += 1

			logger.Debug("transfer data:",
				zap.String("data", fmt.Sprintf("%x", log.Data)),
				zap.Int("length", len(log.Data)))

			structureError := validateTransfer(log)
			if structureError != nil {
				logger.Warn("invalid Transfer() logs: ", zap.Error(structureError))
				continue
			}

			// Extra logging
			if !hasValidPayload {
				// This can happen if the LogMessagePublished emitted an invalid payload that the
				// program could not parse. Here we Warn but it won't be possible for this transfer to
				// pass validation later and will eventually result in an Error.
				// The main purpose of this check is to avoid a nil dereference later in the program
				// if `transferDetails` is nil.
				logger.Warn("transfer details could not be parsed from payload. skipping verification of payload's tokenAddress")
			} else {
				logPayloadStatus(transferDetails.TokenAddress, log.Address, logger)
			}

			tokensWentIn = transferDestinationIsTokenBridge(log, &tokenBridgeAddr, logger)
			amountsMatch := amountsCorrespond(log, transferDetails.Amount, logger)

			if tokensWentIn && amountsMatch {
				logger.Info("marking receipt as 'normal' based on processed logs")
				looksNormal = true
				continue
			}

		} // end check Transfer()
	}

	if !looksNormal {
		logger.Error("message published from core contract without Transfer or Deposit to the Token Bridge",
			zap.String("txHash", receipt.TxHash.Hex()))
	}

	logger.Info("Receipt statistics",
		zap.String("inferredTransferType", inferTransferType(transferCount, depositCount, hasValidPayload).String()),
		zap.Int("erc20Transfers", transferCount),
		zap.Int("wethDeposits", depositCount),
		zap.Bool("hasValidPayload", hasValidPayload))

	return int(len(receipt.Logs)), err
}

// validateDeposit returns an error if  the Deposit event is not well-formed
func validateDeposit(
	log *types.Log,
) error {
	// We expect exactly one field here: the amount.
	if len(log.Data) != EVM_FIELD_LENGTH {
		return fmt.Errorf("event Deposit() detected but log data is invalid")
	}
	// e.g. https://etherscan.io/tx/0x163dd63e8327b494bd22de9b83984fed82e7a6a9af100dbee8ac5c1ade6dea1b/advanced#eventlog
	count := len(log.Topics)
	// Ensure that the Deposit log has the right number of topics so we don't index into topics that aren't there.
	if count != TOPICS_COUNT_DEPOSIT {
		return fmt.Errorf("event Deposit() detected but has wrong number of topics. Got %d, expected %d", TOPICS_COUNT_DEPOSIT, count)
	}
	return nil
}

// validTransfer returns an error if  the Transfer event is not well-formed
func validateTransfer(
	log *types.Log,
) error {
	// We expect exactly one field here: the amount.
	if len(log.Data) != EVM_FIELD_LENGTH {
		return fmt.Errorf("event Transfer() detected but log data is invalid")
	}
	count := len(log.Topics)
	expected := TOPICS_COUNT_TRANSFER
	// Ensure that the Deposit log has the right number of topics so we don't index into topics that aren't there.
	if count != expected {
		return fmt.Errorf("event Transfer() detected but has wrong number of topics. Got %d, expected %d", expected, count)
	}
	return nil
}

func depositRecipientIsTokenBridge(
	// Deposit() log
	log *types.Log,
	tokenBridgeAddr *common.Address,
	logger *zap.Logger,
) (found bool) {
	destination := strings.ToLower(log.Topics[DESTINATION_INDEX_DEPOSIT].Hex())

	// The topic is prepended with 0s so check for the token bridge's address as a suffix. Strip
	// the leading `0x`.
	if !strings.HasSuffix(destination, strings.ToLower(tokenBridgeAddr.Hex()[2:])) {
		logger.Info("event Deposit() detected but destination is not token bridge",
			zap.String("tokenBridge", tokenBridgeAddr.Hex()),
			zap.String("destination", destination))
		return false
	}
	logger.Debug("event Deposit()'s destination is token bridge",
		zap.String("tokenBridge", tokenBridgeAddr.Hex()),
		zap.String("destination", destination))
	return true
}

// amountsCorrespond compares the log's contents with the amount figure parsed from the LogMessagePublished event's payload.
func amountsCorrespond(
	// Transfer() or Deposit() log
	log *types.Log,
	// Value from LogMessagePublished's payload
	payloadAmount *big.Int,
	logger *zap.Logger,
) bool {
	logDataAmount := big.NewInt(0).SetBytes(log.Data[2:]) // remove `0x` prefix
	smaller := big.NewInt(0)
	larger := big.NewInt(0)

	// big.Ints can't use `==` because it compares the pointers, not the values
	switch logDataAmount.Cmp(payloadAmount) {
	case 0:
		logger.Info("amounts match",
			zap.String("transferAmount", fmt.Sprintf("%d", logDataAmount)),
			zap.String("payloadAmount", fmt.Sprintf("%d", payloadAmount)))
		return true
	case 1:
		larger = logDataAmount
		smaller = payloadAmount
	case -1:
		larger = payloadAmount
		smaller = logDataAmount
	}
	logger.Info("amounts do not match",
		zap.String("transferAmount", fmt.Sprintf("%d", logDataAmount)),
		zap.String("payloadAmount", fmt.Sprintf("%d", payloadAmount)))

	likelyNormalized, err := amountLikelyNormalized(larger, smaller)
	if err != nil {
		logger.Warn("error when checking amounts. this is probably a bug.",
			zap.Error(err))
		return false
	}
	if likelyNormalized {
		logger.Info("amounts are likely normalized")
	}
	return likelyNormalized
}

// amountLikelyNormalized determines whether two values are likely to be normalized version of each other.
// The amounts may not be an exact match due to the normalization process.
// See https://github.com/wormhole-foundation/wormhole/blob/main/whitepapers/0003_token_bridge.md#handling-of-token-amounts-and-decimals
// The receipt log does not contain information about the correct number of decimals on either side.
// To avoid adding latency here via making an RPC request to the contract address, we use some heuristics
// to determine whether the amounts appear to be normalized versions of each other.
func amountLikelyNormalized(larger *big.Int, smaller *big.Int) (bool, error) {
	zero := big.NewInt(0)
	ten := big.NewInt(10)

	// Basic validation
	err := errors.New("arguments to amountLikelyNormalized invalid")
	if larger.Cmp(zero) == 0 || smaller.Cmp(zero) == 0 {
		// Mandatory check or else division by zero may occur
		return false, errors.Join(err, errors.New("arguments must not be zero"))
	}
	if larger.Cmp(smaller) != 1 {
		// This also ensures that the arguments are not equal
		return false, errors.Join(err, errors.New("argument 'larger' must be greater than argument 'smaller'"))
	}
	if larger.Cmp(zero) != 1 || smaller.Cmp(zero) != 1 {
		return false, errors.Join(err, errors.New("arguments must be positive"))
	}

	// Effectively do a `log10(larger)` and make sure that it equals `smaller`. This ensures some mathematical
	// properties that must hold for scaled/normalized amounts, e.g.:
	// - smaller is a factor of larger
	// - larger is divisible by 10

	// placeholder value. An intermediate value that is a representation of `larger` divided by some power of 10.
	n := larger
	for {
		// End the loop. Intermediate value cannot be evenly divided by 10.
		// Should be non-infinite because the values are non equal and non zero
		if big.NewInt(1).Mod(n, ten).Cmp(zero) != 0 {
			break
		}

		if n.Cmp(smaller) == 0 {
			// We're done: smaller == log10(larger), so larger is the normalized representation of smaller
			break
		}
		n.Div(n, ten)
	}

	return n.Cmp(smaller) == 0, nil
}

// transferDestinationIsTokenBridge returns whether the Transfer()'s destination is the Token Bridge.
// Returns two booleans: `found` if the destination matches.
func transferDestinationIsTokenBridge(
	// Transfer() log
	log *types.Log,
	tokenBridgeAddr *common.Address,
	logger *zap.Logger,
) bool {
	destination := strings.ToLower(log.Topics[DESTINATION_INDEX_TRANSFER].Hex())

	// The topic is prepended with 0s so check for the token bridge's address as a suffix. Strip
	// the leading `0x`.
	if !strings.HasSuffix(destination, strings.ToLower(tokenBridgeAddr.Hex()[2:])) {
		// This can happen if multiple Transfers occur in the same receipt. It is common
		// when third party apps make use of the token bridge.
		logger.Info("event Transfer() detected but destination is not token bridge",
			zap.String("tokenBridge", tokenBridgeAddr.Hex()),
			zap.String("destination", destination))

		if destination == ZERO_ADDRESS {
			logger.Info("event Transfer() is a burn (destination is zero address)")
		}
		return false
	}

	logger.Debug("event Transfer()'s destination is token bridge",
		zap.String("tokenBridge", tokenBridgeAddr.Hex()),
		zap.String("destination", destination))

	return true
}

// inferTransferType guesses the transfer type based on the number of events seen in the receipt and whether the program
// was able to parse a valid payload from LogMessagePublished.
// This is limited to known, common ways of interacting with the Token Bridge such as calling its functions directly
// or via a Token Relayer. Any of these could be combined with other transactions so this should not be considered an
// exhaustive list.
func inferTransferType(transferCount int, depositCount int, hasValidPayload bool) TransferType {
	// Simple transfer of wrapped ETH
	if transferCount == 0 && depositCount == 1 {
		if hasValidPayload {
			return WrapAndTransferETHWithPayload
		} else {
			return WrapAndTransferETH
		}
	}
	// Simple token transfer
	if transferCount == 1 && depositCount == 0 {
		if hasValidPayload {
			return TransferTokens
		} else {
			return TransferTokensWithPayload
		}
	}
	// See wrapAndTransferEthWithRelay().
	// https://github.com/wormhole-foundation/example-token-bridge-relayer/blob/main/evm/src/token-bridge-relayer/TokenBridgeRelayer.sol#L152
	if transferCount == 1 && depositCount == 1 {
		if hasValidPayload {
			return WrapAndTransferEthWithRelay
		}
	}

	// See transferTokensWithRelay()
	// https://github.com/wormhole-foundation/example-token-bridge-relayer/blob/main/evm/src/token-bridge-relayer/TokenBridgeRelayer.sol#L99
	if depositCount == 0 && transferCount == 2 {
		if hasValidPayload {
			return TransferTokensWithRelay
		}
	}
	// TODO: Count the typical number of Transfers for things like the Token Relays
	// wrapAndTransferEthWithRelay
	// https://github.com/wormhole-foundation/example-token-bridge-relayer/blob/main/evm/src/token-bridge-relayer/TokenBridgeRelayer.sol#L198

	return Unknown
}

// logPayloadStatus logs whether the `tokenAddress` field parsed from the transfer's payload matches the `emitter` of
// a given event log.This isn't a requirement but it might be helpful to log this mismatch.
// The tokenAddress in the payload may not match the token that emitted the event.
// For typical EVM transfers we would expect this to be true, but for cross-chain transfers
// the tokenAddress in the payload may target a contract on another chain.
func logPayloadStatus(payloadTokenAddress common.Address, emitter common.Address, logger *zap.Logger) {
	if payloadTokenAddress != emitter {
		logger.Info("event emitter does not match tokenAddress in payload",
			zap.String("emittedBy", emitter.Hex()),
			zap.String("expectedTokenAddress", payloadTokenAddress.Hex()))
		return
	}

	logger.Info("event emitter matches tokenAddress in payload",
		zap.String("emittedBy", emitter.Hex()),
		zap.String("expectedTokenAddress", payloadTokenAddress.Hex()))
}

// String returns a string representation for TransferType enum variants. Returns "unknown" for variants not explicitly
// handled.
func (t TransferType) String() string {
	switch t {
	case WrapAndTransferETH:
		return "wrapAndTransferETH"
	case WrapAndTransferETHWithPayload:
		return "wrapAndTransferETHWithPayload"
	case TransferTokens:
		return "transferTokens"
	case TransferTokensWithPayload:
		return "transferTokensWithPayload"
	case WrapAndTransferEthWithRelay:
		return "wrapAndTransferEthWithRelay"
	case TransferTokensWithRelay:
		return "transferTokensWithRelay"
	default:
		return "unknown"
	}
}
