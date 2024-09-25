package transferverifier

// TODOs
//	tests
//	globalize tokenBridgeAddress and coreBridgeAddress
//	fix up contexts where it makes sense
//	make EVM selectors more pretty?
//	improve error propogation

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	// "github.com/ethereum/go-ethereum/log"
	ipfslog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	connectors "github.com/certusone/wormhole/node/pkg/watchers/evm/connectors"
	"github.com/certusone/wormhole/node/pkg/watchers/evm/connectors/ethabi"
)

// Event signatures
var (
	// LogMessagePublished(address indexed sender, uint64 sequence, uint32 nonce, bytes payload, uint8 consistencyLevel);
	EVENTHASH_WORMHOLE_LOG_MESSAGE_PUBLISHED = "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2"
	// Transfer(address,address,uint256)
	EVENTHASH_ERC20_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	// Deposit(address,uint256)
	EVENTHASH_WETH_DEPOSIT = "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c"
)

// Fixed addresses
const (
	ZERO_ADDRESS = "0x0000000000000000000000000000000000000000000000000000000000000000"
)

// https://etherscan.io/token/0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
var WETH_ADDRESS = common.HexToAddress("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")

// Standard ERC20 Transfer constants. Note that `_value` (amount) is not indexed.
// event Transfer(address indexed _from, address indexed _to, uint256 _value)

// The expected total number of indexed topics for an ERC20 Transfer event
const TOPICS_COUNT_TRANSFER = 3

// Which index within the topics slice contains the destination for the ERC20 Transfer transaction
const DESTINATION_INDEX_TRANSFER = 2

// The Wormhole Chain ID for the chain being monitored
const NATIVE_CHAIN_ID = 2

// WETH Deposit constants. Note that `wad` (amount) is not indexed.
// https://etherscan.io/token/0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2#code
//     event  Deposit(address indexed dst, uint wad);

// Which index within the topics slice contains the destination for the WETH Deposit transaction
const DESTINATION_INDEX_DEPOSIT = 1

// The expected total number of indexed topics for a WETH Deposit event
const TOPICS_COUNT_DEPOSIT = 2

const EVM_FIELD_LENGTH = 32

// EVM selectors
var (
	// wrappedAsset(uint16 tokenChainId, bytes32 tokenAddress) => 0x1ff1e286
	TOKEN_BRIDGE_WRAPPED_ASSET = []byte("\x1f\xf1\xe2\x86")

	// decimals() => 0x313ce567
	ERC20_DECIMALS_SIGNATURE = []byte("\x31\x3c\xe5\x67")
)

// Global caches
var (
	// Holds previously-recorded decimals (uint8) for token addresses (common.Address)
	// that have been observed.
	decimalsCache = make(map[common.Address]uint8)

	// Maps the 32-byte token addresses received via LogMessagePublished events to their
	// unwrapped 20-byte addresses. This mapping is also used for non-wrapped token addresses.
	wrappedCache = make(map[string]common.Address)
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

// Settings for how often to prune the processed receipts.
type pruneConfig struct {
	// The block height at which to prune receipts, represented as an offset to subtract from the latest block
	// height, e.g. a pruneHeightDelta of 10 means prune blocks older than latestBlockHeight - 10.
	pruneHeightDelta uint64
	// How often to prune the cache.
	pruneFrequency time.Duration
}

type TransferDetails struct {
	TokenAddress common.Address
	TokenChain   uint16
	Amount       *big.Int
}

func parseERC20TransferEvent(logTopics []common.Hash, logData []byte) (from common.Address, to common.Address, amount *big.Int) {

	// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/6e224307b44bc4bd0cb60d408844e028cfa3e485/contracts/token/ERC20/IERC20.sol#L16
	// event Transfer(address indexed from, address indexed to, uint256 value)
	if len(logData) != 32 || len(logTopics) != TOPICS_COUNT_TRANSFER {
		return common.Address{}, common.Address{}, nil
	}

	from = common.BytesToAddress(logTopics[1][:])
	to = common.BytesToAddress(logTopics[2][:])
	amount = new(big.Int).SetBytes(logData[:])

	return from, to, amount
}

// TODO: maybe make this wnative or something? fine for now, since this is for the ethereum network
func parseWethDepositEvent(logTopics []common.Hash, logData []byte) (destination common.Address, amount *big.Int) {

	// https://etherscan.io/token/0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2#code#L29
	// event  Deposit(address indexed dst, uint wad);
	if len(logData) != 32 || len(logTopics) != TOPICS_COUNT_DEPOSIT {
		return common.Address{}, nil
	}

	destination = common.BytesToAddress(logTopics[1][:])
	amount = new(big.Int).SetBytes(logData[:])

	return destination, amount
}

// parseLogMessagePublishedPayload() parses the details of a transfer from a LogMessagePublished event emitted by the core contract.
func parseLogMessagePublishedPayload(data []byte, tokenBridgeAddr common.Address, ethConnector *connectors.EthereumBaseConnector, logger *zap.Logger) (*TransferDetails, error) {
	t := TransferDetails{}

	// TODO: improve commenting here
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

	// Ensure we don't panic due to index out of bounds. We're indexing up to 1 uint8, x2 32-byte fields and a uint16
	if len(data) < 1+2*32+2 {
		return nil, errors.New("payload data is too short")
	}

	// Parse the amount, tokenAddress and tokenChain from the event
	amount := big.NewInt(0).SetBytes(data[1 : 1+32])
	rawTokenAddress := data[33 : 33+32]
	tokenChain := binary.BigEndian.Uint16(data[65 : 65+2])

	// Unwrap the token address if needed, but short-circuit if the chain ID for the token
	// is the wormhole chain ID of the network being monitored.
	var tokenAddress common.Address
	if tokenChain == NATIVE_CHAIN_ID {
		tokenAddress = common.BytesToAddress(rawTokenAddress)
	} else {
		unwrappedTokenAddress, err := unwrapIfWrapped(rawTokenAddress, tokenChain, tokenBridgeAddr, ethConnector, logger)
		if err != nil {
			logger.Fatal("a fatal error occurred when attempting to unwrap a token address")
			return &t, err
		}

		tokenAddress = unwrappedTokenAddress
	}

	// Denormalize the token amount.
	decimals, err := getDecimals(tokenAddress, ethConnector, logger)
	if err != nil {
		logger.Fatal("a fatal error occurred when attempting to get decimals",
			zap.Error(err),
		)
		return &t, err
	}
	denormalizedAmount := denormalize(amount, decimals)

	t.Amount = new(big.Int).Set(denormalizedAmount)
	t.TokenAddress = tokenAddress
	t.TokenChain = tokenChain
	return &t, nil
}

// CLI parameters
func init() {
	// envStr = TransferVerifierCmd.Flags().String("env", "", `environment (may be "testnet" or "mainnet")`)
	logLevel = TransferVerifierCmd.Flags().String("logLevel", "info", "Logging level (debug, info, warn, error, dpanic, panic, fatal)")
	RPC = TransferVerifierCmd.Flags().String("ethRPC", "ws://localhost:8545", "Ethereum RPC url")
	coreContract = TransferVerifierCmd.Flags().String("ethContract", "", "Ethereum core bridge address for verifying VAAs (required if ethRPC is specified)")
	tokenBridgeContract = TransferVerifierCmd.Flags().String("tokenContract", "", "token bridge contract deployed on Ethereum")
}

// Note: logger.Error should be reserved only for conditions that break the invariants of the Token Bridge
func runTransferVerifier(cmd *cobra.Command, args []string) {

	// TODO: Should these be CLI parameters?
	pruneConfig := &pruneConfig{
		pruneHeightDelta: uint64(10),
		pruneFrequency:   time.Duration(1 * time.Minute),
	}

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

	// Verify CLI parameters
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
	coreBridgeAddr := common.HexToAddress(*coreContract)
	tokenBridgeAddr := common.HexToAddress(*tokenBridgeContract)

	// Create the RPC connection, context, and channels
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()

	ethConnector, err := connectors.NewEthereumBaseConnector(ctx, "eth", *RPC, coreBridgeAddr, logger)
	if err != nil {
		logger.Fatal("could not create new ethereum base connector",
			zap.Error(err))
	}

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

	// Counter for amount of logs processed
	countLogsProcessed := int(0)

	// Mapping to track the transactions that have been processed
	processedTransactions := make(map[common.Hash]*types.Receipt)

	// The latest transaction block number, used to determine the size of historic receipts to keep in memory
	lastBlockNumber := uint64(0)

	// Ticker to clear historic transactions that have been processed
	ticker := time.NewTicker(pruneConfig.pruneFrequency)
	defer ticker.Stop() // delete for Go >= 1.23. See time.NewTicker() documentation.
	for {
		select {
		case err := <-sub.Err():
			logger.Fatal("got error on ethConnector's error channel", zap.Error(err))
		case <-ticker.C:

			// Basic liveness report and statistics
			logger.Info("total logs processed:", zap.Int("count", countLogsProcessed))

			// Prune the cache of processed receipts
			numPrunedReceipts := int(0)
			// Iterate over recorded transaction hashes, and clear receipts older than `pruneDelta` blocks
			for hash, receipt := range processedTransactions {
				if receipt.BlockNumber.Uint64() < lastBlockNumber-pruneConfig.pruneHeightDelta {
					numPrunedReceipts++
					delete(processedTransactions, hash)
				}
			}

			logger.Debug("pruned cached transaction receipts",
				zap.Int("numPrunedReceipts", numPrunedReceipts))

		case vLog := <-logs:

			logger.Debug("detected LogMessagePublished event",
				zap.String("txHash", vLog.Raw.TxHash.String()))
			if vLog.Sender != tokenBridgeAddr {
				logger.Debug("skip: sender is not token bridge",
					zap.String("txHash", vLog.Raw.TxHash.String()),
					zap.String("sender", vLog.Sender.Hex()))
				continue
			}

			// record used/inspected tx hash
			if _, exists := processedTransactions[vLog.Raw.TxHash]; exists {
				logger.Debug("skip: transaction hash already processed",
					zap.String("txHash", vLog.Raw.TxHash.String()))
				continue
			}

			// get transaction receipt
			receipt, err := ethConnector.TransactionReceipt(ctx, vLog.Raw.TxHash)
			if err != nil {
				logger.Warn("could not find core bridge receipt", zap.Error(err))
				continue
			}

			// process transaction receipt
			processedTransactions[vLog.Raw.TxHash] = receipt

			// record a new lastBlockNumber
			lastBlockNumber = receipt.BlockNumber.Uint64()

			numProcessed, err := processReceipt(receipt, coreBridgeAddr, tokenBridgeAddr, ethConnector, logger)

			if numProcessed == 0 {
				logger.Warn("receipt logs empty for tx", zap.String("txHash", vLog.Raw.TxHash.Hex()))
				continue
			}
			if err != nil {
				logger.Warn("could not parse core bridge receipt", zap.Error(err), zap.String("txHash", vLog.Raw.TxHash.String()))
				continue
			}

			countLogsProcessed += int(numProcessed)
		}
	}
}

// denormalize() scales an amount to its native decimal representation by multiplying it by some power of 10.
// See also:
// - documentation: https://github.com/wormhole-foundation/wormhole/blob/main/whitepapers/0003_token_bridge.md#handling-of-token-amounts-and-decimals
// - solidity implementation: https://github.com/wormhole-foundation/wormhole/blob/91ec4d1dc01f8b690f0492815407505fb4587520/ethereum/contracts/bridge/Bridge.sol#L295-L300
func denormalize(
	amount *big.Int,
	decimals uint8,
) (denormalizedAmount *big.Int) {
	if decimals > 8 {
		// Scale from 8 decimals to `decimals`
		exponent := new(big.Int).SetInt64(int64(decimals - 8))
		multiplier := new(big.Int).Exp(new(big.Int).SetInt64(10), exponent, nil)
		denormalizedAmount = new(big.Int).Mul(amount, multiplier)

	} else {
		// No scaling necessary
		denormalizedAmount = new(big.Int).Set(amount)
	}

	return denormalizedAmount
}

// TODO: write tests
func getDecimals(
	tokenAddress common.Address,
	ethConnector *connectors.EthereumBaseConnector,
	logger *zap.Logger) (decimals uint8, err error) {
	ctx := context.TODO()

	// First check if this token's decimals is stored in cache
	if _, exists := decimalsCache[tokenAddress]; exists {
		logger.Debug("asset decimals found in cache, returning")
		return decimalsCache[tokenAddress], nil
	}

	// If the decimals aren't cached, perform an eth_call lookup for the decimals
	// This RPC call should only be made once per token, until the guardian is restarted
	ethCallMsg := ethereum.CallMsg{
		To:   &tokenAddress,
		Data: ERC20_DECIMALS_SIGNATURE,
	}

	result, err := ethConnector.Client().CallContract(ctx, ethCallMsg, nil)
	if err != nil || len(result) < 32 {
		logger.Fatal("failed to get decimals for token",
			zap.String("tokenAddress", tokenAddress.String()))
		return 0, err
	}

	// TODO: find out if there is some official documentation for why this uint8 is in the last index of the 32byte return.
	// An ERC20 token's decimals should fit in a single byte. A call to `decimals()`
	// returns a uint8 value encoded in string with 32-bytes. To get the decimals,
	// we grab the last byte, expecting all the preceding bytes to be equal to 0.
	decimals = result[31]

	// Add the decimal value to the cache
	logger.Debug("adding new token's decimals to cache",
		zap.String("tokenAddress", tokenAddress.String()),
		zap.Uint8("tokenDecimals", decimals))

	decimalsCache[tokenAddress] = decimals

	return decimals, nil
}

// unwrapIfWrapped() returns the "unwrapped" address for a token a.k.a. the OriginAddress
// of the token's original minting contract.
func unwrapIfWrapped(
	tokenAddress []byte,
	tokenChain uint16,
	tokenBridgeAddr common.Address,
	ethConnector *connectors.EthereumBaseConnector,
	logger *zap.Logger) (unwrappedTokenAddress common.Address, err error) {
	ctx := context.TODO()

	tokenAddressAsKey := hex.EncodeToString(tokenAddress)

	// If the token address already exists in the wrappedCache mapping the
	// cached value can be returned.
	if addr, exists := wrappedCache[tokenAddressAsKey]; exists {
		logger.Debug("wrapped asset found in cache, returning")
		return addr, nil
	}

	// prepare eth_call data, 4-byte signature + 2x 32 byte arguments
	calldata := make([]byte, 4+32+32)

	copy(calldata, TOKEN_BRIDGE_WRAPPED_ASSET)
	// Add the uint16 tokenChain as the last two bytes in the first argument
	binary.BigEndian.PutUint16(calldata[4+30:], tokenChain)
	copy(calldata[4+32:], tokenAddress)

	ethCallMsg := ethereum.CallMsg{
		To:   &tokenBridgeAddr,
		Data: calldata,
	}

	result, err := ethConnector.Client().CallContract(ctx, ethCallMsg, nil)
	if err != nil {
		logger.Fatal("failed to get mapping for token",
			zap.String("tokenAddress", tokenAddressAsKey))
		return unwrappedTokenAddress, err
	}

	tokenAddressNative := common.BytesToAddress(result)
	wrappedCache[tokenAddressAsKey] = tokenAddressNative

	return tokenAddressNative, nil
}

// processReceipt parses and verifies that a receipt for a LogMessagedPublished event does not verify a fundamental
// invariant of Wormhole token transfers: when the core bridge reports a transfer has occurred, there must be a
// corresponding transfer in the token bridge. This is determined by iterating through the logs of the receipt and
// ensuring that the sum transferred into the token bridge does not exceed the sum emitted by the core bridge.
func processReceipt(
	receipt *types.Receipt,
	coreBridgeAddr common.Address,
	tokenBridgeAddr common.Address,
	ethConnector *connectors.EthereumBaseConnector,
	logger *zap.Logger) (numProcessed int, err error) {

	// Sanity check. Shouldn't be necessary but no harm
	if receipt.Status != 1 {
		return 0, fmt.Errorf("non-success transaction status: %d", receipt.Status)
	}

	numProcessed = 0
	// The sum of tokens transferred into the Token Bridge contract.
	transferredIntoBridge := make(map[common.Address]*big.Int)
	// The sum of tokens parsed from the core bridge's LogMessagePublished payload.
	requestedOutOfBridge := make(map[common.Address]*big.Int)

	for _, log := range receipt.Logs {
		switch log.Topics[0] {
		case common.HexToHash(EVENTHASH_ERC20_TRANSFER):
			_, to, amount := parseERC20TransferEvent(log.Topics, log.Data)

			// If the amount is nil, or the destination of the transfer isn't the tokenBridge, ignore.
			if amount == nil || to != tokenBridgeAddr {
				continue
			}

			// The emitter of the log is the token address
			tokenAddr := log.Address

			// Create the new entry in transferredIntoBridge if it does not exist, otherwise just add
			// the amount to the existing entry.
			if _, exists := transferredIntoBridge[tokenAddr]; !exists {
				transferredIntoBridge[tokenAddr] = new(big.Int).Set(amount)
			} else {
				transferredIntoBridge[tokenAddr] = new(big.Int).Add(transferredIntoBridge[tokenAddr], amount)
			}

			logger.Debug("a deposit into the token bridge was recorded",
				zap.String("tokenAddress", tokenAddr.String()),
				zap.String("amount", amount.String()))

		case common.HexToHash(EVENTHASH_WETH_DEPOSIT):
			// If the event was not emitted by the WETH contract, ignore
			if log.Address != WETH_ADDRESS {
				continue
			}

			// Extract the destination and amount for the deposit
			destination, amount := parseWethDepositEvent(log.Topics, log.Data)

			// if the amount is nil, or the destination is not the token bridge, then just continue
			if amount == nil || destination != tokenBridgeAddr {
				continue
			}

			// Create the new entry in transferredIntoBridge if it does not exist, otherwise just add
			// the amount to the existing entry.
			if _, exists := transferredIntoBridge[WETH_ADDRESS]; !exists {
				transferredIntoBridge[WETH_ADDRESS] = new(big.Int).Set(amount)
			} else {
				transferredIntoBridge[WETH_ADDRESS] = new(big.Int).Add(transferredIntoBridge[WETH_ADDRESS], amount)
			}

			logger.Debug("a deposit into the token bridge was recorded",
				zap.String("tokenAddress", WETH_ADDRESS.String()),
				zap.String("amount", amount.String()))

		case common.HexToHash(EVENTHASH_WORMHOLE_LOG_MESSAGE_PUBLISHED):
			// If the core bridge did not emit the event, ignore it.
			if log.Address != coreBridgeAddr {
				continue
			}

			// Convert the log to a LogMessagePublished event
			logMessagePublished, err := ethConnector.ParseLogMessagePublished(*log)
			if err != nil {
				logger.Fatal("failed to parse LogMessagePublished event")
			}

			// If the Sender is not the token bridge, ignore it
			if logMessagePublished.Sender != tokenBridgeAddr {
				logger.Debug("skipping LogMessagePublished event because the Sender is incorrect",
					zap.Bool("isSenderTokenBridge", logMessagePublished.Sender == tokenBridgeAddr))
				continue
			}

			// If there is no payload, then there's no point in further processing.
			// This is also somewhat suspicious, so a warning is logged.
			if len(logMessagePublished.Payload) == 0 {
				logger.Warn("a LogMessagePayload event from the token bridge was received with a zero-sized payload",
					zap.String("txhash", log.TxHash.String()))
				continue
			}

			// Check the first byte of the payload ID, which needs to be 0x01 (Transfer) or 0x03 (TransferWithPayload)
			// See `payload_id` field: https://wormhole.com/docs/learn/infrastructure/vaas/
			if logMessagePublished.Payload[0] != 0x01 && logMessagePublished.Payload[0] != 0x03 {
				continue
			}

			// Get the transfer information
			td, _ := parseLogMessagePublishedPayload(logMessagePublished.Payload, tokenBridgeAddr, ethConnector, logger)

			if _, exists := requestedOutOfBridge[td.TokenAddress]; !exists {
				// Initialize the big.Int if it's not yet added.
				requestedOutOfBridge[td.TokenAddress] = new(big.Int).Set(td.Amount)
			} else {
				// Add the amount from the transfer to the requestedOutOfBridge mapping
				requestedOutOfBridge[td.TokenAddress] = new(big.Int).Add(requestedOutOfBridge[td.TokenAddress], td.Amount)
			}

			logger.Debug("successfully parsed a LogMessagePublished event payload",
				zap.String("tokenAddress", td.TokenAddress.String()),
				zap.Uint16("tokenChain", td.TokenChain),
				zap.String("amount", td.Amount.String()))

			// Increment number of processed LogMessagePublished events
			numProcessed++
		}
	}

	// TODO: Using `Warn` for testing purposes. Update to Fatal? when ready to go into PR.
	// TODO: Revisit error handling here. 
	for tokenAddress, amountOut := range requestedOutOfBridge {
		if _, exists := transferredIntoBridge[tokenAddress]; !exists {
			logger.Warn("transfer-out request for tokens that were never deposited",
				zap.String("tokenAddress", tokenAddress.String()))
			// TODO: Is it better to return or continue here?
			return numProcessed, errors.New("transfer-out request for tokens that were never deposited")
			// continue
		}

		amountIn := transferredIntoBridge[tokenAddress]

		logger.Debug("bridge request processed",
			zap.String("tokenAddress", tokenAddress.String()),
			zap.String("amountOut", amountOut.String()),
			zap.String("amountIn", amountIn.String()))

		if amountOut.Cmp(amountIn) > 0 {
			logger.Warn("requested amount out is larger than amount in")
			return numProcessed, errors.New("requested amount out is larger than amount in")
		}

	}

	return numProcessed, nil
}
