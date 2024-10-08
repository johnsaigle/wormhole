package transferverifier

// TODOs
//	tests
//	fix up contexts where it makes sense
//	improve error propogation

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	ipfslog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	connectors "github.com/certusone/wormhole/node/pkg/watchers/evm/connectors"
	"github.com/certusone/wormhole/node/pkg/watchers/evm/connectors/ethabi"
)

// Event Signatures
var (
	// LogMessagePublished(address indexed sender, uint64 sequence, uint32 nonce, bytes payload, uint8 consistencyLevel);
	EVENTHASH_WORMHOLE_LOG_MESSAGE_PUBLISHED = "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2"
	// Transfer(address,address,uint256)
	EVENTHASH_ERC20_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	// Deposit(address,uint256)
	EVENTHASH_WETH_DEPOSIT = "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c"
)

// Fixed addresses
// TODO: more useful to convert this to var and use common.Address instead of converting each time
const (
	ZERO_ADDRESS = "0x0000000000000000000000000000000000000000000000000000000000000000"
)

// https://etherscan.io/token/0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
var WETH_ADDRESS = common.HexToAddress("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")

// The expected total number of indexed topics for an ERC20 Transfer event
const TOPICS_COUNT_TRANSFER = 3
// The expected total number of indexed topics for a WETH Deposit event
const TOPICS_COUNT_DEPOSIT = 2

// The Wormhole Chain ID for the chain being monitored
// TODO: Could probably be parameterized to support other EVM chains
const NATIVE_CHAIN_ID = 2

// Global variables
var (
	// Holds previously-recorded decimals (uint8) for token addresses (common.Address)
	// that have been observed.
	decimalsCache = make(map[common.Address]uint8)

	// Maps the 32-byte token addresses received via LogMessagePublished events to their
	// unwrapped 20-byte addresses. This mapping is also used for non-wrapped token addresses.
	wrappedCache = make(map[string]common.Address)

	/// Function signatures
	// wrappedAsset(uint16 tokenChainId, bytes32 tokenAddress) => 0x1ff1e286
	TOKEN_BRIDGE_WRAPPED_ASSET = []byte("\x1f\xf1\xe2\x86")

	// decimals() => 0x313ce567
	ERC20_DECIMALS_SIGNATURE = []byte("\x31\x3c\xe5\x67")
)

// TODO: Replace with common.Address.Cmp() after updating to a newer version of geth.
// see: https://github.com/ethereum/go-ethereum/blob/84a80216c6481efca1a761fb98827478a0589c09/common/types.go#L241-L243
func cmp(a common.Address, other common.Address) int {
	return bytes.Compare(a[:], other[:])
}

type EVMTransferVerifier interface {
	getDecimals(tokenAddress common.Address) (decimals uint8, err error)
	unwrapIfWrapped(tokenAddress []byte, tokenChain uint16) (unwrappedTokenAddress common.Address, err error)
	// parseLogMessagePublishedPayload(data []byte) (*TransferDetails, error)
}

type TransferVerifier struct {
	// Address of the Wormhole core contract for this chain
	coreBridgeAddr common.Address
	// Address of the Wormhole token bridge contract for this chain
	tokenBridgeAddr common.Address
	// Wrapped version of the native asset, e.g. WETH for Ethereum
	wrappedNativeAddr common.Address
	// Wormhole connector for wrapping contract-specific interactions
	ethConnector connectors.Connector
	logger zap.Logger
}

// Abstraction over an ERC20 Transfer event.
type TransferERC20 struct {
	// The address of the token. Also equivalent to the Emitter of the event.
	TokenAddress common.Address
	// TokenChain   uint16
	From   common.Address
	To     common.Address
	Amount *big.Int
}

// Abstraction over a Deposit event for a wrapped native asset.
type NativeDeposit struct {
	// The address of the token. Also equivalent to the Emitter of the event.
	TokenAddress common.Address
	// TokenChain   uint16
	Destination common.Address
	Amount      *big.Int
}

// Abstraction over a LogMessagePublished event emitted by the core bridge.
type LogMessagePublished struct {
	// Which contract emitted the event.
	Emitter common.Address
	// Which address sent the transaction that triggered the message publication.
	Sender common.Address
	// Abstraction over fields encoded in the event's Data field which in turn contains the transfer's payload.
	TransferDetails *TransferDetails
	// Note: these fields are non-exhaustive. Data not needed for Transfer Verification is not encoded here.
}

// Abstraction over an EVM transaction receipt for Token Bridge transfer.
type TransferReceipt struct {
	Deposits  *[]*NativeDeposit
	Transfers *[]*TransferERC20
	// There must be at least one LogMessagePublished for a valid receipt.
	MessagePublicatons *[]*LogMessagePublished
}

// https://wormhole.com/docs/learn/infrastructure/vaas/#payload-types
type VAAPayloadType uint8

const (
	TransferTokens            VAAPayloadType = 1
	TransferTokensWithPayload VAAPayloadType = 3
)

// Abstraction of a Token Bridge transfer payload encoded in the Data field of a LogMessagePublished event.
type TransferDetails struct {
	PayloadType VAAPayloadType
	// Raw token address parsed from the payload. May be wrapped.
	TokenAddressRaw common.Address
	TokenChain      uint16
	// Original address of the token when minted natively. Corresponds to the "unwrapped" address in the token bridge.
	OriginAddress common.Address
	// Amount as sent in the raw payload
	AmountRaw *big.Int
	// Denormalized amount, accounting for decimal differences between contracts and chains
	Amount *big.Int
}

// CLI args
var (
	evmRpc                 *string
	evmCoreContract        *string
	evmTokenBridgeContract *string
	pruneHeightDelta       *uint64
	pruneFrequency         *time.Duration
)

var TransferVerifierCmdEvm = &cobra.Command{
	Use:   "evm",
	Short: "Transfer Verifier for EVM-based chains",
	Run:   runTransferVerifierEvm,
}

// Settings for how often to prune the processed receipts.
type pruneConfig struct {
	// The block height at which to prune receipts, represented as an offset to subtract from the latest block
	// height, e.g. a pruneHeightDelta of 10 means prune blocks older than latestBlockHeight - 10.
	pruneHeightDelta uint64
	// How often to prune the cache.
	pruneFrequency time.Duration
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

// parseWNativeDepositEvent parses an event for a deposit of a wrapped version of the chain's native asset, i.e. WETH for Ethereum.
func parseWNativeDepositEvent(logTopics []common.Hash, logData []byte) (destination common.Address, amount *big.Int) {

	// https://etherscan.io/token/0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2#code#L29
	// event  Deposit(address indexed dst, uint wad);
	if len(logData) != 32 || len(logTopics) != TOPICS_COUNT_DEPOSIT {
		return common.Address{}, nil
	}

	destination = common.BytesToAddress(logTopics[1][:])
	amount = new(big.Int).SetBytes(logData[:])

	return destination, amount
}

// parseLogMessagePublishedPayload() parses the details of a transfer from a LogMessagePublished event's Payload field.
func (tv TransferVerifier) parseLogMessagePublishedPayload(
	// Corresponds to LogMessagePublished.Payload as returned by the ABI parsing operation in the ethConnector.
	data []byte,
) (*TransferDetails, error) {

	// https://docs.wormhole.com/wormhole/explore-wormhole/vaa
	// This program verifies specific events:
	// - The event is LogMessagePublished
	// - The event was emitted by the core bridge
	// - The sender of the event is the token bridge
	// When all of these are true, the ethConnector is able to parse the receipt's Data field into a Payload byte array.
	// This function performs a second round of parsing, converting the raw bytes of the Payload into a TransferDetails
	// instance that contains information about a Transfer.
	// Depending on the function invoked by the original caller, the payload will be of type TransferTokens or
	// TransferTokensWithPayload. The fields relevant for this program are identical between both payload types.
	// Unnecessary fields (like the inner payload for TransferWithPayload) are ignored.

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
	payloadType := VAAPayloadType(data[0])
	amount := big.NewInt(0).SetBytes(data[1 : 1+32])
	rawTokenAddress := data[33 : 33+32]
	// TODO: can be deleted after debugging is finished
	// tv.logger.Debug("raw token address", zap.String("address", fmt.Sprintf("%x", rawTokenAddress)))
	tokenChain := binary.BigEndian.Uint16(data[65 : 65+2])

	// Unwrap the token address if needed, but short-circuit if the chain ID for the token
	// is the wormhole chain ID of the network being monitored.
	tokenAddress := common.BytesToAddress(rawTokenAddress)
	// tv.logger.Debug("raw token address", zap.String("address", fmt.Sprintf("%x", rawTokenAddress)))
	// var tokenAddress common.Address
	// if tokenChain == NATIVE_CHAIN_ID {
	// 	tokenAddress = common.BytesToAddress(rawTokenAddress)
	// } else {
	// 	unwrappedTokenAddress, err := tv.unwrapIfWrapped(rawTokenAddress, tokenChain, logger)
	// 	if err != nil {
	// 		return &t, errors.Join(errors.New("a fatal error occurred when attempting to unwrap a token address"), err)
	// 	}
	//
	// 	tokenAddress = unwrappedTokenAddress
	// }
	//
	// if cmp(tokenAddress, common.HexToAddress(ZERO_ADDRESS)) == 0 {
	// 	logger.Fatal("token address is zero address")
	// }

	// Denormalize the token amount.
	// decimals, err := tv.getDecimals(tokenAddress, logger)
	// if err != nil {
	// 	logger.Fatal("a fatal error occurred when attempting to get decimals",
	// 		zap.Error(err),
	// 	)
	// 	return &t, err
	// }
	// denormalizedAmount := denormalize(amount, decimals)

	return &TransferDetails{
		PayloadType: payloadType,
		AmountRaw: amount,
		TokenAddressRaw: tokenAddress,
		TokenChain: tokenChain,
		// these fields are populated by RPC calls later
		Amount: nil,
		OriginAddress: common.Address{},
	}, nil 
}

// CLI parameters
func init() {
	// default URL connection for anvil
	evmRpc = TransferVerifierCmdEvm.Flags().String("ethRPC", "ws://localhost:8545", "Ethereum RPC url")
	evmCoreContract = TransferVerifierCmdEvm.Flags().String("ethContract", "", "Ethereum core bridge address for verifying VAAs (required if ethRPC is specified)")
	evmTokenBridgeContract = TransferVerifierCmdEvm.Flags().String("tokenContract", "", "token bridge contract deployed on Ethereum")

	pruneHeightDelta = TransferVerifierCmdEvm.Flags().Uint64("pruneHeightDelta", 10, "The number of blocks for which to retain transaction receipts. Defaults to 10 blocks.")
	pruneFrequency = TransferVerifierCmdEvm.Flags().Duration("pruneFrequency", time.Duration(1*time.Minute), "The frequency at which to prune historic transaction receipts. Defaults to 1 minute.")
}

// makes requests to the token bridge and token contract to get detailed, wormhole-specific information about
// a transfer. Modifies parameter `details` as a side-effect
func (tv *TransferVerifier) addWormholeDetails(details *TransferDetails) (newDetails *TransferDetails, err error) {
	decimals, err := tv.getDecimals(details.TokenAddressRaw)
	if err != nil {
		return newDetails, err
	}
	denormalized := denormalize(details.AmountRaw, decimals)

	var originAddress common.Address
	if details.TokenChain == NATIVE_CHAIN_ID {
		originAddress = common.BytesToAddress(details.TokenAddressRaw.Bytes())
	} else {
		originAddress, err = tv.unwrapIfWrapped(details.TokenAddressRaw.Bytes(), details.TokenChain)
	}
	if err != nil {
		return newDetails, err
	}

	if cmp(originAddress, common.HexToAddress(ZERO_ADDRESS)) == 0 {
		tv.logger.Fatal("token address is zero address")
	}

	newDetails = details
	newDetails.OriginAddress = originAddress
	newDetails.Amount = denormalized
	return newDetails, nil
}

// Note: logger.Error should be reserved only for conditions that break the invariants of the Token Bridge
func runTransferVerifierEvm(cmd *cobra.Command, args []string) {

	pruneConfig := &pruneConfig{
		pruneHeightDelta: *pruneHeightDelta,
		pruneFrequency:   *pruneFrequency,
	}

	// Setup logging
	lvl, err := ipfslog.LevelFromString(*logLevel)
	if err != nil {
		fmt.Println("Invalid log level")
		os.Exit(1)
	}

	logger := ipfslog.Logger("wormhole-transfer-verifier").Desugar()

	ipfslog.SetAllLoggers(lvl)
	logger.Info("Starting EVM transfer verifier")

	// Verify CLI parameters
	if *evmRpc == "" || *evmCoreContract == "" || *evmTokenBridgeContract == "" {
		logger.Fatal(
			"One or more CLI parameters are empty",
			zap.String("rpc", *evmRpc),
			zap.String("coreContract", *evmCoreContract),
			zap.String("tokenContract", *evmTokenBridgeContract),
		)
	}

	logger.Debug("EVM rpc connection", zap.String("url", *evmRpc))
	logger.Debug("EVM core contract", zap.String("address", *evmCoreContract))
	logger.Debug("EVM token bridge contract", zap.String("address", *evmTokenBridgeContract))
	logger.Debug("EVM prune config", zap.Uint64("height delta", pruneConfig.pruneHeightDelta), zap.Duration("frequency", pruneConfig.pruneFrequency))

	// Create the RPC connection, context, and channels
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()

	var ethConnector connectors.Connector
	ethConnector, err = connectors.NewEthereumBaseConnector(ctx, "eth", *evmRpc, common.HexToAddress(*evmCoreContract), logger)
	if err != nil {
		logger.Fatal("could not create new ethereum base connector",
			zap.Error(err))
	}

	transferVerifier := &TransferVerifier{
		coreBridgeAddr:  common.HexToAddress(*evmCoreContract),
		tokenBridgeAddr: common.HexToAddress(*evmTokenBridgeContract),
		// TODO should be a CLI parameter so that we could support other EVM chains
		wrappedNativeAddr: WETH_ADDRESS,
		ethConnector:      ethConnector,
		logger:            *logger,
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

	logger.Debug("evm rpc subscription created", zap.String("address", transferVerifier.coreBridgeAddr.String()))

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

			// record used/inspected tx hash
			if _, exists := processedTransactions[vLog.Raw.TxHash]; exists {
				logger.Debug("skip: transaction hash already processed",
					zap.String("txHash", vLog.Raw.TxHash.String()))
				continue
			}

			// This check also occurs when processing a receipt but skipping here avoids unnecessary
			// processing.
			if cmp(vLog.Sender, transferVerifier.tokenBridgeAddr) != 0 {
				logger.Debug("skip: sender is not token bridge",
					zap.String("txHash", vLog.Raw.TxHash.String()),
					zap.String("sender", vLog.Sender.String()),
					zap.String("tokenBridge", transferVerifier.tokenBridgeAddr.String()))
				continue
			}

			// get transaction receipt
			receipt, err := transferVerifier.ethConnector.TransactionReceipt(ctx, vLog.Raw.TxHash)
			if err != nil {
				logger.Warn("could not find core bridge receipt", zap.Error(err))
				continue
			}
			// record a new lastBlockNumber
			lastBlockNumber = receipt.BlockNumber.Uint64()
			processedTransactions[vLog.Raw.TxHash] = receipt

			// parse raw transaction receipt into high-level struct containing transfer details
			transferReceipt, err := transferVerifier.ParseReceipt(receipt)
			if err != nil || transferReceipt == nil {
				logger.Error("error when parsing receipt", zap.String("receipt hash", receipt.TxHash.String()), zap.Error(err))
				continue
			}

			// post-processing: populate wormhole-specific data for transfer details
			for _, message := range *transferReceipt.MessagePublicatons {
				// message.TransferDetails is modified in-place
				logger.Debug("populating wormhole data")
				newDetails, err := transferVerifier.addWormholeDetails(message.TransferDetails)
				if err != nil {
					logger.Error("error when populating wormhole details", zap.Error(err))
				}
				message.TransferDetails = newDetails
			}

			numProcessed, err := transferVerifier.ProcessReceipt(transferReceipt)
			if err != nil {
				logger.Error("detected invalid receipt", zap.Error(err), zap.String("txHash", vLog.Raw.TxHash.String()))
				continue
			}

			if numProcessed == 0 {
				logger.Warn("receipt logs empty for tx", zap.String("txHash", vLog.Raw.TxHash.Hex()))
				continue
			}

			countLogsProcessed += int(numProcessed)
		}
	}
}

func (tv *TransferVerifier) getDecimals(
	tokenAddress common.Address,
) (decimals uint8, err error) {
	ctx := context.TODO()

	// First check if this token's decimals is stored in cache
	if _, exists := decimalsCache[tokenAddress]; exists {
		tv.logger.Debug("asset decimals found in cache, returning")
		return decimalsCache[tokenAddress], nil
	}

	// If the decimals aren't cached, perform an eth_call lookup for the decimals
	// This RPC call should only be made once per token, until the guardian is restarted
	ethCallMsg := ethereum.CallMsg{
		To:   &tokenAddress,
		Data: ERC20_DECIMALS_SIGNATURE,
	}

	result, err := tv.ethConnector.Client().CallContract(ctx, ethCallMsg, nil)
	if err != nil || len(result) < 32 {
		tv.logger.Fatal("failed to get decimals for token",
			zap.String("tokenAddress", tokenAddress.String()),
			zap.Error(err))
		return 0, err
	}

	// TODO: find out if there is some official documentation for why this uint8 is in the last index of the 32byte return.
	// An ERC20 token's decimals should fit in a single byte. A call to `decimals()`
	// returns a uint8 value encoded in string with 32-bytes. To get the decimals,
	// we grab the last byte, expecting all the preceding bytes to be equal to 0.
	decimals = result[31]

	// Add the decimal value to the cache
	tv.logger.Debug("adding new token's decimals to cache",
		zap.String("tokenAddress", tokenAddress.String()),
		zap.Uint8("tokenDecimals", decimals))

	decimalsCache[tokenAddress] = decimals

	return decimals, nil
}

// unwrapIfWrapped() returns the "unwrapped" address for a token a.k.a. the OriginAddress
// of the token's original minting contract.
func (tv TransferVerifier) unwrapIfWrapped(
	tokenAddress []byte,
	tokenChain uint16,
) (unwrappedTokenAddress common.Address, err error) {
	ctx := context.TODO()

	tokenAddressAsKey := hex.EncodeToString(tokenAddress)

	// If the token address already exists in the wrappedCache mapping the
	// cached value can be returned.
	if addr, exists := wrappedCache[tokenAddressAsKey]; exists {
		tv.logger.Debug("wrapped asset found in cache, returning")
		return addr, nil
	}

	// prepare eth_call data, 4-byte signature + 2x 32 byte arguments
	calldata := make([]byte, 4+32+32)

	copy(calldata, TOKEN_BRIDGE_WRAPPED_ASSET)
	// Add the uint16 tokenChain as the last two bytes in the first argument
	binary.BigEndian.PutUint16(calldata[4+30:], tokenChain)
	copy(calldata[4+32:], tokenAddress)

	ethCallMsg := ethereum.CallMsg{
		To:   &tv.tokenBridgeAddr,
		Data: calldata,
	}
	tv.logger.Debug("calling wrappedAsset", zap.Uint16("tokenChain", tokenChain), zap.String("tokenAddress", fmt.Sprintf("%x", tokenAddress)))

	result, err := tv.ethConnector.Client().CallContract(ctx, ethCallMsg, nil)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to get mapping for token %s", tokenAddressAsKey)
	}

	tokenAddressNative := common.BytesToAddress(result)
	wrappedCache[tokenAddressAsKey] = tokenAddressNative
	if cmp(tokenAddressNative, common.HexToAddress(ZERO_ADDRESS)) == 0 {
		return common.Address{}, errors.New("unwrapped address returned the zero address")
	}

	return tokenAddressNative, nil
}

// ParseReceipt converts a go-ethereum receipt struct into a TransferReceipt. It makes use of the ethConnector to
// parse information from the logs within the receipt. This function is mainly helpful to isolate the
// parsing code from the verification logic, which makes the latter easier to test without needing an active
// RPC connection.
// This function parses only events with topics needed for Transfer Verification. Any other events will be discarded.
// This function is not responsible for checking that the values for the various fields are relevant, only that they are well-formed.
func (tv *TransferVerifier) ParseReceipt(
	receipt *types.Receipt,
) (*TransferReceipt, error) {
	// Sanity check. Shouldn't be necessary but no harm
	if receipt.Status != 1 {
		tv.logger.Fatal("non-success transaction status", zap.Uint64("status", receipt.Status))
	}
	var deposits []*NativeDeposit
	var transfers []*TransferERC20
	var messagePublications []*LogMessagePublished
	for _, log := range receipt.Logs {
		switch log.Topics[0] {
		case common.HexToHash(EVENTHASH_ERC20_TRANSFER):
			from, to, amount := parseERC20TransferEvent(log.Topics, log.Data)
			transfers = append(transfers, &TransferERC20{
				// TokenChain: log.Address,
				TokenAddress: log.Address,
				From:         from,
				To:           to,
				Amount:       amount,
			})
		case common.HexToHash(EVENTHASH_WETH_DEPOSIT):
			destination, amount := parseWNativeDepositEvent(log.Topics, log.Data)
			deposits = append(deposits, &NativeDeposit{
				TokenAddress: log.Address,
				Destination:  destination,
				Amount:       amount,
			})
		case common.HexToHash(EVENTHASH_WORMHOLE_LOG_MESSAGE_PUBLISHED):
			logMessagePublished, err := tv.ethConnector.ParseLogMessagePublished(*log)
			if err != nil {
				tv.logger.Fatal("failed to parse LogMessagePublished event")
			}

			// If there is no payload, then there's no point in further processing.
			// This is also somewhat suspicious, so a warning is logged.
			// TODO: Revisit whether this should be an error. This shouldn't ever happen.
			if len(logMessagePublished.Payload) == 0 {
				tv.logger.Warn("a LogMessagePayload event from the token bridge was received with a zero-sized payload",
					zap.String("txhash", log.TxHash.String()))
				continue
			}

			// Payload parsing will fail if performed on a message emitted from another contract or sent
			// by a contract other than the token bridge
			if log.Address != tv.coreBridgeAddr {
				tv.logger.Debug("skipping LogMessagePublished not emitted from the core bridge",
					zap.String("emitter", log.Address.String()))
				continue
			}

			if log.Topics[1] != tv.tokenBridgeAddr.Hash() {
				tv.logger.Debug("skipping LogMessagePublished with sender not equal to the token bridge",
					zap.String("sender", log.Topics[1].String()),
					zap.String("tokenBridgeAddr", tv.tokenBridgeAddr.Hex()),
				)
				continue
			}

			transferDetails, err := tv.parseLogMessagePublishedPayload(logMessagePublished.Payload)
			if err != nil {
				return nil, err
			}
			messagePublications = append(messagePublications, &LogMessagePublished{
				Emitter:         log.Address,
				Sender:          logMessagePublished.Sender,
				TransferDetails: transferDetails,
			})

		}
	}

	return &TransferReceipt{Deposits: &deposits, Transfers: &transfers, MessagePublicatons: &messagePublications}, nil
}

// ProcessReceipt verifies that a receipt for a LogMessagedPublished event does not verify a fundamental
// invariant of Wormhole token transfers: when the core bridge reports a transfer has occurred, there must be a
// corresponding transfer in the token bridge. This is determined by iterating through the logs of the receipt and
// ensuring that the sum transferred into the token bridge does not exceed the sum emitted by the core bridge.
func (tv *TransferVerifier) ProcessReceipt(
	transferReceipt *TransferReceipt,
) (numProcessed int, err error) {
	if transferReceipt == nil {
		tv.logger.Warn("transfer receipt is nil. Skipping transfer verification")
		return 0, errors.New("got nil transfer receipt")
	}
	if len(*transferReceipt.MessagePublicatons) == 0 {
		tv.logger.Warn("transfer receipt contained no LogMessagePublished events")
		return 0, errors.New("no message publications in receipt")
	}

	// The sum of tokens transferred into the Token Bridge contract.
	transferredIntoBridge := make(map[common.Address]*big.Int)
	// The sum of tokens parsed from the core bridge's LogMessagePublished payload.
	requestedOutOfBridge := make(map[common.Address]*big.Int)

	for _, deposit := range *transferReceipt.Deposits {
		// Filter for deposits into the token bridge
		if deposit.Amount == nil {
			tv.logger.Debug("skipping deposit event with nil amount")
			continue
		}
		if deposit.Destination != tv.tokenBridgeAddr {
			tv.logger.Debug("skipping deposit event with destination not equal to the token bridge",
				zap.String("destination", deposit.Destination.String()))
			continue
		}

		if deposit.TokenAddress != tv.wrappedNativeAddr {
			tv.logger.Debug("skipping deposit event not from the wrapped native asset contract",
				zap.String("tokenAddress", deposit.TokenAddress.String()),
				zap.String("amount", deposit.Amount.String()))
			continue
		}

		if _, exists := transferredIntoBridge[deposit.TokenAddress]; !exists {
			transferredIntoBridge[deposit.TokenAddress] = new(big.Int).Set(deposit.Amount)
		} else {
			transferredIntoBridge[deposit.TokenAddress] = new(big.Int).Add(transferredIntoBridge[deposit.TokenAddress], deposit.Amount)
		}
		tv.logger.Debug("a deposit into the token bridge was recorded",
			zap.String("tokenAddress", deposit.TokenAddress.String()),
			zap.String("amount", deposit.Amount.String()))
	}

	for _, transfer := range *transferReceipt.Transfers {
		// Filter for transfers into the token bridge
		if transfer.To != tv.tokenBridgeAddr {
			continue
		}
		if _, exists := transferredIntoBridge[transfer.TokenAddress]; !exists {
			transferredIntoBridge[transfer.TokenAddress] = new(big.Int).Set(transfer.Amount)
		} else {
			transferredIntoBridge[transfer.TokenAddress] = new(big.Int).Add(transferredIntoBridge[transfer.TokenAddress], transfer.Amount)
		}
	}

	for _, message := range *transferReceipt.MessagePublicatons {
		td := message.TransferDetails
		// This should have already been skipped earlier in the script, but check for it here anyway.
		if message.Emitter != tv.coreBridgeAddr {
			tv.logger.Debug("skipping LogMessagePublished event because the emitter is not the core bridge",
				zap.String("emitter", message.Emitter.String()))
			continue
		}
		// This should have already been skipped earlier in the script, but check for it here anyway.
		if message.Sender != tv.tokenBridgeAddr {
			tv.logger.Debug("skipping LogMessagePublished event because the Sender is not token bridge",
				zap.String("sender", message.Sender.String()))
			continue
		}
		if td.PayloadType != TransferTokens && td.PayloadType != TransferTokensWithPayload {
			tv.logger.Debug("skipping LogMessagePublished event because of Payload type",
				zap.Int("payloadType", int(td.PayloadType)))
			continue
		}

		if td.Amount == nil {
			tv.logger.Error("Amount is nil (has not been normalized)",
				zap.String("amountRaw", td.AmountRaw.String()))
			continue
		}
		if cmp(td.OriginAddress, common.HexToAddress(ZERO_ADDRESS)) == 0 {
			tv.logger.Error("OriginAddress have not been populated (has not been unwrapped)",
				zap.String("tokenAddressRaw", td.TokenAddressRaw.String()),
			)
			continue
		}

		// Sum up amount requested out of bridge
		if _, exists := requestedOutOfBridge[td.OriginAddress]; !exists {
			// Initialize the big.Int if it's not yet added.
			requestedOutOfBridge[td.OriginAddress] = new(big.Int).Set(td.Amount)
		} else {
			// Add the amount from the transfer to the requestedOutOfBridge mapping
			requestedOutOfBridge[td.OriginAddress] = new(big.Int).Add(requestedOutOfBridge[td.OriginAddress], td.Amount)
		}
		tv.logger.Debug("successfully parsed a LogMessagePublished event payload",
			zap.String("tokenAddress", td.OriginAddress.String()),
			zap.Uint16("tokenChain", td.TokenChain),
			zap.String("amount", td.Amount.String()))
		numProcessed++
	}

	// TODO: Using `Warn` for testing purposes. Update to Fatal? when ready to go into PR.
	// TODO: Revisit error handling here.
	for tokenAddress, amountOut := range requestedOutOfBridge {
		if _, exists := transferredIntoBridge[tokenAddress]; !exists {
			tv.logger.Warn("transfer-out request for tokens that were never deposited",
				zap.String("tokenAddress", tokenAddress.String()))
			// TODO: Is it better to return or continue here?
			return numProcessed, errors.New("transfer-out request for tokens that were never deposited")
			// continue
		}

		amountIn := transferredIntoBridge[tokenAddress]

		tv.logger.Debug("bridge request processed",
			zap.String("tokenAddress", tokenAddress.String()),
			zap.String("amountOut", amountOut.String()),
			zap.String("amountIn", amountIn.String()))

		if amountOut.Cmp(amountIn) > 0 {
			tv.logger.Warn("requested amount out is larger than amount in")
			return numProcessed, errors.New("requested amount out is larger than amount in")
		}

	}

	return numProcessed, nil
}
