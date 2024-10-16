package transferverifier

// TODOs
//	tests
//	fix up contexts where it makes sense
//	improve error propogation

import (
	// "bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethClient "github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/event"
	"github.com/wormhole-foundation/wormhole/sdk/vaa"

	ipfslog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	// transferverifier "github.com/certusone/wormhole/node/cmd/transfer-verifier"
	connectors "github.com/certusone/wormhole/node/pkg/watchers/evm/connectors"
	"github.com/certusone/wormhole/node/pkg/watchers/evm/connectors/ethabi"
)

// Global variables
var (
	// Holds previously-recorded decimals (uint8) for token addresses (common.Address)
	// that have been observed.
	// TODO: Add common coins (USDC, USDT, etc.) in compilation. No need to fetch these.
	decimalsCache = make(map[common.Address]uint8)

	// Maps the 32-byte token addresses received via LogMessagePublished events to their
	// unwrapped 20-byte addresses. This mapping is also used for non-wrapped token addresses.
	// TODO: Add common coins (USDC, USDT, etc.) in compilation. No need to fetch these.
	wrappedCache = make(map[string]common.Address)
)

var TransferVerifierCmdEvm = &cobra.Command{
	Use:   "evm",
	Short: "Transfer Verifier for EVM-based chains",
	Run:   runTransferVerifierEvm,
}

// CLI args
var (
	evmRpc                 *string
	evmCoreContract        *string
	evmTokenBridgeContract *string
	pruneHeightDelta       *uint64
	pruneFrequency         *time.Duration
)

const (
	// Maximum number of attempts to establish a subscription to the LogMessagePublished event emitted by the core contract..
	MAX_RETRIES = 5
)

// Settings for how often to prune the processed receipts.
type pruneConfig struct {
	// The block height at which to prune receipts, represented as an offset to subtract from the latest block
	// height, e.g. a pruneHeightDelta of 10 means prune blocks older than latestBlockHeight - 10.
	pruneHeightDelta uint64
	// How often to prune the cache.
	pruneFrequency time.Duration
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

	transferVerifier := &TransferVerifier[*ethClient.Client, connectors.Connector]{
		Addresses: TVAddresses{
			CoreBridgeAddr:  common.HexToAddress(*evmCoreContract),
			TokenBridgeAddr: common.HexToAddress(*evmTokenBridgeContract),
			// TODO should be a CLI parameter so that we could support other EVM chains
			WrappedNativeAddr: WETH_ADDRESS,
		},
		ethConnector: ethConnector,
		logger:       *logger,
		client:       ethConnector.Client(),
	}

	logC := make(chan *ethabi.AbiLogMessagePublished)
	errC := make(chan error)

	sub, err := tryConnect(ethConnector, logC, errC, transferVerifier.logger)

	if err != nil {
		logger.Fatal("Error on WatchLogMessagePublished",
			zap.Error(err))
	}
	if sub == nil {
		logger.Fatal("WatchLogMessagePublished returned nil")
	}

	logger.Debug("evm rpc subscription created", zap.String("address", transferVerifier.Addresses.CoreBridgeAddr.String()))

	// Counter for amount of logs processed
	countLogsProcessed := int(0)

	// Mapping to track the transactions that have been processed
	processedTransactions := make(map[common.Hash]*types.Receipt)

	// The latest transaction block number, used to determine the size of historic receipts to keep in memory
	lastBlockNumber := uint64(0)

	// Ticker to clear historic transactions that have been processed
	ticker := time.NewTicker(pruneConfig.pruneFrequency)
	defer ticker.Stop() // delete for Go >= 1.23. See time.NewTicker() documentation.

	// Main loop:
	// - watch for LogMessagePublished events coming from the connector attached to the core bridge.
	// - parse receipts for these events
	// - process parsed receipts to make sure they are valid
	for {
		select {
		case err := <-sub.Err():
			logger.Fatal("got error on ethConnector's error channel", zap.Error(err))
			// TODO: do we need to overwrite sub? any risk?
			_, connectErr := tryConnect(ethConnector, logC, errC, transferVerifier.logger)
			if connectErr != nil {
				logger.Fatal("Could not reconnect. Terminating", zap.Error(err))
			}
		// Do cleanup and statistics reporting
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

		// Process observed LogMessagePublished events
		case vLog := <-logC:

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
			if cmp(vLog.Sender, transferVerifier.Addresses.TokenBridgeAddr) != 0 {
				logger.Debug("skip: sender is not token bridge",
					zap.String("txHash", vLog.Raw.TxHash.String()),
					zap.String("sender", vLog.Sender.String()),
					zap.String("tokenBridge", transferVerifier.Addresses.TokenBridgeAddr.String()))
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
				logger.Error("error when parsing receipt",
					zap.String("receipt hash", receipt.TxHash.String()),
					zap.Error(err))
				continue
			}

			// post-processing: populate wormhole-specific data for transfer details
			for _, message := range *transferReceipt.MessagePublicatons {
				logger.Debug("populating wormhole data")
				newDetails, err := transferVerifier.addWormholeDetails(message.TransferDetails)
				if err != nil {
					// The unwrapped address and the denormalized amount are necessary for checking
					// that the amount matches.
					logger.Error("error when populating wormhole details. cannot verify receipt!",
						zap.String("receipt", receipt.TxHash.String()),
						zap.Error(err))
					continue
				}
				message.TransferDetails = newDetails
			}

			// Ensure that the amount coming in is at least as much as the amount requested out.
			numProcessed, err := transferVerifier.ProcessReceipt(transferReceipt)
			if err != nil {
				logger.Error("detected invalid receipt", zap.Error(err), zap.String("txHash", vLog.Raw.TxHash.String()))
				continue
			}

			// Update statistics
			if numProcessed == 0 {
				logger.Warn("receipt logs empty for tx", zap.String("txHash", vLog.Raw.TxHash.Hex()))
				continue
			}

			countLogsProcessed += int(numProcessed)
		}
	}
}

func tryConnect[C connectors.Connector](
	connector C,
	logC chan *ethabi.AbiLogMessagePublished,
	errC chan error,
	logger zap.Logger,
) (sub event.Subscription, err error) {
	attempts := 0
	for attempts < MAX_RETRIES {
		attempts++
		logger.Debug("Attempting connection", 
			zap.Int("connection attempt", attempts), 
			zap.Int("max retries", MAX_RETRIES))

		sub, err = connector.WatchLogMessagePublished(
			context.Background(), 
			errC, 
			logC,
			)
		if err != nil {
			logger.Warn("Could not establish connection", 
				zap.Error(err))
			continue
		}
		if sub == nil {
			logger.Warn("Could not establish connection: nil event subscription")
			continue
		}
		/// Successful connection
		return
	}
	return 
}

// ParseReceipt() converts a go-ethereum receipt struct into a TransferReceipt. It makes use of the ethConnector to
// parse information from the logs within the receipt. This function is mainly helpful to isolate the
// parsing code from the verification logic, which makes the latter easier to test without needing an active
// RPC connection.
// This function parses only events with topics needed for Transfer Verification. Any other events will be discarded.
// This function is not responsible for checking that the values for the various fields are relevant, only that they are well-formed.
func (tv *TransferVerifier[evmClient, connector]) ParseReceipt(
	receipt *types.Receipt,
) (*TransferReceipt, error) {
	// Sanity check. Shouldn't be necessary but no harm
	if receipt.Status != 1 {
		return &TransferReceipt{}, errors.New("non-success transaction status")
	}
	if len(receipt.Logs) == 0 {
		return &TransferReceipt{}, errors.New("no logs in receipt")
	}

	var deposits []*NativeDeposit
	var transfers []*ERC20Transfer
	var messagePublications []*LogMessagePublished
	for _, log := range receipt.Logs {
		switch log.Topics[0] {
		case common.HexToHash(EVENTHASH_ERC20_TRANSFER):
			from, to, amount := parseERC20TransferEvent(log.Topics, log.Data)
			transfers = append(transfers, &ERC20Transfer{
				TokenAddress: log.Address,
				TokenChain:   NATIVE_CHAIN_ID, // TODO is this right?
				From:         from,
				To:           to,
				Amount:       amount,
			})
		case common.HexToHash(EVENTHASH_WETH_DEPOSIT):
			destination, amount := parseWNativeDepositEvent(log.Topics, log.Data)
			deposits = append(deposits, &NativeDeposit{
				TokenAddress: log.Address,
				TokenChain:   NATIVE_CHAIN_ID, // always equal to Ethereum for native deposits
				Receiver:     destination,
				Amount:       amount,
			})
		case common.HexToHash(EVENTHASH_WORMHOLE_LOG_MESSAGE_PUBLISHED):
			logMessagePublished, err := tv.ethConnector.ParseLogMessagePublished(*log)
			if err != nil {
				tv.logger.Fatal("failed to parse LogMessagePublished event")
			}

			// If there is no payload, then there's no point in further processing.
			// This should never happen.
			if len(logMessagePublished.Payload) == 0 {
				tv.logger.Error("a LogMessagePayload event from the token bridge was received with a zero-sized payload",
					zap.String("txhash", log.TxHash.String()))
				continue
			}

			// Payload parsing will fail if performed on a message emitted from another contract or sent
			// by a contract other than the token bridge
			if log.Address != tv.Addresses.CoreBridgeAddr {
				tv.logger.Debug("skipping LogMessagePublished not emitted from the core bridge",
					zap.String("emitter", log.Address.String()))
				continue
			}

			if log.Topics[1] != tv.Addresses.TokenBridgeAddr.Hash() {
				tv.logger.Debug("skipping LogMessagePublished with sender not equal to the token bridge",
					zap.String("sender", log.Topics[1].String()),
					zap.String("tokenBridgeAddr", tv.Addresses.TokenBridgeAddr.Hex()),
				)
				continue
			}

			transferDetails, err := parseLogMessagePublishedPayload(logMessagePublished.Payload)
			if err != nil {
				return nil, err
			}
			messagePublications = append(messagePublications, &LogMessagePublished{
				EventEmitter:    log.Address,
				MsgSender:       logMessagePublished.Sender,
				TransferDetails: transferDetails,
			})

		}
	}

	return &TransferReceipt{Deposits: &deposits, Transfers: &transfers, MessagePublicatons: &messagePublications}, nil
}

// ProcessReceipt() verifies that a receipt for a LogMessagedPublished event does not verify a fundamental
// invariant of Wormhole token transfers: when the core bridge reports a transfer has occurred, there must be a
// corresponding transfer in the token bridge. This is determined by iterating through the logs of the receipt and
// ensuring that the sum transferred into the token bridge does not exceed the sum emitted by the core bridge.
func (tv *TransferVerifier[evmClient, connector]) ProcessReceipt(
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
	transferredIntoBridge := make(map[string]*big.Int)
	// The sum of tokens parsed from the core bridge's LogMessagePublished payload.
	requestedOutOfBridge := make(map[string]*big.Int)

	for _, deposit := range *transferReceipt.Deposits {

		err := validate[*NativeDeposit](deposit)
		if err != nil {
			return numProcessed, err
		}

		key, relevant := relevant[*NativeDeposit](deposit, &tv.Addresses)
		if !relevant {
			tv.logger.Debug("skipping irrelevant deposit",
				zap.String("emitter", deposit.Emitter().String()),
			)
			continue
		}
		if key == "" {
			return numProcessed, errors.New("Couldn't get key")
		}

		upsert(&transferredIntoBridge, key, deposit.TransferAmount())
		// if deposit.Receiver != tv.tokenBridgeAddr {
		// 	tv.logger.Debug("skipping deposit event with destination not equal to the token bridge",
		// 		zap.String("destination", deposit.Receiver.String()))
		// 	continue
		// }

		// if deposit.TokenAddress != tv.wrappedNativeAddr {
		// 	tv.logger.Debug("skipping deposit event not from the wrapped native asset contract",
		// 		zap.String("tokenAddress", deposit.TokenAddress.String()),
		// 		zap.String("amount", deposit.Amount.String()))
		// 	continue
		// }

		tv.logger.Debug("a deposit into the token bridge was recorded",
			zap.String("tokenAddress", deposit.TokenAddress.String()),
			zap.String("amount", deposit.Amount.String()))
	}

	for _, transfer := range *transferReceipt.Transfers {
		// Filter for transfers into the token bridge
		// if transfer.To != tv.tokenBridgeAddr {
		// 	continue
		// }
		// if transfer.Amount == nil {
		// 	tv.logger.Debug("skipping transfer event with nil amount")
		// 	continue
		// }
		err := validate[*ERC20Transfer](transfer)
		if err != nil {
			return numProcessed, err
		}
		key, relevant := relevant[*ERC20Transfer](transfer, &tv.Addresses)
		if !relevant {
			tv.logger.Debug("skipping irrelevant transfer")
			continue
		}
		if key == "" {
			return numProcessed, errors.New("Couldn't get key")
		}
		// key := fmt.Sprintf(KEY_FORMAT, transfer.TokenAddress, transfer.TokenChain)
		// if _, exists := transferredIntoBridge[key]; !exists {
		// 	transferredIntoBridge[key] = new(big.Int).Set(transfer.Amount)
		// } else {
		// 	transferredIntoBridge[key] = new(big.Int).Add(transferredIntoBridge[key], transfer.Amount)
		// }
		upsert(&transferredIntoBridge, key, transfer.TransferAmount())
	}

	for _, message := range *transferReceipt.MessagePublicatons {
		td := message.TransferDetails

		err := validate[*LogMessagePublished](message)
		if err != nil {
			return numProcessed, err
		}
		key, relevant := relevant[*LogMessagePublished](message, &tv.Addresses)
		if !relevant {
			tv.logger.Debug("skipping irrelevant message publication")
			continue
		}
		upsert(&requestedOutOfBridge, key, message.TransferAmount())

		// // This should have already been skipped earlier in the script, but check for it here anyway.
		// if message.EventEmitter != tv.coreBridgeAddr {
		// 	tv.logger.Debug("skipping LogMessagePublished event because the emitter is not the core bridge",
		// 		zap.String("emitter", message.EventEmitter.String()))
		// 	continue
		// }
		// // This should have already been skipped earlier in the script, but check for it here anyway.
		// if message.MsgSender != tv.tokenBridgeAddr {
		// 	tv.logger.Debug("skipping LogMessagePublished event because the Sender is not token bridge",
		// 		zap.String("sender", message.MsgSender.String()))
		// 	continue
		// }
		// if td.PayloadType != TransferTokens && td.PayloadType != TransferTokensWithPayload {
		// 	tv.logger.Debug("skipping LogMessagePublished event because of Payload type",
		// 		zap.Int("payloadType", int(td.PayloadType)))
		// 	continue
		// }
		//
		// if td.Amount == nil {
		// 	tv.logger.Error("Amount is nil (has not been normalized)",
		// 		zap.String("amountRaw", td.AmountRaw.String()))
		// 	continue
		// }
		// if cmp(td.OriginAddress, ZERO_ADDRESS) == 0 {
		// 	tv.logger.Error("OriginAddress have not been populated (has not been unwrapped)",
		// 		zap.String("tokenAddressRaw", td.OriginAddressRaw.String()),
		// 	)
		// 	continue
		// }

		// Sum up amount requested out of bridge
		// key := fmt.Sprintf(KEY_FORMAT, td.OriginAddress, td.TokenChain)
		// if _, exists := requestedOutOfBridge[key]; !exists {
		// 	// Initialize the big.Int if it's not yet added.
		// 	requestedOutOfBridge[key] = new(big.Int).Set(td.Amount)
		// } else {
		// 	// Add the amount from the transfer to the requestedOutOfBridge mapping
		// 	requestedOutOfBridge[key] = new(big.Int).Add(requestedOutOfBridge[key], td.Amount)
		// }
		tv.logger.Debug("successfully parsed a LogMessagePublished event payload",
			zap.String("tokenAddress", td.OriginAddress.String()),
			zap.String("tokenChain", td.TokenChain.String()),
			zap.String("amount", td.Amount.String()))
		numProcessed++
	}

	// TODO: Revisit error handling here. Are errors enough or should we do Fatal?
	for key, amountOut := range requestedOutOfBridge {
		if _, exists := transferredIntoBridge[key]; !exists {
			tv.logger.Error("transfer-out request for tokens that were never deposited",
				zap.String("key", key))
			// TODO: Is it better to return or continue here?
			return numProcessed, errors.New("invariant violated: transfer-out request for tokens that were never deposited")
		}

		amountIn := transferredIntoBridge[key]

		tv.logger.Debug("bridge request processed",
			zap.String("key", key),
			zap.String("amountOut", amountOut.String()),
			zap.String("amountIn", amountIn.String()))

		if amountOut.Cmp(amountIn) > 0 {
			tv.logger.Warn("requested amount out is larger than amount in")
			return numProcessed, errors.New("invariant violated: requested amount out is larger than amount in")
		}
	}

	return numProcessed, nil
}

func parseERC20TransferEvent(logTopics []common.Hash, logData []byte) (from common.Address, to common.Address, amount *big.Int) {

	// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/6e224307b44bc4bd0cb60d408844e028cfa3e485/contracts/token/ERC20/IERC20.sol#L16
	// event Transfer(address indexed from, address indexed to, uint256 value)
	if len(logData) != EVM_WORD_LENGTH || len(logTopics) != TOPICS_COUNT_TRANSFER {
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
	if len(logData) != EVM_WORD_LENGTH || len(logTopics) != TOPICS_COUNT_DEPOSIT {
		return common.Address{}, nil
	}

	destination = common.BytesToAddress(logTopics[1][:])
	amount = new(big.Int).SetBytes(logData[:])

	return destination, amount
}

// parseLogMessagePublishedPayload() parses the details of a transfer from a LogMessagePublished event's Payload field.
func parseLogMessagePublishedPayload(
	// Corresponds to LogMessagePublished.Payload as returned by the ABI parsing operation in the ethConnector.
	data []byte,
) (*TransferDetails, error) {

	// Note: vaa.DecodeTransferPayloadHdr performs validation on data, e.g. length checks.
	hdr, err := vaa.DecodeTransferPayloadHdr(data)
	if err != nil {
		return nil, err
	}
	return &TransferDetails{
		PayloadType:     VAAPayloadType(hdr.Type),
		AmountRaw:       hdr.Amount,
		OriginAddressRaw: common.BytesToAddress(hdr.OriginAddress.Bytes()),
		TokenChain:      vaa.ChainID(hdr.OriginChain),
		TargetAddress:   hdr.TargetAddress,
		// these fields are populated by RPC calls later
		Amount:        nil,
		OriginAddress: common.Address{},
	}, nil

}

// addWormholeDetails() makes requests to the token bridge and token contract to get detailed, wormhole-specific information about
// a transfer. Modifies parameter `details` as a side-effect
func (tv *TransferVerifier[ethClient, connector]) addWormholeDetails(details *TransferDetails) (newDetails *TransferDetails, err error) {

	decimals, err := tv.getDecimals(details.OriginAddressRaw)
	if err != nil {
		return
	}
	denormalized := denormalize(details.AmountRaw, decimals)

	var originAddress common.Address
	if details.TokenChain == NATIVE_CHAIN_ID {
		originAddress = common.BytesToAddress(details.OriginAddressRaw.Bytes())
	} else {
		originAddress, err = tv.unwrapIfWrapped(details.OriginAddressRaw.Bytes(), details.TokenChain)
	}
	if err != nil {
		return
	}

	if cmp(originAddress, ZERO_ADDRESS) == 0 {
		tv.logger.Fatal("token address is zero address")
	}

	// TODO: It's probably better to modify the argument in-place rather than return new values
	newDetails = details
	newDetails.OriginAddress = originAddress
	newDetails.Amount = denormalized
	return newDetails, nil
}

// Insert a value into a map or update it if it already exists.
func upsert(
	dict *map[string]*big.Int,
	key string,
	amount *big.Int,
) {
	d := *dict
	if _, exists := d[key]; !exists {
		d[key] = new(big.Int).Set(amount)
	} else {
		d[key] = new(big.Int).Add(d[key], amount)
	}
}
