package transferverifier

// TODOs
//	add comments at the top of this file
//	fix up contexts where it makes sense
//	fix issue where cross-chain transfers show an invariant violation because of they cannot be found in the wrapped asset map

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/wormhole-foundation/wormhole/sdk/vaa"

	ipfslog "github.com/ipfs/go-log/v2"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	connectors "github.com/certusone/wormhole/node/pkg/watchers/evm/connectors"
)

// Global variables for caching RPC responses.
var (
	// Holds previously-recorded decimals (uint8) for token addresses
	// (common.Address) that have been observed.
	decimalsCache = make(map[common.Address]uint8)

	// Records whether an asset is wrapped but does not store the native data
	isWrappedCache = make(map[string]bool)

	// Maps the 32-byte token addresses received via LogMessagePublished
	// events to their unwrapped 20-byte addresses. This mapping is also
	// used for non-wrapped token addresses.
	wrappedCache = make(map[string]common.Address)

	// Native chain cache for wrapped assets.
	nativeChainCache = make(map[string]vaa.ChainID)
)

var TransferVerifierCmdEvm = &cobra.Command{
	Use:   "evm",
	Short: "Transfer Verifier for EVM-based chains",
	Run:   runTransferVerifierEvm,
}

// Configuration variables for EVM interactions.
var (
	// RPC endpoint URL for interacting with an EVM node.
	evmRpc *string
	// Contract address of the EVM core bridge contract.
	evmCoreContract *string
	// Contract address of the token bridge contract.
	evmTokenBridgeContract *string
	// Height difference between pruning windows (in blocks).
	pruneHeightDelta *uint64
	// Time interval between pruning windows (in seconds).
	pruneFrequency *time.Duration
)

const (
	// Seconds to wait before trying to reconnect to the core contract event subscription.
	RECONNECT_DELAY = 5 * time.Second
)

// Settings for how often to prune the processed receipts.
type pruneConfig struct {
	// The block height at which to prune receipts, represented as an
	// offset to subtract from the latest block height, e.g. a
	// pruneHeightDelta of 10 means prune blocks older than
	// latestBlockHeight - 10.
	pruneHeightDelta uint64
	// How often to prune the cache.
	pruneFrequency time.Duration
}

// Function to initialize the configuration for the TransferVerifierCmdEvm flags.
func init() {
	// default URL connection for anvil
	evmRpc = TransferVerifierCmdEvm.Flags().String("ethRPC", "ws://localhost:8545", "Ethereum RPC url")
	evmCoreContract = TransferVerifierCmdEvm.Flags().String("ethContract", "", "Ethereum core bridge address for verifying VAAs (required if ethRPC is specified)")
	evmTokenBridgeContract = TransferVerifierCmdEvm.Flags().String("tokenContract", "", "token bridge contract deployed on Ethereum")

	pruneHeightDelta = TransferVerifierCmdEvm.Flags().Uint64("pruneHeightDelta", 10, "The number of blocks for which to retain transaction receipts. Defaults to 10 blocks.")
	pruneFrequency =
		TransferVerifierCmdEvm.Flags().Duration(
			"pruneFrequency",
			time.Duration(1*time.Minute),
			"The frequency at which to prune historic transaction receipts. Defaults to 1 minute.")
}

// Note: logger.Error should be reserved only for conditions that break the
// invariants of the Token Bridge
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
	logger.Debug("EVM prune config",
		zap.Uint64("height delta", pruneConfig.pruneHeightDelta),
		zap.Duration("frequency", pruneConfig.pruneFrequency))

	// Create the RPC connection, context, and channels
	ctx, ctxCancel := context.WithCancel(context.Background())
	defer ctxCancel()

	var ethConnector connectors.Connector
	ethConnector, err = connectors.NewEthereumBaseConnector(ctx, "eth", *evmRpc, common.HexToAddress(*evmCoreContract), logger)
	if err != nil {
		logger.Fatal("could not create new ethereum base connector",
			zap.Error(err))
	}

	// Create main configuration for Transfer Verification
	transferVerifier := NewTransferVerifier(
		ethConnector,
		&TVAddresses{
			CoreBridgeAddr:  common.HexToAddress(*evmCoreContract),
			TokenBridgeAddr: common.HexToAddress(*evmTokenBridgeContract),
			// TODO should be a CLI parameter so that we could support other EVM chains
			WrappedNativeAddr: WETH_ADDRESS,
		},
		logger,
	)

	// Set-up for main processing loop

	// Subscription for LogMessagePublished events
	sub := NewSubscription(ethConnector.Client(), ethConnector)
	sub.Subscribe(ctx)
	defer sub.Close()
	// Counter for amount of logs processed.
	countLogsProcessed := int(0)
	// Mapping to track the transactions that have been processed.
	processedTransactions := make(map[common.Hash]*types.Receipt)
	// The latest transaction block number, used to determine the size of historic receipts to keep in memory.
	lastBlockNumber := uint64(0)
	// Ticker to clear historic transactions that have been processed
	ticker := time.NewTicker(pruneConfig.pruneFrequency)
	defer ticker.Stop() // delete for Go >= 1.23. See time.NewTicker() documentation.

	// MAIN LOOP:
	// - watch for LogMessagePublished events coming from the connector attached to the core bridge.
	// - parse receipts for these events
	// - process parsed receipts to make sure they are valid
	main:
	for {
		select {
		case err := <-sub.Errors():
			logger.Warn("error on subscription", zap.Error(err))

		// Do cleanup and statistics reporting.
		case <-ticker.C:

			// Basic liveness report and statistics.
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
		case vLog := <-sub.Events():

			logger.Debug("detected LogMessagePublished event",
				zap.String("txHash", vLog.Raw.TxHash.String()))

			// Record used/inspected tx hash.
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

			// Get transaction receipt.
			receipt, err := transferVerifier.ethConnector.TransactionReceipt(ctx, vLog.Raw.TxHash)
			if err != nil {
				logger.Warn("could not find core bridge receipt", zap.Error(err))
				continue
			}

			// Record a new lastBlockNumber.
			lastBlockNumber = receipt.BlockNumber.Uint64()
			processedTransactions[vLog.Raw.TxHash] = receipt

			// Parse raw transaction receipt into high-level struct containing transfer details.
			transferReceipt, err := transferVerifier.ParseReceipt(receipt)
			if err != nil || transferReceipt == nil {
				logger.Warn("error when parsing receipt. skipping validation",
					zap.String("receipt hash", receipt.TxHash.String()),
					zap.Error(err))
				continue
			}

			// Do additional processing on the raw data that has
			// been parsed. This consists of checking whether
			// assets are wrapped for both ERC20 Transfer logs and
			// LogMessagePublished events. If so, unwrap the assets
			// and fetch information about the native chain, native
			// address, and token decimals. All of this information
			// is required to determine whether the amounts
			// deposited into the token bridge match the amount
			// that was requested out.
			// This is done separately from parsing step so that
			// RPC calls are done independently of parsing code,
			// which facilitates testing.
			for _, transfer := range *transferReceipt.Transfers {
				// The native address is returned here, but it is ignored. The goal here is only to correct
				// the native chain ID so that it can be compared against the destination asset in the
				// LogMessagePublished payload.
				nativeChainID, _, nativeErr := transferVerifier.nativeInfo(transfer.TokenAddress, transfer.TokenChain)
				if nativeErr != nil {
					// It's somewhat common for transfers to be made across the bridge for assets
					// that are not properly registered. In this case, calls to isWrappedAsset() on 
					// the Token Bridge will return true but the calls to wrappedAsset() will return
					// the zero address. In this case it's impossible to determine the decimals and
					// therefore there is no way to compare the amount transferred or burned with 
					// the LogMessagePublished payload. In this case, we can't process this receipt.
					transferVerifier.logger.Info(
						"error when getting native info for ERC20 Transfer. Can't continue to process this receipt",
						zap.Error(nativeErr),
						zap.String("ERC20Transfer", transfer.String()),
					)
					// Stop processing this receipt and continue to the main program loop
					continue main
				}

				// Update ChainID if this is a wrapped asset
				if nativeChainID != 0  && nativeChainID != transfer.TokenChain {
					transferVerifier.logger.Debug("updating chain ID for Token with its native chain ID",
						zap.String("tokenAddr", transfer.TokenChain.String()),
						zap.Uint16("new chainID", uint16(nativeChainID)),
						zap.String("chain name", nativeChainID.String()))
					transfer.TokenChain = nativeChainID
					continue
				}

				transferVerifier.logger.Debug("token is native. no info updated")
			}

			// Populate the native asset information and token decimals for assets recorded in LogMessagePublished
			// events for this receipt.
			for _, message := range *transferReceipt.MessagePublicatons {
				logger.Debug("populating native data for LogMessagePublished assets")
				newDetails, wormErr := transferVerifier.populateNativeDetails(message.TransferDetails)
				if wormErr != nil {
					// The unwrapped address and the denormalized amount are necessary for checking
					// that the amount matches.
					logger.Warn("error when populating wormhole details. cannot verify receipt!",
						zap.String("txHash", receipt.TxHash.String()),
						zap.String("parsed transfer details", message.TransferDetails.String()),
						zap.Error(wormErr))
					continue
				}
				message.TransferDetails = newDetails
			}

			// Ensure that the amount coming in is at least as much as the amount requested out.
			summary, processErr := transferVerifier.ProcessReceipt(transferReceipt)
			logger.Debug("finished processing receipt", zap.String("summary", summary.String()))

			if processErr != nil {
				logger.Error("detected invalid receipt", zap.Error(err), zap.String("txHash", vLog.Raw.TxHash.String()))
				continue
			}

			// Update statistics
			if summary.logsProcessed == 0 {
				logger.Warn("receipt logs empty for tx", zap.String("txHash", vLog.Raw.TxHash.Hex()))
				continue
			}

			countLogsProcessed += int(summary.logsProcessed)
		}
	}
}

// nativeInfo queries the token bridge about whether the token address is wrapped, and if so, returns the native chain
// and address where the token was minted.
func (tv *TransferVerifier[ethClient, Connector]) nativeInfo(
	tokenAddr common.Address,
	tokenChain vaa.ChainID,
) (nativeChain vaa.ChainID, nativeAddr common.Address, err error) {
	tv.logger.Debug("checking if ERC20 asset is wrapped")

	wrapped, err := tv.isWrappedAsset(tokenAddr)
	if err != nil {
		return 0, ZERO_ADDRESS, errors.Join(errors.New("could not check if asset was wrapped"), err)
	}

	if !wrapped {
		tv.logger.Debug("asset is native (not wrapped)", zap.String("tokenAddr", tokenAddr.String()))
		return 0, ZERO_ADDRESS, nil
	}

	// Unwrap the asset
	unwrapped, err := tv.unwrapIfWrapped(tokenAddr.Bytes(), tokenChain)
	if err != nil {
		return 0, ZERO_ADDRESS, errors.Join(errors.New("error when unwrapping asset"), err)
	}

	// Asset is wrapped but not in wrappedAsset map for the Token Bridge.
	if cmp(unwrapped, ZERO_ADDRESS) == 0 {
		// No need to query if the address is not wrapped
		return 0, ZERO_ADDRESS, errors.New("Asset is wrapped but equal to the zero address. This is an unusual asset or there is a bug in the program.")
	}

	// Get the native chain ID
	nativeChain, err = tv.chainId(unwrapped)
	if err != nil {
		return 0, ZERO_ADDRESS, errors.Join(errors.New("error when fetching chain ID"), err)
	}
	return nativeChain, nativeAddr, nil
}

// ParseReceipt converts a go-ethereum receipt struct into a TransferReceipt.
// It makes use of the ethConnector to parse information from the logs within
// the receipt. This function is mainly helpful to isolate the parsing code
// from the verification logic, which makes the latter easier to test without
// needing an active RPC connection.

// This function parses only events with topics needed for Transfer
// Verification. Any other events will be discarded.
// This function is not responsible for checking that the values for the
// various fields are relevant, only that they are well-formed.
func (tv *TransferVerifier[evmClient, connector]) ParseReceipt(
	receipt *types.Receipt,
) (*TransferReceipt, error) {
	// Sanity checks. Shouldn't be necessary but no harm
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
			// TODO this function could take the entire log and return the Transfer
			from, to, amount := parseERC20TransferEvent(log.Topics, log.Data)
			transfers = append(transfers, &ERC20Transfer{
				TokenAddress: log.Address,
				TokenChain:   NATIVE_CHAIN_ID, // TODO is this right?
				From:         from,
				To:           to,
				Amount:       amount,
			})
		case common.HexToHash(EVENTHASH_WETH_DEPOSIT):
			// TODO this function could take the entire log and return the Deposit
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
				tv.logger.Error(
					"a LogMessagePayload event from the token bridge was received with a zero-sized payload",
					zap.String("txhash", log.TxHash.String()))
				continue
			}

			// This check is required. Payload parsing will fail if performed on a message emitted from another contract or sent
			// by a contract other than the token bridge
			if log.Address != tv.Addresses.CoreBridgeAddr {
				tv.logger.Debug("skip: LogMessagePublished not emitted from the core bridge",
					zap.String("emitter", log.Address.String()))
				continue
			}

			if log.Topics[1] != tv.Addresses.TokenBridgeAddr.Hash() {
				tv.logger.Debug("skip: LogMessagePublished with sender not equal to the token bridge",
					zap.String("sender", log.Topics[1].String()),
					zap.String("tokenBridgeAddr", tv.Addresses.TokenBridgeAddr.Hex()),
				)
				continue
			}

			// Validation is complete. Now, parse the raw bytes of the payload into a TransferDetails instance.
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

	return &TransferReceipt{
			Deposits:           &deposits,
			Transfers:          &transfers,
			MessagePublicatons: &messagePublications},
		nil
}

// Custom error type used to signal that a core invariant of the token bridge has been violated.
type InvariantError struct {
	Msg string
}

func (i InvariantError) Error() string {
	return fmt.Sprintf("invariant violated: %s", i.Msg)
}

// ProcessReceipt verifies that a receipt for a LogMessagedPublished event does
// not verify a fundamental invariant of Wormhole token transfers: when the
// core bridge reports a transfer has occurred, there must be a corresponding
// transfer in the token bridge. This is determined by iterating through the
// logs of the receipt and ensuring that the sum transferred into the token
// bridge does not exceed the sum emitted by the core bridge.
func (tv *TransferVerifier[evmClient, connector]) ProcessReceipt(
	transferReceipt *TransferReceipt,
) (summary *ReceiptSummary, err error) {
	summary = NewReceiptSummary()

	// Sanity checks.
	if transferReceipt == nil {
		tv.logger.Warn("transfer receipt is nil. Cannot perform transfer verification")
		return summary, errors.New("got nil transfer receipt")
	}
	if len(*transferReceipt.MessagePublicatons) == 0 {
		tv.logger.Warn("transfer receipt contained no LogMessagePublished events. Cannot perform transfer verification")
		return summary, errors.New("no message publications in receipt")
	}

	// Process NativeDeposits
	for _, deposit := range *transferReceipt.Deposits {

		validateErr := validate[*NativeDeposit](deposit)
		if validateErr != nil {
			return summary, validateErr
		}

		key, relevant := relevant[*NativeDeposit](deposit, tv.Addresses)
		if !relevant {
			tv.logger.Debug("skip: irrelevant deposit",
				zap.String("emitter", deposit.Emitter().String()),
				zap.String("deposit", deposit.String()),
			)
			continue
		}
		if key == "" {
			return summary, errors.New("Couldn't get key")
		}

		upsert(&summary.in, key, deposit.TransferAmount())

		tv.logger.Debug("a deposit into the token bridge was recorded",
			zap.String("tokenAddress", deposit.TokenAddress.String()),
			zap.String("amount", deposit.Amount.String()))
	}

	// Process ERC20Transfers
	for _, transfer := range *transferReceipt.Transfers {
		validateErr := validate[*ERC20Transfer](transfer)
		if validateErr != nil {
			return summary, validateErr
		}

		key, relevant := relevant[*ERC20Transfer](transfer, tv.Addresses)
		if !relevant {
			tv.logger.Debug("skipping irrelevant transfer",
				zap.String("emitter", transfer.Emitter().String()),
				zap.String("erc20Transfer", transfer.String()))
			continue
		}
		if key == "" {
			return summary, errors.New("Couldn't get key")
		}

		upsert(&summary.in, key, transfer.TransferAmount())

		tv.logger.Debug("a transfer into the token bridge was recorded",
			zap.String("tokenAddress", transfer.TokenAddress.String()),
			zap.String("amount", transfer.Amount.String()))
	}

	// Process LogMessagePublished events.
	for _, message := range *transferReceipt.MessagePublicatons {
		td := message.TransferDetails

		validateErr := validate[*LogMessagePublished](message)
		if validateErr != nil {
			return summary, validateErr
		}

		key, relevant := relevant[*LogMessagePublished](message, tv.Addresses)
		if !relevant {
			tv.logger.Debug("skip: irrelevant LogMessagePublished event")
			continue
		}

		upsert(&summary.out, key, message.TransferAmount())

		tv.logger.Debug("successfully parsed a LogMessagePublished event payload",
			zap.String("tokenAddress", td.OriginAddress.String()),
			zap.String("tokenChain", td.TokenChain.String()),
			zap.String("amount", td.Amount.String()))

		summary.logsProcessed++
	}

	err = nil
	for key, amountOut := range summary.out {
		var localErr error
		if amountIn, exists := summary.in[key]; !exists {
			tv.logger.Error("transfer-out request for tokens that were never deposited",
				zap.String("key", key))
			localErr = &InvariantError{Msg: "transfer-out request for tokens that were never deposited"}
		} else {
			if amountOut.Cmp(amountIn) == 1 {
				tv.logger.Error("requested amount out is larger than amount in")
				localErr = &InvariantError{Msg: "requested amount out is larger than amount in"}
			}

			// Normally the amounts should be equal. This case indicates
			// an unusual transfer or else a bug in the program.
			if amountOut.Cmp(amountIn) == -1 {
				tv.logger.Info("requested amount in is larger than amount out.",
					zap.String("key", key),
					zap.String("amountIn", amountIn.String()),
					zap.String("amountOut", amountOut.String()),
				)
			}

			tv.logger.Debug("bridge request processed",
				zap.String("key", key),
				zap.String("amountOut", amountOut.String()),
				zap.String("amountIn", amountIn.String()))
		}

		if err != nil {
			err = errors.Join(err, localErr)
		} else {
			err = localErr
		}
	}

	return
}

// This function parses an ERC20 transfer event from a log topic and data.
// It verifies the input lengths, extracts the 'from', 'to' and amount fields from the log data,
// and returns these values as common.Address and big.Int types.
// - Error handling: The function checks if the log data and topic lengths are correct before attempting to parse them.
// - Input validation: The function verifies that the input lengths match expected values, preventing potential attacks or errors.
func parseERC20TransferEvent(logTopics []common.Hash, logData []byte) (from common.Address, to common.Address, amount *big.Int) {

	// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/6e224307b44bc4bd0cb60d408844e028cfa3e485/contracts/token/ERC20/IERC20.sol#L16
	// event Transfer(address indexed from, address indexed to, uint256 value)
	if len(logData) != EVM_WORD_LENGTH || len(logTopics) != TOPICS_COUNT_TRANSFER {
		return common.Address{}, common.Address{}, nil
	}

	from = common.BytesToAddress(logTopics[1][:])
	to = common.BytesToAddress(logTopics[2][:])
	amount = new(big.Int).SetBytes(logData[:])

	return
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

// parseLogMessagePublishedPayload parses the details of a transfer from a
// LogMessagePublished event's Payload field.
func parseLogMessagePublishedPayload(
	// Corresponds to LogMessagePublished.Payload as returned by the ABI parsing operation in the ethConnector.
	data []byte,
) (*TransferDetails, error) {
	// This method is already called by DecodeTransferPayloadHdr but the
	// error message is unclear. Doing a manual check here lets us return a
	// more helpful error message.
	if !vaa.IsTransfer(data) {
		return nil, errors.New("payload is not a transfer type. no need to process.")
	}

	// Note: vaa.DecodeTransferPayloadHdr performs validation on data, e.g. length checks.
	hdr, err := vaa.DecodeTransferPayloadHdr(data)
	if err != nil {
		return nil, err
	}
	return &TransferDetails{
		PayloadType:      VAAPayloadType(hdr.Type),
		AmountRaw:        hdr.Amount,
		OriginAddressRaw: hdr.OriginAddress.Bytes(),
		TokenChain:       vaa.ChainID(hdr.OriginChain),
		TargetAddress:    hdr.TargetAddress,
		// these fields are populated by RPC calls later
		Amount:        nil,
		OriginAddress: common.Address{},
	}, nil
}

// populateNativeDetails makes requests to the token bridge and token contract to get detailed, wormhole-specific information about
// the transfer details parsed from a LogMessagePublished event.
func (tv *TransferVerifier[ethClient, connector]) populateNativeDetails(details *TransferDetails) (newDetails *TransferDetails, decimalErr error) {
	// This function adds information to a TransferDetails struct, filling out its uninitialized fields.
	// It populates the following fields:
	// - Amount: populate the Amount field by denormalizing details.AmountRaw.
	// - OriginAddress: use ChainID and OriginAddressRaw to determine whether the token is wrapped.

	// If the token was minted on the chain monitored by this program, set its OriginAddress equal to OriginAddressRaw.
	var originAddress common.Address
	if details.TokenChain == NATIVE_CHAIN_ID {
		// The token was minted on this chain.
		originAddress = common.BytesToAddress(details.OriginAddressRaw)
		tv.logger.Debug("token is native. no need to unwrap",
			zap.String("originAddressRaw", fmt.Sprintf("%x", details.OriginAddressRaw)),
		)
	} else {
		// The token was minted on a foreign chain. Unwrap it.
		tv.logger.Debug("unwrapping",
			zap.String("originAddressRaw", fmt.Sprintf("%x", details.OriginAddressRaw)),
		)
		// If the token was minted on another chain, try to unwrap it.
		unwrappedAddress, unwrapErr := tv.unwrapIfWrapped(details.OriginAddressRaw, details.TokenChain)
		if unwrapErr != nil {
			return newDetails, unwrapErr
		}

		if cmp(unwrappedAddress, ZERO_ADDRESS) == 0 {
			// If the unwrap function returns the zero address, that means
			// it has no knowledge of this token. In this case set the
			// OriginAddress to OriginAddressRaw rather than to the zero
			// address. The program will still be able to know that this is
			// a non-native address by examining the chain ID.
			//
			// This case can occur if a token is transferred when the wrapped asset hasn't been set-up yet.
			// https://github.com/wormhole-foundation/wormhole/blob/main/whitepapers/0003_token_bridge.md#setup-of-wrapped-assets
			tv.logger.Warn("unwrap call for foreign asset returned the zero address. Either token has not been registered or there is a bug in the program. .",
				zap.String("originAddressRaw", details.OriginAddress.String()),
				zap.String("tokenChain", details.TokenChain.String()),
			)
			return newDetails, errors.New("unwrap call for foreign asset returned the zero address. Either token has not been registered or there is a bug in the program")
		} else {
			originAddress = unwrappedAddress
		}
	}

	// Fetch the token's decimals and update TransferDetails with the denormalized amount.
	// This must be done on the unwrapped address.
	decimals, decimalErr := tv.getDecimals(originAddress)
	if decimalErr != nil {
		return newDetails, decimalErr
	}

	denormalized := denormalize(details.AmountRaw, decimals)

	newDetails = details
	newDetails.OriginAddress = originAddress
	newDetails.Amount = denormalized
	return newDetails, nil
}

// upsert inserts a new key and value into a map or update the value if the key already exists.
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
