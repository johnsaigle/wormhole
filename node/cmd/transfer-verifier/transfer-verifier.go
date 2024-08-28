package transferverifier

import (
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

// The expected total number of indexed topics for a WETH Deposit event
const TOPICS_COUNT_DEPOSIT = 2
// The expected total number of indexed topics for an ERC20 Transfer event
const TOPICS_COUNT_TRANSFER = 3

// Which index within the topics slice contains the destination for the WETH Deposit transaction
const DESTINATION_INDEX_DEPOSIT = 1
// Which index within the topics slice contains the destination for the ERC20 Transfer transaction
const DESTINATION_INDEX_TRANSFER = 2

// CLI args
var (
	// envStr *string
	logLevel *string
	RPC      *string
	coreContract *string
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
func parseTransferPayload(data []byte) (*TransferDetails, error) {
	t := TransferDetails{}

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
	if len(data) < 65 {
		return nil, errors.New("Invalid data length")
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
	countLogsProcessed := uint(0)
	livenessInterval := uint(2)
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

			logger.Debug("parsing data payload",
				zap.String("payload", fmt.Sprintf("%x", vLog.Payload)))
			transferDetails, err := parseTransferPayload(vLog.Payload)
			if err != nil {
				// This should never occur when parsing well-formed payloads from the Token Bridge
				logger.Warn("error when parsing data payload", zap.Error(err))
			} else if transferDetails != nil {
				// nil check should be redundant after checking err, but this avoids nil pointer deref
				logger.Debug("expected transfer token", zap.String("tokenAddress", transferDetails.TokenAddress.String()))
				logger.Debug("expected transfer amount", zap.String("amount", transferDetails.Amount.String()))
			} 


			receipt, err := ethConnector.TransactionReceipt(ctx, vLog.Raw.TxHash)
			if err != nil {
				logger.Warn("could not find core bridge receipt", zap.Error(err))
				continue
			}

			numProcessed, err := validateReceipt(receipt, tokenBridgeAddr, logger)
			if numProcessed == 0 {
				logger.Warn("receipt logs empty for tx", zap.String("txHash", vLog.Raw.TxHash.String()))
				continue
			} 
			if err != nil {
				logger.Warn("could not parse core bridge receipt", zap.Error(err), zap.String("txHash", vLog.Raw.TxHash.String()))
				continue
			}

			// Basic liveness report and statistics
			countLogsProcessed += uint(numProcessed)
			// TODO fix with a total count and a trigger
			if countLogsProcessed % livenessInterval == 0 {
				logger.Info("total logs processed:",  zap.Uint("count", countLogsProcessed))
			}
		}
	}
}



// validateReceipt Parses the receipt for a transaction that emits a LogMessagePublished event. Returns the number of logs parsed from the receipt.
func validateReceipt(
	receipt *types.Receipt,
	tokenBridgeAddr common.Address,
	logger *zap.Logger) (numProcessed uint8, err error) {

	// Shouldn't be necessary but no harm
	if receipt.Status != 1 {
		return 0, fmt.Errorf("non-success transaction status: %d", receipt.Status)
	}

	looksNormal := false
	for i, l := range receipt.Logs {
		if l == nil {
			logger.Debug("Skipping nil log")
			continue
		}
		logger.Debug("processing receipt log", 
			zap.Int("index", i), 
			zap.String("address", l.Address.String()))

		// Skip logs produced by the core contract
		// if l.Address == coreBridgeAddr {
		// 	continue
		// }

		for i, topic := range l.Topics {
			logger.Debug("topic info", zap.String("topic", topic.Hex()), zap.Int("index", i))
		}

		// Required in the receipt from Token Bridge's wrapAndTransferEth()
		if l.Topics[0] == common.HexToHash(EVENTHASH_WETH_DEPOSIT) {
			logger.Debug("deposit occurred: Deposit() topic found", 
				zap.Int("logIndex", i))

			if len(l.Topics) != TOPICS_COUNT_DEPOSIT {
				logger.Warn("event Deposit() detected but has wrong number of topics", 
					zap.Int("logIndex", i),
					zap.Int("expected", TOPICS_COUNT_TRANSFER),
					zap.Int("actual", len(l.Topics)))
				// Can't go further here or we might index out of bounds
				err = errors.New("event Deposit() detected but has wrong number of topics")
				continue
			}

			destination := strings.ToLower(l.Topics[DESTINATION_INDEX_DEPOSIT].Hex())

			// The topic is prepended with 0s so check for the token bridge's address as a suffix. Strip
			// the leading `0x`.
			if !strings.HasSuffix(destination, strings.ToLower(tokenBridgeAddr.Hex()[2:])) {
				logger.Warn("event Deposit() detected but destination is not token bridge", 
					zap.String("tokenBridge", tokenBridgeAddr.Hex()), 
					zap.String("destination", destination))
				continue
			}
			logger.Debug("event Deposit()'s destination is token bridge", 
				zap.String("tokenBridge", tokenBridgeAddr.Hex()), 
				zap.String("destination", destination))

			looksNormal = true
			continue // break?
		} // end check deposit

		// Required in the receipt from Token Bridge's transferTokenWithPayload()
		if l.Topics[0] == common.HexToHash(EVENTHASH_ERC20_TRANSFER) {
			logger.Debug("transfer occurred: Transfer() topic found", 
				zap.Int("logIndex", i))

			if len(l.Topics) != TOPICS_COUNT_TRANSFER {
				logger.Warn("event Transfer() detected but has wrong number of topics", 
					zap.Int("logIndex", i),
					zap.Int("expected", TOPICS_COUNT_TRANSFER),
					zap.Int("actual", len(l.Topics)))

				err = errors.New("event Transfer() detected but has wrong number of topics")
				// Can't go further here or we might index out of bounds
				continue
			}

			destination := strings.ToLower(l.Topics[DESTINATION_INDEX_TRANSFER].Hex())

			// The topic is prepended with 0s so check for the token bridge's address as a suffix. Strip
			// the leading `0x`.
			if !strings.HasSuffix(destination, strings.ToLower(tokenBridgeAddr.Hex()[2:])) {
				logger.Warn("event Transfer() detected but destination is not token bridge", 
					zap.String("tokenBridge", tokenBridgeAddr.Hex()), 
					zap.String("destination", destination))
				continue
			}

			logger.Debug("event Transfer()'s destination is token bridge", 
				zap.String("tokenBridge", tokenBridgeAddr.Hex()), 
				zap.String("destination", destination))

			looksNormal = true
			continue // break?
		} // end check transfer
	}

	if !looksNormal {
		logger.Error("message published from core contract without corresponding Transfer or Deposit", 
			zap.String("txHash", receipt.TxHash.Hex()))
	}

	return uint8(len(receipt.Logs)), err
}
