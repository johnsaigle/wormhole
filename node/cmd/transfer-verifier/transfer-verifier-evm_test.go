package transferverifier

// TODO:
// - do mocking of ABI parsing and requests out to decimal
// - remove all `t.Skip()` calls

import (
	"context"
	// "encoding/binary"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// "github.com/uber/jaeger-client-go/log/zap"
	ipfslog "github.com/ipfs/go-log/v2"
	"go.uber.org/zap"

	// "go.uber.org/zap/zapcore"
	// "go.uber.org/zap/zaptest"
	// "go.uber.org/zap/zaptest/observer"

	// "github.com/ethereum/go-ethereum/accounts/abi/bind"
	// "github.com/ethereum/go-ethereum/accounts/abi/bind/backends"
	// transferverifier "github.com/certusone/wormhole/node/cmd/transfer-verifier"
	"github.com/ethereum/go-ethereum/common"
	// "github.com/ethereum/go-ethereum/core"
	// transferverifier "github.com/certusone/wormhole/node/cmd/transfer-verifier"
	connectors "github.com/certusone/wormhole/node/pkg/watchers/evm/connectors"
	"github.com/ethereum/go-ethereum/core/types"
	// "github.com/ethereum/go-ethereum/crypto"// "github.com/stretchr/testify/require"
)

// Important addresses for testing. Arbitrary, but Ethereum mainnet values used here
var (
	coreBridgeAddr  = common.HexToAddress("0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B")
	tokenBridgeAddr = common.HexToAddress("0x3ee18B2214AFF97000D974cf647E7C347E8fa585")
	nativeAddr      = common.HexToAddress("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2") // weth
	erc20Addr       = common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
)

// Sender of transactions
var (
	eoa = common.HexToAddress("0xbeefcafe")
)

// Typical receipt logs that can be included in various receipt test cases
var (
	transferLog = &types.Log{
		Address: erc20Addr,
		Topics: []common.Hash{
			// Transfer(address,address,uint256)
			common.HexToHash(EVENTHASH_ERC20_TRANSFER),
			// from
			common.HexToHash("0x00"), // unused
			// to
			tokenBridgeAddr.Hash(),
		},
		// amount
		// TODO this must match Data below
		Data: common.LeftPadBytes([]byte{0x01}, 32),
	}

	logMessagedPublishedLog = &types.Log{
		Address: coreBridgeAddr,
		Topics: []common.Hash{
			// LogMessagePublished(address indexed sender, uint64 sequence, uint32 nonce, bytes payload, uint8 consistencyLevel);
			common.HexToHash(EVENTHASH_WORMHOLE_LOG_MESSAGE_PUBLISHED),
			// sender
			tokenBridgeAddr.Hash(),
		},
		// NOTE: Make sure the amount here matches with the Data field of `transferLog`
		// TODO: This was grabbed from an arbitrary transaction on etherscan. We should change this: data
		// could be populated by doing ABI encoding on values we want to test
		Data: common.Hex2Bytes(
			"0000000000000000000000000000000000000000000000000000000000054683" +
				"0000000000000000000000000000000000000000000000000000000000000000" +
				"0000000000000000000000000000000000000000000000000000000000000080" +
				"0000000000000000000000000000000000000000000000000000000000000001" +
				"0000000000000000000000000000000000000000000000000000000000000085" +
				"010000000000000000000000000000000000000000000000000000000ba90d68" +
				"30069b8857feab8184fb687f634618c035dac439dc1aeb3b5598a0f000000000" +
				"010001ae50701d3669549b204728323f799ae131d966b05ec11198b4d00118de" +
				"b584720001000000000000000000000000000000000000000000000000000000" +
				"0000000000000000000000000000000000000000000000000000000000000000",
		),
	}
)

var (
	// TODO: this is not actually valid right now. Need to fix the logs to make them agree with each other
	validTransferReceipt = &types.Receipt{
		Status: types.ReceiptStatusSuccessful,
		Logs: []*types.Log{
			transferLog,
			logMessagedPublishedLog,
		},
	}
	// Invalid: no erc20 transfer, so amount out > amount in
	invalidTransferReceipt = &types.Receipt{
		Status: types.ReceiptStatusSuccessful,
		Logs: []*types.Log{
			logMessagedPublishedLog,
		},
	}
	// TODO: Invalid: erc20 transfer amount is less than payload amount, so amount out > amount in
	// invalidTransferReceipt = &types.Receipt{
	// 	Status:            types.ReceiptStatusSuccessful,
	// 	Logs: []*types.Log{logMessagedPublishedLog},
	// }
)

type mockConnections struct {
	transferVerifier *TransferVerifier
	logger           *zap.Logger
	connector        *connectors.Connector
	ctx              *context.Context
	ctxCancel        context.CancelFunc
}

// Create the connections and loggers expected by the functions we are testing
func setup() *mockConnections {
	transferVerifier := TransferVerifier{
		coreBridgeAddr:    coreBridgeAddr,
		tokenBridgeAddr:   tokenBridgeAddr,
		wrappedNativeAddr: nativeAddr,
	}
	ctx, ctxCancel := context.WithCancel(context.Background())
	// logger := zap.NewNop()
	logger := ipfslog.Logger("wormhole-transfer-verifier-tests").Desugar()
	ipfslog.SetAllLoggers(ipfslog.LevelDebug)

	var ethConnector connectors.Connector
	// TODO this needs to be replaced with a mock connector
	// Currently the tests should "work" but only if you have anvil running because they are making RPC calls
	// ethConnector, err := connectors.NewEthereumBaseConnector(ctx, "eth", "ws://localhost:8545", coreBridgeAddr, logger)
	// if err != nil {
	// 	panic(err)
	// }
	return &mockConnections{
		&transferVerifier,
		logger,
		&ethConnector,
		&ctx,
		ctxCancel,
	}
}

func TestParseReceiptHappyPath(t *testing.T) {
	t.Skip("needs a mock connector to function properly")
	mocks := setup()
	defer mocks.ctxCancel()

	// t.Parallel() // marks TLog as capable of running in parallel with other tests
	tests := map[string]struct {
		receipt  *types.Receipt
		expected int
	}{
		"valid transfer receipt, single LogMessagePublished": {
			validTransferReceipt,
			1,
		},
		// "valid transfer receipt, multiple LogMessagePublished": {
		// 	validTransferReceipt, // TODO
		// 	2,
		// },
	}
	for name, test := range tests {
		test := test // NOTE: uncomment for Go < 1.22, see /doc/faq#closures_and_goroutines
		t.Run(name, func(t *testing.T) {
			t.Log(name)

			transferReceipt, err := mocks.transferVerifier.parseReceipt(test.receipt, *mocks.connector, mocks.logger)
			require.NoError(t, err)
			assert.Equal(t, test.expected, transferReceipt)
		})
	}
}

func TestParseReceiptErrors(t *testing.T) {
	t.Skip("needs a mock connector to function properly")
	mocks := setup()
	defer mocks.ctxCancel()

	tests := map[string]struct {
		receipt  *types.Receipt
		expected int
	}{
		"only LogMessagedPublished": {
			receipt: &types.Receipt{
				Status: types.ReceiptStatusSuccessful,
				Logs: []*types.Log{
					logMessagedPublishedLog,
				},
			},
			// The Log will be processed successfully and increment the counter. But the function
			// should return an error.
			expected: 1,
		},
		"wrong receipt status": {
			receipt: &types.Receipt{
				Status: types.ReceiptStatusFailed,
				Logs: []*types.Log{
					logMessagedPublishedLog,
				},
			},
			expected: 0,
		},
	}
	for name, test := range tests {
		test := test // NOTE: uncomment for Go < 1.22, see /doc/faq#closures_and_goroutines
		t.Run(name, func(t *testing.T) {
			t.Log(name)

			numProcessed, err := mocks.transferVerifier.parseReceipt(test.receipt, *mocks.connector, mocks.logger)
			assert.Equal(t, test.expected, numProcessed)
			require.Error(t, err)
		})
	}
}

func TestParseERC20TransferEvent(t *testing.T) {
	type parsedValues struct {
		from   common.Address
		to     common.Address
		amount *big.Int
	}
	erc20TransferHash := common.HexToHash(EVENTHASH_ERC20_TRANSFER)
	t.Parallel() // marks TLog as capable of running in parallel with other tests
	tests := map[string]struct {
		topics   []common.Hash
		data     []byte
		expected *parsedValues
	}{
		"well-formed": {
			topics: []common.Hash{
				erc20TransferHash,
				eoa.Hash(),
				tokenBridgeAddr.Hash(),
			},
			data: common.LeftPadBytes([]byte{0x01}, 32),
			expected: &parsedValues{
				from:   eoa,
				to:     tokenBridgeAddr,
				amount: new(big.Int).SetBytes([]byte{0x01}),
			},
		},
		"data too short": {
			topics: []common.Hash{
				erc20TransferHash,
				eoa.Hash(),
				tokenBridgeAddr.Hash(),
			},
			// should be 32 bytes exactly
			data:     []byte{0x01},
			expected: &parsedValues{}, // everything nil for its type
		},
		"wrong number of topics": {
			// only 1 topic: should be 3
			topics: []common.Hash{
				erc20TransferHash,
			},
			data:     common.LeftPadBytes([]byte{0x01}, 32),
			expected: &parsedValues{}, // everything nil for its type
		},
	}

	for name, test := range tests {
		test := test // NOTE: uncomment for Go < 1.22, see /doc/faq#closures_and_goroutines
		t.Run(name, func(t *testing.T) {
			t.Parallel() // marks each test case as capable of running in parallel with each other
			t.Log(name)

			from, to, amount := parseERC20TransferEvent(test.topics, test.data)
			assert.Equal(t, test.expected.from, from)
			assert.Equal(t, test.expected.to, to)
			assert.Zero(t, amount.Cmp(test.expected.amount))
		})
	}
}

func TestParseWNativeDepositEvent(t *testing.T) {
	{
		type parsedValues struct {
			destination common.Address
			amount      *big.Int
		}
		t.Parallel() // marks TLog as capable of running in parallel with other tests

		wethDepositHash := common.HexToHash(EVENTHASH_WETH_DEPOSIT)
		tests := map[string]struct {
			topics   []common.Hash
			data     []byte
			expected *parsedValues
		}{
			"well-formed": {
				topics: []common.Hash{
					wethDepositHash,
					tokenBridgeAddr.Hash(),
				},
				data: common.LeftPadBytes([]byte{0x01}, 32),
				expected: &parsedValues{
					destination: tokenBridgeAddr,
					amount:      new(big.Int).SetBytes([]byte{0x01}),
				},
			},
			"data too short": {
				topics: []common.Hash{
					wethDepositHash,
					tokenBridgeAddr.Hash(),
				},
				// should be 32 bytes exactly
				data:     []byte{0x01},
				expected: &parsedValues{}, // everything nil for its type
			},
			"wrong number of topics": {
				// only 1 topic: should be 2
				topics: []common.Hash{
					wethDepositHash,
				},
				data:     common.LeftPadBytes([]byte{0x01}, 32),
				expected: &parsedValues{}, // everything nil for its type
			},
		}

		for name, test := range tests {
			test := test // NOTE: uncomment for Go < 1.22, see /doc/faq#closures_and_goroutines
			t.Run(name, func(t *testing.T) {
				t.Parallel() // marks each test case as capable of running in parallel with each other
				t.Log(name)

				destination, amount := parseWNativeDepositEvent(test.topics, test.data)
				assert.Equal(t, test.expected.destination, destination)
				assert.Zero(t, amount.Cmp(test.expected.amount))
			})
		}
	}

}

func TestProcessReceipt(t *testing.T) {
	mocks := setup()

	tests := map[string]struct {
		transferReceipt *TransferReceipt
		expected        int
		errored         bool
	}{
		// TODO test cases:
		// - multiple transfers adding up to the right amount
		// - multiple depoists adding up to the right amount
		// - multiple LogMessagePublished events
		"valid transfer: amounts match, deposit": {
			transferReceipt: &TransferReceipt{
				Deposits: &[]*NativeDeposit{
					&NativeDeposit{
						TokenAddress: nativeAddr,
						Destination:  tokenBridgeAddr,
						Amount:       big.NewInt(123),
					},
				},
				Transfers: &[]*TransferERC20{},
				MessagePublicatons: &[]*LogMessagePublished{
					&LogMessagePublished{
						Emitter: coreBridgeAddr,
						Sender:  tokenBridgeAddr,
						TransferDetails: &TransferDetails{
							PayloadType:  TransferTokens,
							TokenAddress: nativeAddr,
							TokenChain:   2,
							Amount:       big.NewInt(123),
						},
					},
				},
			},
			expected: 1,
			errored:  false,
		},
		"valid transfer: amounts match, transfer": {
			transferReceipt: &TransferReceipt{
				Deposits: &[]*NativeDeposit{},
				Transfers: &[]*TransferERC20{
					&TransferERC20{
						TokenAddress: erc20Addr,
						From:         eoa,
						To:           tokenBridgeAddr,
						Amount:       big.NewInt(456),
					},
				},
				MessagePublicatons: &[]*LogMessagePublished{
					&LogMessagePublished{
						Emitter: coreBridgeAddr,
						Sender:  tokenBridgeAddr,
						TransferDetails: &TransferDetails{
							PayloadType:  TransferTokens,
							TokenAddress: erc20Addr,
							TokenChain:   2,
							Amount:       big.NewInt(456),
						},
					},
				},
			},
			expected: 1,
			errored:  false,
		},
		"valid transfer: amount in is greater than amount out, deposit": {
			transferReceipt: &TransferReceipt{
				Deposits: &[]*NativeDeposit{
					&NativeDeposit{
						TokenAddress: nativeAddr,
						Destination:  tokenBridgeAddr,
						Amount:       big.NewInt(999),
					},
				},
				Transfers: &[]*TransferERC20{},
				MessagePublicatons: &[]*LogMessagePublished{
					&LogMessagePublished{
						Emitter: coreBridgeAddr,
						Sender:  tokenBridgeAddr,
						TransferDetails: &TransferDetails{
							PayloadType:  TransferTokens,
							TokenAddress: nativeAddr,
							TokenChain:   2,
							Amount:       big.NewInt(321),
						},
					},
				},
			},
			expected: 1,
			errored:  false,
		},
		"valid transfer: amount in is greater than amount out, transfer": {
			transferReceipt: &TransferReceipt{
				Deposits: &[]*NativeDeposit{},
				Transfers: &[]*TransferERC20{
					&TransferERC20{
						TokenAddress: erc20Addr,
						From:         eoa,
						To:           tokenBridgeAddr,
						Amount:       big.NewInt(999),
					},
				},
				MessagePublicatons: &[]*LogMessagePublished{
					&LogMessagePublished{
						Emitter: coreBridgeAddr,
						Sender:  tokenBridgeAddr,
						TransferDetails: &TransferDetails{
							PayloadType:  TransferTokens,
							TokenAddress: erc20Addr,
							TokenChain:   2,
							Amount:       big.NewInt(321),
						},
					},
				},
			},
			expected: 1,
			errored:  false,
		},
		"invalid transfer: no LogMessagePublished": {
			transferReceipt: &TransferReceipt{
				Deposits: &[]*NativeDeposit{
					&NativeDeposit{
						TokenAddress: nativeAddr,
						Destination:  tokenBridgeAddr,
						Amount:       big.NewInt(10),
					},
				},
				Transfers: &[]*TransferERC20{
					&TransferERC20{
						TokenAddress: erc20Addr,
						From:         eoa,
						To:           tokenBridgeAddr,
						Amount:       big.NewInt(456),
					},
				},
				MessagePublicatons: &[]*LogMessagePublished{},
			},
			expected: 0,
			errored:  true,
		},
		"invalid transfer: amount in too low, deposit": {
			transferReceipt: &TransferReceipt{
				Deposits: &[]*NativeDeposit{
					&NativeDeposit{
						TokenAddress: nativeAddr,
						Destination:  tokenBridgeAddr,
						Amount:       big.NewInt(10),
					},
				},
				Transfers: &[]*TransferERC20{},
				MessagePublicatons: &[]*LogMessagePublished{
					&LogMessagePublished{
						Emitter: coreBridgeAddr,
						Sender:  tokenBridgeAddr,
						TransferDetails: &TransferDetails{
							PayloadType:  TransferTokens,
							TokenAddress: nativeAddr,
							TokenChain:   2,
							Amount:       big.NewInt(11),
						},
					},
				},
			},
			expected: 1,
			errored:  true,
		},
		"invalid transfer: amount in too low, transfer": {
			transferReceipt: &TransferReceipt{
				Deposits: &[]*NativeDeposit{},
				Transfers: &[]*TransferERC20{
					&TransferERC20{
						TokenAddress: erc20Addr,
						From:         eoa,
						To:           tokenBridgeAddr,
						Amount:       big.NewInt(1),
					},
				},
				MessagePublicatons: &[]*LogMessagePublished{
					&LogMessagePublished{
						Emitter: coreBridgeAddr,
						Sender:  tokenBridgeAddr,
						TransferDetails: &TransferDetails{
							PayloadType:  TransferTokens,
							TokenAddress: nativeAddr,
							TokenChain:   2,
							Amount:       big.NewInt(2),
						},
					},
				},
			},
			expected: 1,
			errored:  true,
		},
		"invalid transfer: transfer out after transferring a different token": {
			transferReceipt: &TransferReceipt{
				Deposits: &[]*NativeDeposit{},
				Transfers: &[]*TransferERC20{
					&TransferERC20{
						TokenAddress: erc20Addr,
						From:         eoa,
						To:           tokenBridgeAddr,
						Amount:       big.NewInt(2),
					},
				},
				MessagePublicatons: &[]*LogMessagePublished{
					&LogMessagePublished{
						Emitter: coreBridgeAddr,
						Sender:  tokenBridgeAddr,
						TransferDetails: &TransferDetails{
							PayloadType:  TransferTokens,
							TokenAddress: nativeAddr,
							TokenChain:   2,
							Amount:       big.NewInt(2),
						},
					},
				},
			},
			expected: 1,
			errored:  true,
		},
	}

	for name, test := range tests {
		test := test // NOTE: uncomment for Go < 1.22, see /doc/faq#closures_and_goroutines
		t.Run(name, func(t *testing.T) {
			t.Log(name)

			numProcessed, err := mocks.transferVerifier.processReceipt(test.transferReceipt, mocks.logger)
			assert.Equal(t, test.expected, numProcessed)
			// TODO this could be expanded to check for specific error messages
			assert.Equal(t, err != nil, test.errored)
		})
	}
}

func TestDenormalize(t *testing.T) {

	t.Parallel() // marks TLog as capable of running in parallel with other tests
	tests := map[string]struct {
		amount   *big.Int
		decimals uint8
		expected *big.Int
	}{
		"noop: decimals less than 8": {
			amount:   big.NewInt(123000),
			decimals: 1,
			expected: big.NewInt(123000),
		},
		"noop: decimals equal to 8": {
			amount:   big.NewInt(123000),
			decimals: 8,
			expected: big.NewInt(123000),
		},
		"denormalize: decimals greater than 8": {
			amount:   big.NewInt(123000),
			decimals: 12,
			expected: big.NewInt(1230000000),
		},
		// NOTE: some tokens on NEAR have as many as 24 decimals so this isn't a strict limit for Wormhole
		// overall, but should be true for EVM chains.
		"denormalize: decimals at maximum expected size": {
			amount:   big.NewInt(123_000_000),
			decimals: 18,
			expected: big.NewInt(1_230_000_000_000_000_000),
		},
		// https://github.com/wormhole-foundation/wormhole/blob/main/whitepapers/0003_token_bridge.md#handling-of-token-amounts-and-decimals
		"denormalize: whitepaper example 1": {
			amount:   big.NewInt(100000000),
			decimals: 18,
			expected: big.NewInt(1000000000000000000),
		},
		"denormalize: whitepaper example 2": {
			amount:   big.NewInt(20000),
			decimals: 4,
			expected: big.NewInt(20000),
		},
	}
	for name, test := range tests {
		test := test // NOTE: uncomment for Go < 1.22, see /doc/faq#closures_and_goroutines
		t.Run(name, func(t *testing.T) {
			t.Parallel() // marks each test case as capable of running in parallel with each other
			t.Log(name)

			if got := denormalize(test.amount, test.decimals); got.Cmp(test.expected) != 0 {
				t.Fatalf("denormalize(%s, %d) returned %s; expected %s",
					test.amount.String(),
					test.decimals,
					got,
					test.expected.String(),
				)
			}

		})
	}
}
