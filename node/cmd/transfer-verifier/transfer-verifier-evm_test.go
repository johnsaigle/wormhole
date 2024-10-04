package transferverifier

// TODO:
// - do mocking of ABI parsing and requests out to decimal
// - remove all `t.Skip()` calls

import (
	"context"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	// The following imports are needed for mocking
	connectors "github.com/certusone/wormhole/node/pkg/watchers/evm/connectors"
	ethAbi "github.com/certusone/wormhole/node/pkg/watchers/evm/connectors/ethabi"
	ethereum "github.com/ethereum/go-ethereum"
	ethClient "github.com/ethereum/go-ethereum/ethclient"
	ethEvent "github.com/ethereum/go-ethereum/event"
	ethRpc "github.com/ethereum/go-ethereum/rpc"

	ipfslog "github.com/ipfs/go-log/v2"
	// "go.uber.org/zap"
)

// Important addresses for testing. Arbitrary, but Ethereum mainnet values used here
var (
	coreBridgeAddr  = common.HexToAddress("0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B")
	tokenBridgeAddr = common.HexToAddress("0x3ee18B2214AFF97000D974cf647E7C347E8fa585")
	nativeAddr      = common.HexToAddress("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2") // weth
	erc20Addr       = common.HexToAddress("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48") // usdc
	eoa             = common.HexToAddress("0xbeefcafe")
)

// Typical receipt logs that can be included in various receipt test cases
var (
	transferLog = &types.Log{
		Address: erc20Addr,
		Topics: []common.Hash{
			// Transfer(address,address,uint256)
			common.HexToHash(EVENTHASH_ERC20_TRANSFER),
			// from
			eoa.Hash(),
			// to
			tokenBridgeAddr.Hash(),
		},
		// amount
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
		Data: receiptData(big.NewInt(1)),
	}
)

var (
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

type mockTV struct {
	TransferVerifier TransferVerifier
}

func (m mockTV) getDecimals(tokenAddress common.Address) (decimals uint8, err error) {
	return 8, nil
}
func (m mockTV) unwrapIfWrapped(tokenAddress []byte, tokenChain uint16) (unwrappedTokenAddress common.Address, err error) {
	return common.BytesToAddress(tokenAddress), nil
}

// func (m mockTV) parseLogMessagePublishedPayload(data []byte) (*TransferDetails, error) {
// 	// panic("mock: parseLogMessagePublishedPayload")
// 	return m.TransferVerifier.parseLogMessagePublishedPayload(data, zap.NewNop())
// }

func (m mockTV) ParseReceipt(
	receipt *types.Receipt,
) (*TransferReceipt, error) {
	return m.TransferVerifier.ParseReceipt(receipt)
}

func (m mockTV) ProcessReceipt(
	receipt *TransferReceipt,
) (int, error) {
	return m.TransferVerifier.ProcessReceipt(receipt)
}

type mockConnections struct {
	transferVerifier mockTV
	ctx              *context.Context
	ctxCancel        context.CancelFunc
}

// Create the connections and loggers expected by the functions we are testing
func setup() *mockConnections {
	logger := ipfslog.Logger("wormhole-transfer-verifier-tests").Desugar()
	ipfslog.SetAllLoggers(ipfslog.LevelDebug)
	transferVerifier := mockTV{
		TransferVerifier: TransferVerifier{
			coreBridgeAddr:    coreBridgeAddr,
			tokenBridgeAddr:   tokenBridgeAddr,
			wrappedNativeAddr: nativeAddr,
			ethConnector:      &mockConnector{},
			logger:            *logger,
		},
	}
	ctx, ctxCancel := context.WithCancel(context.Background())

	// var ethConnector connectors.Connector
	// TODO this needs to be replaced with a mock connector
	// Currently the tests should "work" but only if you have anvil running because they are making RPC calls
	// ethConnector, err := connectors.NewEthereumBaseConnector(ctx, "eth", "ws://localhost:8545", coreBridgeAddr, logger)
	// if err != nil {
	// 	panic(err)
	// }

	return &mockConnections{
		transferVerifier,
		&ctx,
		ctxCancel,
	}
}

func TestParseReceiptHappyPath(t *testing.T) {
	mocks := setup()
	defer mocks.ctxCancel()

	// t.Parallel() // marks TLog as capable of running in parallel with other tests
	tests := map[string]struct {
		receipt  *types.Receipt
		expected *TransferReceipt
	}{
		"valid transfer receipt, single LogMessagePublished": {
			validTransferReceipt,
			&TransferReceipt{
				Deposits: &[]*NativeDeposit{},
				Transfers: &[]*TransferERC20{
					&TransferERC20{
						From:         eoa,
						To:           tokenBridgeAddr,
						TokenAddress: erc20Addr,
						Amount:       big.NewInt(1),
					},
				},
				MessagePublicatons: &[]*LogMessagePublished{
					&LogMessagePublished{
						Emitter: coreBridgeAddr,
						Sender:  tokenBridgeAddr,
						TransferDetails: &TransferDetails{
							PayloadType:     TransferTokens,
							TokenAddressRaw: erc20Addr,
							TokenChain:      2, // Wormhole ethereum chain ID
							AmountRaw:       big.NewInt(1),
							// Amount and OriginAddress are not populated by ParseReceipt
							// Amount: big.NewInt(1),
							// OriginAddress: erc20Addr,
						},
					},
				},
			},
		},
	}
	for name, test := range tests {
		test := test // NOTE: uncomment for Go < 1.22, see /doc/faq#closures_and_goroutines
		t.Run(name, func(t *testing.T) {
			t.Log(name)

			transferReceipt, err := mocks.transferVerifier.ParseReceipt(test.receipt)
			require.NoError(t, err)

			// Note: the data for this test uses only a single transfer. However, if multiple transfers
			// are used, iteration over these slices will be non-deterministic which might result in a flaky
			// test.
			expectedTransfers := *test.expected.Transfers
			assert.Equal(t, len(expectedTransfers), len(*transferReceipt.Transfers))
			for _, ret := range *transferReceipt.Transfers {
				assert.Equal(t, ret.From, expectedTransfers[0].From)
				assert.Equal(t, ret.To, expectedTransfers[0].To)
				assert.Equal(t, ret.TokenAddress, expectedTransfers[0].TokenAddress)
				assert.Zero(t, ret.Amount.Cmp(expectedTransfers[0].Amount))
			}

			expectedMessages := *test.expected.MessagePublicatons
			assert.Equal(t, len(expectedMessages), len(*transferReceipt.MessagePublicatons))
			for _, ret := range *transferReceipt.MessagePublicatons {
				assert.Equal(t, ret.Sender, expectedMessages[0].Sender)
				assert.Equal(t, ret.Emitter, expectedMessages[0].Emitter)
				assert.Equal(t, ret.TransferDetails, expectedMessages[0].TransferDetails)
				// Amount and OriginAddress are not populated by ParseReceipt
				assert.Equal(t, common.BytesToAddress([]byte{0x00}), ret.TransferDetails.OriginAddress)
				assert.Nil(t, ret.TransferDetails.Amount)
			}

		})
	}
}

func TestParseReceiptErrors(t *testing.T) {
	// TODO: Replace the test cases below with incorrect TransferReceipts
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

			numProcessed, err := mocks.transferVerifier.ParseReceipt(test.receipt)
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
							PayloadType:     TransferTokens,
							TokenAddressRaw: nativeAddr,
							OriginAddress:   nativeAddr,
							TokenChain:      2,
							AmountRaw:       big.NewInt(123),
							Amount:          big.NewInt(123),
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
							PayloadType:     TransferTokens,
							TokenAddressRaw: erc20Addr,
							OriginAddress:   erc20Addr,
							TokenChain:      2,
							AmountRaw:       big.NewInt(456),
							Amount:          big.NewInt(456),
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
							PayloadType:     TransferTokens,
							TokenAddressRaw: nativeAddr,
							OriginAddress:   nativeAddr,
							TokenChain:      2,
							AmountRaw:       big.NewInt(321),
							Amount:          big.NewInt(321),
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
							PayloadType:     TransferTokens,
							TokenAddressRaw: erc20Addr,
							OriginAddress:   erc20Addr,
							TokenChain:      2,
							AmountRaw:       big.NewInt(321),
							Amount:          big.NewInt(321),
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
							PayloadType:     TransferTokens,
							TokenAddressRaw: nativeAddr,
							OriginAddress:   nativeAddr,
							TokenChain:      2,
							AmountRaw:       big.NewInt(11),
							Amount:          big.NewInt(11),
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
							PayloadType:     TransferTokens,
							TokenAddressRaw: nativeAddr,
							OriginAddress:   nativeAddr,
							TokenChain:      2,
							AmountRaw:       big.NewInt(2),
							Amount:          big.NewInt(2),
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
							PayloadType:     TransferTokens,
							TokenAddressRaw: nativeAddr,
							OriginAddress:   nativeAddr,
							TokenChain:      2,
							AmountRaw:       big.NewInt(2),
							Amount:          big.NewInt(2),
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

			numProcessed, err := mocks.transferVerifier.ProcessReceipt(test.transferReceipt)
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

// End of Test cases

// Generate the Data portion of a LogMessagePublished receipt for use in unit tests.
// Note that Data encompasses the Payload for a transfer as well as metadata.
func receiptData(payloadAmount *big.Int) (data []byte) {
	// non-payload part of the receipt and ABI metadata fields
	seq := common.LeftPadBytes([]byte{0x00}, 32)
	nonce := common.LeftPadBytes([]byte{0x00}, 32)
	offset := common.LeftPadBytes([]byte{0x80}, 32)
	consistencyLevel := common.LeftPadBytes([]byte{0x01}, 32)
	payloadLength := common.LeftPadBytes([]byte{0x85}, 32) // 133 for transferTokens

	data = append(data, seq...)
	data = append(data, nonce...)
	data = append(data, offset...)
	data = append(data, consistencyLevel...)
	data = append(data, payloadLength...)
	data = append(data, transferTokensPayload(payloadAmount)...)
	return data
}

// Generate the Payload portion of a LogMessagePublished receipt for use in unit tests.
func transferTokensPayload(payloadAmount *big.Int) (data []byte) {
	// tokenTransfer() payload format:
	//     transfer.payloadID, uint8, size: 1
	//     amount, uint256, size: 32
	//     tokenAddress, bytes32: size 32
	//     tokenChain, uint16, size 2
	//     to, bytes32: size 32
	//     toChain, uint16, size: 2
	//     fee, uint256 size: size 32
	// 1 + 32 + 32 + 2 + 32 + 2 + 32 = 133
	// See also: https://docs.soliditylang.org/en/latest/abi-spec.html

	payloadType := []byte{0x01} // transferTokens, not padded
	amount := common.LeftPadBytes(payloadAmount.Bytes(), 32)
	tokenAddress := common.LeftPadBytes(erc20Addr.Bytes(), 32)
	tokenChain := common.LeftPadBytes([]byte{0x02}, 2) // Eth wormhole chain ID, uint16
	to := common.LeftPadBytes([]byte{0xca, 0xfe}, 32)
	toChain := common.LeftPadBytes([]byte{0x01}, 2) // Eth wormhole chain ID, uint16
	fee := common.LeftPadBytes([]byte{0x00}, 32)    // Solana wormhole chain ID, uint16
	data = append(data, payloadType...)
	data = append(data, amount...)
	data = append(data, tokenAddress...)
	data = append(data, tokenChain...)
	data = append(data, to...)
	data = append(data, toChain...)
	data = append(data, fee...)
	return data
}

// mockConnector implements the connector interface for testing purposes.
type mockConnector struct {
	address common.Address
	client  *ethClient.Client
	// mutex           sync.Mutex
	// headSink        chan<- *types.Header
	sub ethEvent.Subscription
	// err error
	// persistentError bool
	// blockNumbers    []uint64
	// prevLatest      uint64
	// prevSafe        uint64
	// prevFinalized   uint64
}

func (e *mockConnector) Client() *ethClient.Client {
	return e.client
}

func (e *mockConnector) NetworkName() string {
	return "mockConnector"
}

func (e *mockConnector) ContractAddress() common.Address {
	return e.address
}

func (e *mockConnector) GetCurrentGuardianSetIndex(ctx context.Context) (uint32, error) {
	return 0, fmt.Errorf("not implemented")
}

func (e *mockConnector) GetGuardianSet(ctx context.Context, index uint32) (ethAbi.StructsGuardianSet, error) {
	return ethAbi.StructsGuardianSet{}, fmt.Errorf("not implemented")
}

func (e *mockConnector) WatchLogMessagePublished(ctx context.Context, errC chan error, sink chan<- *ethAbi.AbiLogMessagePublished) (ethEvent.Subscription, error) {
	var s ethEvent.Subscription
	return s, fmt.Errorf("not implemented")
}

func (e *mockConnector) TransactionReceipt(ctx context.Context, txHash common.Hash) (*types.Receipt, error) {
	return nil, fmt.Errorf("not implemented")
}

func (e *mockConnector) TimeOfBlockByHash(ctx context.Context, hash common.Hash) (uint64, error) {
	return 0, fmt.Errorf("not implemented")
}

// This function is mocked to return data for TestParseReceiptHappyPath.
func (e *mockConnector) ParseLogMessagePublished(log types.Log) (*ethAbi.AbiLogMessagePublished, error) {
	// Returns only a single receipt for all calls to this function. This is because ParseLogMessagePublished
	// requires a valid connector and ethClient which requires extensive mocking beyond what's already done in
	// this test.
	return &ethAbi.AbiLogMessagePublished{
		Sender:   tokenBridgeAddr,
		Sequence: 0,
		Nonce:    0,
		Payload:  transferTokensPayload(big.NewInt(1)),
		Raw:      log,
	}, nil
}

func (e *mockConnector) SubscribeForBlocks(ctx context.Context, errC chan error, sink chan<- *connectors.NewBlock) (ethereum.Subscription, error) {
	return e.sub, fmt.Errorf("not implemented")
}

func (e *mockConnector) RawCallContext(ctx context.Context, result interface{}, method string, args ...interface{}) error {
	panic("method not implemented by mockConnector")
}

func (e *mockConnector) RawBatchCallContext(ctx context.Context, b []ethRpc.BatchElem) (err error) {
	panic("method not implemented by mockConnector")
}

func (e *mockConnector) SubscribeNewHead(ctx context.Context, ch chan<- *types.Header) (ethereum.Subscription, error) {
	return e.sub, fmt.Errorf("not implemented")
}
