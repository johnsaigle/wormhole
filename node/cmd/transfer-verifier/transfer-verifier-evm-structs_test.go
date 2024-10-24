package transferverifier

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wormhole-foundation/wormhole/sdk/vaa"
)

func TestRelevantDeposit(t *testing.T) {
	t.Parallel()

	// The expected return values for relevant()
	type result struct {
		key      string
		relevant bool
	}

	mocks := setup()

	deposits := map[string]struct {
		input    NativeDeposit
		expected result
	}{
		"relevant, deposit": {
			input: NativeDeposit{
				TokenAddress: nativeAddr,
				TokenChain:   NATIVE_CHAIN_ID,
				Receiver:     tokenBridgeAddr,
				Amount:       big.NewInt(500),
			},
			expected: result{"000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2-2", true},
		},
		"irrelevant, deposit from non-native contract": {
			input: NativeDeposit{
				TokenAddress: usdcAddr, // not Native
				TokenChain:   NATIVE_CHAIN_ID,
				Receiver:     tokenBridgeAddr,
				Amount:       big.NewInt(500),
			},
			expected: result{"", false},
		},
		"irrelevant, deposit not sent to token bridge": {
			input: NativeDeposit{
				TokenAddress: nativeAddr,
				TokenChain:   NATIVE_CHAIN_ID,
				Receiver:     eoaAddrGeth, // not token bridge
				Amount:       big.NewInt(500),
			},
			expected: result{"", false},
		},
		"irrelevant, sanity check for zero-address deposits": {
			input: NativeDeposit{
				TokenAddress: ZERO_ADDRESS, // zero address
				TokenChain:   NATIVE_CHAIN_ID,
				Receiver:     tokenBridgeAddr,
				Amount:       big.NewInt(500),
			},
			expected: result{"", false},
		},
	}

	transfers := map[string]struct {
		input    ERC20Transfer
		expected result
	}{
		"relevant, transfer": {
			input: ERC20Transfer{
				TokenAddress: nativeAddr,
				TokenChain:   NATIVE_CHAIN_ID,
				From:         eoaAddrGeth,
				To:           tokenBridgeAddr,
				Amount:       big.NewInt(500),
			},
			expected: result{"000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2-2", true},
		},
		"irrelevant, transfer destination is not token bridge": {
			input: ERC20Transfer{
				TokenAddress: nativeAddr,
				TokenChain:   NATIVE_CHAIN_ID,
				From:         eoaAddrGeth,
				To:           eoaAddrGeth,
				Amount:       big.NewInt(500),
			},
			expected: result{"", false},
		},
	}

	messages := map[string]struct {
		input    LogMessagePublished
		expected result
	}{
		"relevant, LogMessagePublished": {
			input: LogMessagePublished{
				EventEmitter: coreBridgeAddr,
				MsgSender:    tokenBridgeAddr,
				TransferDetails: &TransferDetails{
					PayloadType:      TransferTokens,
					OriginAddressRaw: usdcAddr.Bytes(),
					TokenChain:       NATIVE_CHAIN_ID,
					OriginAddress:    nativeAddr,
					TargetAddress:    eoaAddrVAA,
					AmountRaw:        big.NewInt(7),
					Amount:           big.NewInt(7),
				},
			},
			expected: result{"000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2-2", true},
		},
		"irrelevant, LogMessagePublished has a sender not equal to token bridge": {
			input: LogMessagePublished{
				EventEmitter: coreBridgeAddr,
				MsgSender:    eoaAddrGeth,
				TransferDetails: &TransferDetails{
					PayloadType:      TransferTokens,
					OriginAddressRaw: usdcAddr.Bytes(),
					TokenChain:       NATIVE_CHAIN_ID,
					OriginAddress:    nativeAddr,
					TargetAddress:    eoaAddrVAA,
					AmountRaw:        big.NewInt(7),
					Amount:           big.NewInt(7),
				},
			},
			expected: result{"", false},
		},
		"irrelevant, LogMessagePublished not emitted by core bridge": {
			input: LogMessagePublished{
				EventEmitter: tokenBridgeAddr,
				MsgSender:    tokenBridgeAddr,
				TransferDetails: &TransferDetails{
					PayloadType:      TransferTokens,
					OriginAddressRaw: usdcAddr.Bytes(),
					TokenChain:       NATIVE_CHAIN_ID,
					OriginAddress:    nativeAddr,
					TargetAddress:    eoaAddrVAA,
					AmountRaw:        big.NewInt(7),
					Amount:           big.NewInt(7),
				},
			},
			expected: result{"", false},
		},
		"irrelevant, LogMessagePublished does not have a PayloadType corresponding to a Transfer": {
			input: LogMessagePublished{
				EventEmitter: coreBridgeAddr,
				MsgSender:    tokenBridgeAddr,
				TransferDetails: &TransferDetails{
					PayloadType:      2,
					OriginAddressRaw: usdcAddr.Bytes(),
					TokenChain:       NATIVE_CHAIN_ID,
					OriginAddress:    nativeAddr,
					TargetAddress:    eoaAddrVAA,
					AmountRaw:        big.NewInt(7),
					Amount:           big.NewInt(7),
				},
			},
			expected: result{"", false},
		},
	}

	for name, test := range deposits {
		test := test // NOTE: uncomment for Go < 1.22, see /doc/faq#closures_and_goroutines
		t.Run(name, func(t *testing.T) {
			t.Parallel() // marks each test case as capable of running in parallel with each other
			t.Log(name)

			key, relevant := relevant[*NativeDeposit](&test.input, mocks.transferVerifier.Addresses)
			assert.Equal(t, test.expected.key, key)
			assert.Equal(t, test.expected.relevant, relevant)

			if key == "" {
				assert.False(t, relevant, "key must be empty for irrelevant transfers, but got ", key)
			} else {
				assert.True(t, relevant, "relevant must be true for non-empty keys")
			}
		})
	}

	for name, test := range transfers {
		test := test // NOTE: uncomment for Go < 1.22, see /doc/faq#closures_and_goroutines
		t.Run(name, func(t *testing.T) {
			t.Parallel() // marks each test case as capable of running in parallel with each other
			t.Log(name)

			key, relevant := relevant[*ERC20Transfer](&test.input, mocks.transferVerifier.Addresses)
			assert.Equal(t, test.expected.key, key)
			assert.Equal(t, test.expected.relevant, relevant)

			if key == "" {
				assert.False(t, relevant, "key must be empty for irrelevant transfers, but got ", key)
			} else {
				assert.True(t, relevant, "relevant must be true for non-empty keys")
			}
		})
	}

	for name, test := range messages {
		test := test // NOTE: uncomment for Go < 1.22, see /doc/faq#closures_and_goroutines
		t.Run(name, func(t *testing.T) {
			t.Parallel() // marks each test case as capable of running in parallel with each other
			t.Log(name)

			key, relevant := relevant[*LogMessagePublished](&test.input, mocks.transferVerifier.Addresses)
			assert.Equal(t, test.expected.key, key)
			assert.Equal(t, test.expected.relevant, relevant)

			if key == "" {
				assert.False(t, relevant, "key must be empty for irrelevant transfers, but got ", key)
			} else {
				assert.True(t, relevant, "relevant must be true for non-empty keys")
			}
		})
	}
}

func TestValidateDeposit(t *testing.T) {
	t.Parallel()

	invalidDeposits := map[string]struct {
		input NativeDeposit
	}{
		"invalid: zero-value for TokenAddress": {
			input: NativeDeposit{
				// TokenAddress:
				TokenChain: NATIVE_CHAIN_ID,
				Receiver:   tokenBridgeAddr,
				Amount:     big.NewInt(1),
			},
		},
		"invalid: zero-value for TokenChain": {
			input: NativeDeposit{
				TokenAddress: usdcAddr,
				// TokenChain:
				Receiver: tokenBridgeAddr,
				Amount:   big.NewInt(1),
			},
		},
		"invalid: zero-value for Receiver": {
			input: NativeDeposit{
				TokenAddress: usdcAddr,
				TokenChain:   NATIVE_CHAIN_ID,
				// Receiver:
				Amount: big.NewInt(1),
			},
		},
		"invalid: nil Amount": {
			input: NativeDeposit{
				TokenAddress: usdcAddr,
				TokenChain:   NATIVE_CHAIN_ID,
				Receiver:     tokenBridgeAddr,
				Amount:       nil,
			},
		},
		"invalid: negative Amount": {
			input: NativeDeposit{
				TokenAddress: usdcAddr,
				TokenChain:   NATIVE_CHAIN_ID,
				Receiver:     tokenBridgeAddr,
				Amount:       big.NewInt(-1),
			},
		},
	}

	for name, test := range invalidDeposits {
		test := test // NOTE: uncomment for Go < 1.22, see /doc/faq#closures_and_goroutines
		t.Run(name, func(t *testing.T) {
			t.Parallel() // marks each test case as capable of running in parallel with each other
			t.Log(name)

			err := validate[*NativeDeposit](&test.input)
			require.Error(t, err)
		})
	}

	validDeposits := map[string]struct {
		input NativeDeposit
	}{
		"valid": {
			input: NativeDeposit{
				TokenAddress: nativeAddr,
				TokenChain:   NATIVE_CHAIN_ID,
				Receiver:     tokenBridgeAddr,
				Amount:       big.NewInt(500),
			},
		},
	}

	for name, test := range validDeposits {
		test := test // NOTE: uncomment for Go < 1.22, see /doc/faq#closures_and_goroutines
		t.Run(name, func(t *testing.T) {
			t.Parallel() // marks each test case as capable of running in parallel with each other
			t.Log(name)

			err := validate[*NativeDeposit](&test.input)
			require.NoError(t, err)
		})
	}
}

func TestValidateERC20Transfer(t *testing.T) {
	t.Parallel()

	invalidTransfers := map[string]struct {
		input ERC20Transfer
	}{
		"invalid: zero-value for TokenAddress": {
			input: ERC20Transfer{
				// TokenAddress:
				TokenChain: NATIVE_CHAIN_ID,
				To:         tokenBridgeAddr,
				From:       eoaAddrGeth,
				Amount:     big.NewInt(1),
			},
		},
		"invalid: zero-value for TokenChain": {
			input: ERC20Transfer{
				TokenAddress: usdcAddr,
				// TokenChain:
				To:     tokenBridgeAddr,
				From:   eoaAddrGeth,
				Amount: big.NewInt(1),
			},
		},
		// Note: transfer's To and From values are allowed to be the zero address.
		"invalid: nil Amount": {
			input: ERC20Transfer{
				TokenAddress: usdcAddr,
				TokenChain:   NATIVE_CHAIN_ID,
				From:         eoaAddrGeth,
				To:           tokenBridgeAddr,
				Amount:       nil,
			},
		},
		"invalid: negative Amount": {
			input: ERC20Transfer{
				TokenAddress: usdcAddr,
				TokenChain:   NATIVE_CHAIN_ID,
				From:         eoaAddrGeth,
				To:           tokenBridgeAddr,
				Amount:       big.NewInt(-1),
			},
		},
	}

	for name, test := range invalidTransfers {
		test := test // NOTE: uncomment for Go < 1.22, see /doc/faq#closures_and_goroutines
		t.Run(name, func(t *testing.T) {
			t.Parallel() // marks each test case as capable of running in parallel with each other
			t.Log(name)

			err := validate[*ERC20Transfer](&test.input)
			require.Error(t, err)
			assert.ErrorContains(t, err, "invalid log")
		})
	}

	validTransfers := map[string]struct {
		input ERC20Transfer
	}{
		"valid": {
			input: ERC20Transfer{
				TokenAddress: usdcAddr,
				TokenChain:   NATIVE_CHAIN_ID,
				To:           tokenBridgeAddr,
				From:         eoaAddrGeth,
				Amount:       big.NewInt(100),
			},
		},
		"valid: zero-value for From (possible Transfer event from non-ERC20 contract)": {
			input: ERC20Transfer{
				TokenAddress: usdcAddr,
				TokenChain:   NATIVE_CHAIN_ID,
				From:         ZERO_ADDRESS,
				To:           tokenBridgeAddr,
				Amount:       big.NewInt(1),
			},
		},
		"valid: zero-value for To (burning funds)": {
			input: ERC20Transfer{
				TokenAddress: usdcAddr,
				TokenChain:   NATIVE_CHAIN_ID,
				From:         tokenBridgeAddr,
				To:           ZERO_ADDRESS,
				Amount:       big.NewInt(1),
			},
		},
	}

	for name, test := range validTransfers {
		test := test // NOTE: uncomment for Go < 1.22, see /doc/faq#closures_and_goroutines
		t.Run(name, func(t *testing.T) {
			t.Parallel() // marks each test case as capable of running in parallel with each other
			t.Log(name)

			err := validate[*ERC20Transfer](&test.input)
			require.NoError(t, err)
		})
	}
}

func TestValidateLogMessagePublished(t *testing.T) {
	t.Parallel()

	invalidMessages := map[string]struct {
		input LogMessagePublished
	}{
		"invalid: zero-value for EventEmitter": {
			input: LogMessagePublished{
				// EventEmitter: coreBridgeAddr,
				MsgSender: tokenBridgeAddr,
				TransferDetails: &TransferDetails{
					PayloadType:      TransferTokens,
					OriginAddressRaw: usdcAddr.Bytes(),
					TokenChain:       NATIVE_CHAIN_ID,
					OriginAddress:    usdcAddr,
					TargetAddress:    eoaAddrVAA,
					AmountRaw:        big.NewInt(7),
					Amount:           big.NewInt(7),
				},
			},
		},
		"invalid: zero-value for MsgSender": {
			input: LogMessagePublished{
				EventEmitter: coreBridgeAddr,
				// MsgSender:    tokenBridgeAddr,
				TransferDetails: &TransferDetails{
					PayloadType:      TransferTokens,
					OriginAddressRaw: usdcAddr.Bytes(),
					TokenChain:       NATIVE_CHAIN_ID,
					OriginAddress:    usdcAddr,
					TargetAddress:    eoaAddrVAA,
					AmountRaw:        big.NewInt(7),
					Amount:           big.NewInt(7),
				},
			},
		},
		"invalid: zero-value for TransferDetails": {
			input: LogMessagePublished{
				EventEmitter: coreBridgeAddr,
				MsgSender:    tokenBridgeAddr,
				// TransferDetails: &TransferDetails{
				// 	PayloadType:     TransferTokens,
				// 	OriginAddressRaw: usdcAddr,
				// 	TokenChain:      NATIVE_CHAIN_ID,
				// 	OriginAddress:   eoaAddrGeth,
				// 	TargetAddress:   eoaAddrVAA,
				// 	AmountRaw:       big.NewInt(7),
				// 	Amount:          big.NewInt(7),
				// },
			},
		},
		"invalid: zero-value for PayloadType": {
			input: LogMessagePublished{
				EventEmitter: coreBridgeAddr,
				MsgSender:    tokenBridgeAddr,
				TransferDetails: &TransferDetails{
					// PayloadType:     TransferTokens,
					OriginAddressRaw: usdcAddr.Bytes(),
					TokenChain:       NATIVE_CHAIN_ID,
					OriginAddress:    usdcAddr,
					TargetAddress:    eoaAddrVAA,
					AmountRaw:        big.NewInt(7),
					Amount:           big.NewInt(7),
				},
			},
		},
		"invalid: zero-value for OriginAddressRaw": {
			input: LogMessagePublished{
				EventEmitter: coreBridgeAddr,
				MsgSender:    tokenBridgeAddr,
				TransferDetails: &TransferDetails{
					PayloadType: TransferTokens,
					// OriginAddressRaw: erc20Addr,
					TokenChain:    NATIVE_CHAIN_ID,
					OriginAddress: usdcAddr,
					TargetAddress: eoaAddrVAA,
					AmountRaw:     big.NewInt(7),
					Amount:        big.NewInt(7),
				},
			},
		},
		"invalid: zero-value for TokenChain": {
			input: LogMessagePublished{
				EventEmitter: coreBridgeAddr,
				MsgSender:    tokenBridgeAddr,
				TransferDetails: &TransferDetails{
					PayloadType:      TransferTokens,
					OriginAddressRaw: usdcAddr.Bytes(),
					// TokenChain:      NATIVE_CHAIN_ID,
					OriginAddress: usdcAddr,
					TargetAddress: eoaAddrVAA,
					AmountRaw:     big.NewInt(7),
					Amount:        big.NewInt(7),
				},
			},
		},
		// OriginAddress may be zero for unwrapped assets without a wrapped entry?
		// "invalid: zero-value for OriginAddress": {
		// 	input: LogMessagePublished{
		// 		EventEmitter: coreBridgeAddr,
		// 		MsgSender:    tokenBridgeAddr,
		// 		TransferDetails: &TransferDetails{
		// 			PayloadType:      TransferTokens,
		// 			OriginAddressRaw: usdcAddr,
		// 			TokenChain:       NATIVE_CHAIN_ID,
		// 			// OriginAddress:   usdcAddr,
		// 			TargetAddress: eoaAddrVAA,
		// 			AmountRaw:     big.NewInt(7),
		// 			Amount:        big.NewInt(7),
		// 		},
		// 	},
		// },
		"invalid: zero-value for TargetAddress": {
			input: LogMessagePublished{
				EventEmitter: coreBridgeAddr,
				MsgSender:    tokenBridgeAddr,
				TransferDetails: &TransferDetails{
					PayloadType:      TransferTokens,
					OriginAddressRaw: usdcAddr.Bytes(),
					TokenChain:       NATIVE_CHAIN_ID,
					OriginAddress:    usdcAddr,
					// TargetAddress:   eoaAddrVAA,
					AmountRaw: big.NewInt(7),
					Amount:    big.NewInt(7),
				},
			},
		},
		"invalid: nil AmountRaw": {
			input: LogMessagePublished{
				EventEmitter: coreBridgeAddr,
				MsgSender:    tokenBridgeAddr,
				TransferDetails: &TransferDetails{
					PayloadType:      TransferTokens,
					OriginAddressRaw: usdcAddr.Bytes(),
					TokenChain:       NATIVE_CHAIN_ID,
					OriginAddress:    usdcAddr,
					TargetAddress:    eoaAddrVAA,
					// AmountRaw:       big.NewInt(7),
					Amount: big.NewInt(7),
				},
			},
		},
		"invalid: negative AmountRaw": {
			input: LogMessagePublished{
				EventEmitter: coreBridgeAddr,
				MsgSender:    tokenBridgeAddr,
				TransferDetails: &TransferDetails{
					PayloadType:      TransferTokens,
					OriginAddressRaw: usdcAddr.Bytes(),
					TokenChain:       NATIVE_CHAIN_ID,
					OriginAddress:    usdcAddr,
					TargetAddress:    eoaAddrVAA,
					AmountRaw:        big.NewInt(-1),
					Amount:           big.NewInt(7),
				},
			},
		},
		"invalid: nil Amount": {
			input: LogMessagePublished{
				EventEmitter: coreBridgeAddr,
				MsgSender:    tokenBridgeAddr,
				TransferDetails: &TransferDetails{
					PayloadType:      TransferTokens,
					OriginAddressRaw: usdcAddr.Bytes(),
					TokenChain:       NATIVE_CHAIN_ID,
					OriginAddress:    usdcAddr,
					TargetAddress:    eoaAddrVAA,
					AmountRaw:        big.NewInt(7),
					// Amount:          big.NewInt(7),
				},
			},
		},
		"invalid: negative Amount": {
			input: LogMessagePublished{
				EventEmitter: coreBridgeAddr,
				MsgSender:    tokenBridgeAddr,
				TransferDetails: &TransferDetails{
					PayloadType:      TransferTokens,
					OriginAddressRaw: usdcAddr.Bytes(),
					TokenChain:       NATIVE_CHAIN_ID,
					OriginAddress:    usdcAddr,
					TargetAddress:    eoaAddrVAA,
					AmountRaw:        big.NewInt(7),
					Amount:           big.NewInt(-1),
				},
			},
		},
	}

	for name, test := range invalidMessages {
		test := test // NOTE: uncomment for Go < 1.22, see /doc/faq#closures_and_goroutines
		t.Run(name, func(t *testing.T) {
			t.Parallel() // marks each test case as capable of running in parallel with each other
			t.Log(name)

			err := validate[*LogMessagePublished](&test.input)
			require.Error(t, err)
			_, ok := err.(*InvalidLogError)
			assert.True(t, ok, "wrong error type: ", err.Error())
		})
	}

	validTransfers := map[string]struct {
		input LogMessagePublished
	}{
		"valid and relevant": {
			input: LogMessagePublished{
				EventEmitter: coreBridgeAddr,
				MsgSender:    tokenBridgeAddr,
				TransferDetails: &TransferDetails{
					PayloadType:      TransferTokens,
					OriginAddressRaw: usdcAddr.Bytes(),
					TokenChain:       NATIVE_CHAIN_ID,
					OriginAddress:    eoaAddrGeth,
					TargetAddress:    eoaAddrVAA,
					AmountRaw:        big.NewInt(7),
					Amount:           big.NewInt(7),
				},
			},
		},
		"valid and irrelevant": {
			input: LogMessagePublished{
				EventEmitter: usdcAddr,
				MsgSender:    eoaAddrGeth,
				TransferDetails: &TransferDetails{
					PayloadType:      TransferTokensWithPayload,
					OriginAddressRaw: usdcAddr.Bytes(),
					TokenChain:       NATIVE_CHAIN_ID,
					OriginAddress:    eoaAddrGeth,
					TargetAddress:    eoaAddrVAA,
					AmountRaw:        big.NewInt(7),
					Amount:           big.NewInt(7),
				},
			},
		},
	}

	for name, test := range validTransfers {
		test := test // NOTE: uncomment for Go < 1.22, see /doc/faq#closures_and_goroutines
		t.Run(name, func(t *testing.T) {
			t.Parallel() // marks each test case as capable of running in parallel with each other
			t.Log(name)

			err := validate[*LogMessagePublished](&test.input)
			require.NoError(t, err)
		})
	}
}

func TestCmp(t *testing.T) {

	t.Parallel()

	// Table-driven tests were not used here because the function takes generic types which are awkward to declare
	// in that format.

	// Test identity
	assert.Zero(t, cmp(ZERO_ADDRESS, ZERO_ADDRESS))
	assert.Zero(t, cmp(ZERO_ADDRESS_VAA, ZERO_ADDRESS))

	// Test mixed types
	assert.Zero(t, cmp(ZERO_ADDRESS, ZERO_ADDRESS_VAA))
	assert.Zero(t, cmp(ZERO_ADDRESS_VAA, ZERO_ADDRESS_VAA))

	vaaAddr, err := vaa.BytesToAddress([]byte{0x01})
	require.NoError(t, err)
	assert.Zero(t, cmp(vaaAddr, common.BytesToAddress([]byte{0x01})))

	vaaAddr, err = vaa.BytesToAddress([]byte{0xff, 0x02})
	require.NoError(t, err)
	assert.Zero(t, cmp(common.BytesToAddress([]byte{0xff, 0x02}), vaaAddr))
}

func TestVAAFromAddr(t *testing.T) {

	t.Parallel()

	// Test values. Declared here in order to silence error values from the vaa functions.
	vaa1, _ := vaa.BytesToAddress([]byte{0xff, 0x02})
	vaa2, _ := vaa.StringToAddress("0000000000000000000000002260fac5e5542a773aa44fbcfedf7c193bc2c599")

	tests := map[string]struct {
		input    common.Address
		expected vaa.Address
	}{
		"valid, arbitrary": {
			input:    common.BytesToAddress([]byte{0xff, 0x02}),
			expected: vaa1,
		},
		"valid, zero values": {
			input:    ZERO_ADDRESS,
			expected: ZERO_ADDRESS_VAA,
		},
		"valid, string-based": {
			input:    common.HexToAddress("0x2260fac5e5542a773aa44fbcfedf7c193bc2c599"),
			expected: vaa2,
		},
	}

	for name, test := range tests {
		test := test // NOTE: uncomment for Go < 1.22, see /doc/faq#closures_and_goroutines
		t.Run(name, func(t *testing.T) {
			t.Parallel() // marks each test case as capable of running in parallel with each other
			t.Log(name)

			res := VAAAddrFrom(test.input)
			assert.Equal(t, test.expected, res)
			assert.Zero(t, bytes.Compare(res[:], common.LeftPadBytes(test.input.Bytes(), EVM_WORD_LENGTH)))
		})
	}

}
