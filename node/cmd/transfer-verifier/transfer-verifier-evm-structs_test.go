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

func TestValidateDeposit(t *testing.T) {
	t.Parallel() 

	invalidDeposits := map[string]struct {
		input    NativeDeposit
	}{
		"invalid: zero-value for TokenAddress": {
			input:    NativeDeposit{
				// TokenAddress: 
				TokenChain: NATIVE_CHAIN_ID,
				Receiver: tokenBridgeAddr,
				Amount: big.NewInt(1),
			},
		},
		"invalid: zero-value for TokenChain": {
			input:    NativeDeposit{
				TokenAddress: erc20Addr,
				// TokenChain: 
				Receiver: tokenBridgeAddr,
				Amount: big.NewInt(1),
			},
		},
		"invalid: zero-value for Receiver": {
			input:    NativeDeposit{
				TokenAddress: erc20Addr,
				TokenChain: NATIVE_CHAIN_ID,
				// Receiver:
				Amount: big.NewInt(1),
			},
		},
		"invalid: nil Amount": {
			input:    NativeDeposit{
				TokenAddress: erc20Addr,
				TokenChain: NATIVE_CHAIN_ID,
				Receiver: tokenBridgeAddr,
				Amount: nil,
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
		input    NativeDeposit
	}{
		"valid": {
			input:    NativeDeposit{
				TokenAddress: nativeAddr,
				TokenChain: NATIVE_CHAIN_ID,
				Receiver: tokenBridgeAddr,
				Amount: big.NewInt(500),
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
		input    ERC20Transfer
	}{
		"invalid: zero-value for TokenAddress": {
			input:    ERC20Transfer{
				// TokenAddress: 
				TokenChain: NATIVE_CHAIN_ID,
				To: tokenBridgeAddr,
				From: eoaAddrGeth,
				Amount: big.NewInt(1),
			},
		},
		"invalid: zero-value for TokenChain": {
			input:    ERC20Transfer{
				TokenAddress: erc20Addr,
				// TokenChain: 
				To: tokenBridgeAddr,
				From: eoaAddrGeth,
				Amount: big.NewInt(1),
			},
		},
		"invalid: zero-value for From": {
			input:    ERC20Transfer{
				TokenAddress: erc20Addr,
				TokenChain: NATIVE_CHAIN_ID,
				// From:
				To: tokenBridgeAddr,
				Amount: big.NewInt(1),
			},
		},
		"invalid: zero-value for To": {
			input:    ERC20Transfer{
				TokenAddress: erc20Addr,
				TokenChain: NATIVE_CHAIN_ID,
				From: eoaAddrGeth,
				// To:
				Amount: big.NewInt(1),
			},
		},
		"invalid: nil Amount": {
			input:    ERC20Transfer{
				TokenAddress: erc20Addr,
				TokenChain: NATIVE_CHAIN_ID,
				From: eoaAddrGeth,
				// To:
				Amount: nil,
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
		})
	}

	validTransfers := map[string]struct {
		input    ERC20Transfer
	}{
		"valid": {
			input:    ERC20Transfer{
				TokenAddress: erc20Addr,
				TokenChain: NATIVE_CHAIN_ID,
				To: tokenBridgeAddr,
				From: eoaAddrGeth,
				Amount: big.NewInt(100),
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
