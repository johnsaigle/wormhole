package transferverifier
import (
	"testing"
	"math/big"
	// "github.com/stretchr/testify/assert"
	// "github.com/stretchr/testify/require"
)

func TestDenormalize(t *testing.T) {
	t.Parallel() // marks TLog as capable of running in parallel with other tests
	tests := map[string] struct {
		amount *big.Int
		decimals uint8
		expected *big.Int
	} {
		"noop: decimals less than 8":  {
			amount: big.NewInt(123000),
			decimals: 1,
			expected:big.NewInt(123000), 
		},
		"noop: decimals equal to 8":  {
			amount: big.NewInt(123000),
			decimals: 8,
			expected:big.NewInt(123000), 
		},
		"denormalize: decimals greater than 8":  {
			amount:big.NewInt(123000), 
			decimals: 12,
			expected: big.NewInt(1230000000),
		},
		"denormalize: decimals at maximum expected size":  {
			amount: big.NewInt(123_000_000), 
			decimals: 18,
			expected: big.NewInt(1_230_000_000_000_000_000),
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
