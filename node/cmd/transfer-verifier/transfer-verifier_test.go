package transferverifier
import (
	"testing"
	"math/big"
	// "github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

)

func TestAmountLikelyNormalized(t *testing.T) {
	t.Parallel() // marks TLog as capable of running in parallel with other tests
	tests := map[string] struct {
		larger *big.Int
		smaller *big.Int
		expected bool
	} {
		"happy path":  {
			larger: big.NewInt(123000),
			smaller: big.NewInt(123),
			expected: true,
		},
		"amounts do not match":  {
			larger: big.NewInt(123000),
			smaller: big.NewInt(456),
			expected: false,
		},
		// "one character": {
		//   input: "x",
		//   result: "x",
		// },
		// "one multi byte glyph": {
		//   input: "🎉",
		//   result: "🎉",
		// },
		// "string with multiple multi-byte glyphs": {
		//   input: "🥳🎉🐶",
		//   result: "🐶🎉🥳",
		// },
	}
	for name, test := range tests {
		test := test // NOTE: uncomment for Go < 1.22, see /doc/faq#closures_and_goroutines
		t.Run(name, func(t *testing.T) {
			t.Parallel() // marks each test case as capable of running in parallel with each other 
			t.Log(name)

			if got, err := amountLikelyNormalized(test.larger, test.smaller); got != test.expected {
				require.NoError(t, err)
				t.Fatalf("amountLikelyNormalized(%s, %s) returned %t; expected %t",
					test.larger,
					test.smaller,
					got,
					test.expected,
				)
			}
	
		})
    }
}
