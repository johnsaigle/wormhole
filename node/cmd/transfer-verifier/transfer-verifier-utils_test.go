package transferverifier

import (
	"encoding/json"
	"math/big"
	"testing"
)

func TestExtractFromJsonPath(t *testing.T) {
	testcases := []struct {
		name     string
		data     json.RawMessage
		path     string
		expected interface{}
		wantErr  bool
		typ      string
	}{
		{
			name:     "ValidPathString",
			data:     json.RawMessage(`{"key1": {"key2": "value"}}`),
			path:     "key1.key2",
			expected: "value",
			wantErr:  false,
			typ:      "string",
		},
		{
			name:     "ValidPathFloat",
			data:     json.RawMessage(`{"key1": {"key2": 123.45}}`),
			path:     "key1.key2",
			expected: 123.45,
			wantErr:  false,
			typ:      "float64",
		},
		{
			name:     "InvalidPath",
			data:     json.RawMessage(`{"key1": {"key2": "value"}}`),
			path:     "key1.key3",
			expected: nil,
			wantErr:  true,
			typ:      "string",
		},
		{
			name:     "NestedPath",
			data:     json.RawMessage(`{"key1": {"key2": {"key3": "value"}}}`),
			path:     "key1.key2.key3",
			expected: "value",
			wantErr:  false,
			typ:      "string",
		},
		{
			name:     "EmptyPath",
			data:     json.RawMessage(`{"key1": {"key2": "value"}}`),
			path:     "",
			expected: nil,
			wantErr:  true,
			typ:      "string",
		},
		{
			name:     "NonExistentPath",
			data:     json.RawMessage(`{"key1": {"key2": "value"}}`),
			path:     "key3.key4",
			expected: nil,
			wantErr:  true,
			typ:      "string",
		},
		{
			name:     "MalformedJson",
			data:     json.RawMessage(`{"key1": {"key2": "value"`),
			path:     "key1.key2",
			expected: nil,
			wantErr:  true,
			typ:      "string",
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			var result interface{}
			var err error
			switch tt.typ {
			case "string":
				var res string
				res, err = extractFromJsonPath[string](tt.data, tt.path)
				result = res
			case "float64":
				var res float64
				res, err = extractFromJsonPath[float64](tt.data, tt.path)
				result = res
			default:
				t.Fatalf("Unsupported type: %v", tt.typ)
			}

			if (err != nil) != tt.wantErr {
				t.Errorf("Expected error: %v, got: %v", tt.wantErr, err)
			}
			if !tt.wantErr && result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestNormalize(t *testing.T) {
	testcases := []struct {
		name     string
		amount   *big.Int
		decimals uint8
		expected *big.Int
	}{
		{
			name:     "AmountWithMoreThan8Decimals",
			amount:   big.NewInt(1000000000000000000),
			decimals: 18,
			expected: big.NewInt(100000000),
		},
		{
			name:     "AmountWithExactly8Decimals",
			amount:   big.NewInt(12345678),
			decimals: 8,
			expected: big.NewInt(12345678),
		},
		{
			name:     "AmountWithLessThan8Decimals",
			amount:   big.NewInt(12345),
			decimals: 5,
			expected: big.NewInt(12345),
		},
		{
			name:     "AmountWithZeroDecimals",
			amount:   big.NewInt(12345678),
			decimals: 0,
			expected: big.NewInt(12345678),
		},
		{
			name:     "AmountWith9Decimals",
			amount:   big.NewInt(123456789),
			decimals: 9,
			expected: big.NewInt(12345678),
		},
		{
			name:     "AmountWith10Decimals",
			amount:   big.NewInt(1234567890),
			decimals: 10,
			expected: big.NewInt(12345678),
		},
		{
			name:     "AmountEqualsNil",
			amount:   nil,
			decimals: 18,
			expected: nil,
		},
	}

	for _, tt := range testcases {
		t.Run(tt.name, func(t *testing.T) {
			result := normalize(tt.amount, tt.decimals)
			if result.Cmp(tt.expected) != 0 {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}
