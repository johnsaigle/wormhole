package transferverifier

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// Extracts the value at the given path from the JSON object, and casts it to
// type T. If the path does not exist in the object, an error is returned.
func extractFromJsonPath[T any](data json.RawMessage, path string) (T, error) {
	var defaultT T

	var obj map[string]interface{}
	err := json.Unmarshal(data, &obj)
	if err != nil {
		return defaultT, err
	}

	// Split the path and iterate over the keys, except for the final key. For
	// each key, check if it exists in the object. If it does exist and is a map,
	// update the object to the value of the key.
	keys := strings.Split(path, ".")
	for _, key := range keys[:len(keys)-1] {
		if obj[key] == nil {
			return defaultT, fmt.Errorf("key %s not found", key)
		}
		obj = obj[key].(map[string]interface{})
	}

	// If the final key exists in the object, return the value as T. Otherwise,
	// return an error.
	if value, exists := obj[keys[len(keys)-1]]; exists {
		return value.(T), nil
	} else {
		return defaultT, fmt.Errorf("key %s not found", keys[len(keys)-1])
	}
}

// Normalize the amount to 8 decimals. If the amount has more than 8 decimals,
// the amount is divided by 10^(decimals-8). If the amount has less than 8
// decimals, the amount is returned as is.
func normalize(amount *big.Int, decimals uint8) (normalizedAmount *big.Int) {
	if decimals > MAX_DECIMALS {
		exponent := new(big.Int).SetInt64(int64(decimals - 8))
		multiplier := new(big.Int).Exp(new(big.Int).SetInt64(10), exponent, nil)
		normalizedAmount = new(big.Int).Div(amount, multiplier)
	} else {
		return amount
	}

	return normalizedAmount
}
