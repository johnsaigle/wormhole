package main

import (
	"fmt"
	"math"
)

// Mock vaa package types for testing
type ChainID uint16

const (
	ChainIDSolana   ChainID = 1
	ChainIDEthereum ChainID = 2
	GovernanceChain ChainID = 1
	MaxUint16               = math.MaxUint16
)

func ChainIDFromNumber(n interface{}) (ChainID, error) {
	var val uint64
	switch v := n.(type) {
	case int:
		if v < 0 {
			return 0, fmt.Errorf("chainID cannot be negative")
		}
		val = uint64(v)
	case int8:
		if v < 0 {
			return 0, fmt.Errorf("chainID cannot be negative")
		}
		val = uint64(v)
	case int16:
		if v < 0 {
			return 0, fmt.Errorf("chainID cannot be negative")
		}
		val = uint64(v)
	case int32:
		if v < 0 {
			return 0, fmt.Errorf("chainID cannot be negative")
		}
		val = uint64(v)
	case int64:
		if v < 0 {
			return 0, fmt.Errorf("chainID cannot be negative")
		}
		val = uint64(v)
	case uint:
		val = uint64(v)
	case uint8:
		val = uint64(v)
	case uint16:
		val = uint64(v)
	case uint32:
		val = uint64(v)
	case uint64:
		val = v
	default:
		return 0, fmt.Errorf("unsupported type for chainID")
	}

	if val > MaxUint16 {
		return 0, fmt.Errorf("chainID must be <= %d", MaxUint16)
	}
	return ChainID(val), nil
}

func KnownChainIDFromNumber(n interface{}) (ChainID, error) {
	id, err := ChainIDFromNumber(n)
	if err != nil {
		return 0, err
	}
	// Additional validation for known chains would go here
	return id, nil
}

// BAD: Direct cast without validation
func badDirectCast(userInput uint32) ChainID {
	return ChainID(userInput) // Will be flagged - no validation
}

// BAD: Direct cast in processing function
func processChainMessage(chainID uint32, msg string) {
	chain := ChainID(chainID) // Will be flagged - no validation in scope
	fmt.Printf("Processing message for chain %d: %s\n", chain, msg)
}

// GOOD: Using validation function in same scope
func goodWithValidation(userInput uint32) (ChainID, error) {
	// Validation function call in same scope
	validated, err := ChainIDFromNumber(userInput)
	if err != nil {
		return 0, err
	}

	// This cast is OK because validation happened in same function
	return ChainID(validated), nil
}

// GOOD: Using proper validation function
func goodWithKnownValidation(userInput uint32) (ChainID, error) {
	return KnownChainIDFromNumber(userInput) // Will NOT be flagged - uses validation
}

// GOOD: Constants are safe
func goodWithConstants() {
	chain1 := ChainID(ChainIDSolana)   // Will NOT be flagged - constant
	chain2 := ChainID(GovernanceChain) // Will NOT be flagged - constant
	chain3 := ChainID(1)               // Will NOT be flagged - literal

	fmt.Printf("Chains: %d, %d, %d\n", chain1, chain2, chain3)
}

// BAD: Mixed - validation exists but cast happens without checking result
func badMixedValidation(userInput uint32) ChainID {
	// Validation call exists in scope
	_, err := ChainIDFromNumber(userInput)
	if err != nil {
		panic(err)
	}

	// But this direct cast is still unsafe - what if userInput changed?
	return ChainID(userInput) // Will be flagged
}

// GOOD: Proper pattern - use the validated result
func goodProperPattern(userInput uint32) (ChainID, error) {
	// Validation call
	validated, err := ChainIDFromNumber(userInput)
	if err != nil {
		return 0, err
	}

	// Return the validated result, not a new cast
	return validated, nil // Will NOT be flagged
}

// EDGE CASE: Test file - might want to exclude
func testFunction() {
	// In test files, direct casts are often OK for setting up test data
	testChain := ChainID(999) // Might want to exclude test files
	fmt.Printf("Test chain: %d\n", testChain)
}

// GOOD: Function parameters that are already ChainID type
func processValidatedChain(chain ChainID) {
	fmt.Printf("Processing chain: %d\n", chain) // No cast needed
}

// ============================================================================
// COMPREHENSIVE TYPE TESTS - Testing all integer types for completeness
// ============================================================================

// BAD: Direct casts with signed integer types
func badSignedIntegerCasts() {
	var i8 int8 = 1
	var i16 int16 = 2
	var i32 int32 = 3
	var i64 int64 = 4
	var i int = 5

	chain8 := ChainID(i8)   // Will be flagged - no validation
	chain16 := ChainID(i16) // Will be flagged - no validation
	chain32 := ChainID(i32) // Will be flagged - no validation
	chain64 := ChainID(i64) // Will be flagged - no validation
	chainInt := ChainID(i)  // Will be flagged - no validation

	fmt.Printf("Chains: %d, %d, %d, %d, %d\n", chain8, chain16, chain32, chain64, chainInt)
}

// BAD: Direct casts with unsigned integer types
func badUnsignedIntegerCasts() {
	var u8 uint8 = 1
	var u16 uint16 = 2
	var u32 uint32 = 3
	var u64 uint64 = 4
	var u uint = 5

	chain8 := ChainID(u8)   // Will be flagged - no validation
	chain16 := ChainID(u16) // Will be flagged - no validation
	chain32 := ChainID(u32) // Will be flagged - no validation
	chain64 := ChainID(u64) // Will be flagged - no validation
	chainUint := ChainID(u) // Will be flagged - no validation

	fmt.Printf("Chains: %d, %d, %d, %d, %d\n", chain8, chain16, chain32, chain64, chainUint)
}

// BAD: Function parameters without validation
func badFunctionWithAllTypes(
	i8 int8, i16 int16, i32 int32, i64 int64, i int,
	u8 uint8, u16 uint16, u32 uint32, u64 uint64, u uint,
) {
	// All of these should be flagged - direct casts without validation
	chains := []ChainID{
		ChainID(i8),  // Will be flagged
		ChainID(i16), // Will be flagged
		ChainID(i32), // Will be flagged
		ChainID(i64), // Will be flagged
		ChainID(i),   // Will be flagged
		ChainID(u8),  // Will be flagged
		ChainID(u16), // Will be flagged
		ChainID(u32), // Will be flagged
		ChainID(u64), // Will be flagged
		ChainID(u),   // Will be flagged
	}

	for _, chain := range chains {
		fmt.Printf("Chain: %d\n", chain)
	}
}

// GOOD: Using validation with different types
func goodValidationWithAllTypes() {
	var i32 int32 = 1
	var u32 uint32 = 2
	var u64 uint64 = 3

	// Proper validation calls - these should NOT be flagged
	chain1, err1 := ChainIDFromNumber(i32)
	if err1 != nil {
		panic(err1)
	}

	chain2, err2 := KnownChainIDFromNumber(u32)
	if err2 != nil {
		panic(err2)
	}

	chain3, err3 := ChainIDFromNumber(u64)
	if err3 != nil {
		panic(err3)
	}

	fmt.Printf("Validated chains: %d, %d, %d\n", chain1, chain2, chain3)
}

// GOOD: Validation in same scope allows subsequent casts
func goodSameScopeValidation(input int64) (ChainID, error) {
	// Validation call in same function scope
	validated, err := ChainIDFromNumber(input)
	if err != nil {
		return 0, err
	}

	// This cast is safe because validation happened in same scope
	result := ChainID(validated) // Should NOT be flagged
	return result, nil
}

// BAD: Different variable, even with validation present
func badDifferentVariable(input1 int32, input2 int32) ChainID {
	// Validation exists in scope but for different variable
	_, err := ChainIDFromNumber(input1)
	if err != nil {
		panic(err)
	}

	// This cast is for a different variable - should be flagged
	return ChainID(input2) // Will be flagged
}

// EDGE CASE: Type conversions
func edgeCaseTypeConversions() {
	var f float64 = 1.0

	// These are unusual but possible type conversions
	chainFloat := ChainID(f) // Will be flagged - no validation
	// Note: bool to ChainID conversion requires explicit int conversion
	chainFromBool := ChainID(1) // Using literal instead since direct bool conversion doesn't compile

	fmt.Printf("Edge case chains: %d, %d\n", chainFloat, chainFromBool)
}

// GOOD: Small integer literals are safe
func goodSmallLiterals() {
	// Small literals should be safe
	chain1 := ChainID(0)     // Will NOT be flagged - literal
	chain2 := ChainID(1)     // Will NOT be flagged - literal
	chain3 := ChainID(65535) // Will NOT be flagged - literal (max uint16)

	fmt.Printf("Literal chains: %d, %d, %d\n", chain1, chain2, chain3)
}

// BAD: Large literals that could overflow
func badLargeLiterals() {
	// This demonstrates the problem with large values, but we can't actually compile
	// a literal that overflows uint16. In real code, this would come from variables.
	var largeValue uint32 = 65536
	chainBig := ChainID(largeValue) // Will be flagged - variable could overflow uint16

	fmt.Printf("Large literal chain: %d\n", chainBig)
}

// GOOD: Binary operations with constants
func goodBinaryOperationsWithConstants() {
	const baseChain = 1

	// Operations with constants should be safe
	chain1 := ChainID(baseChain + 1) // Will NOT be flagged - constant expression
	chain2 := ChainID(baseChain * 2) // Will NOT be flagged - constant expression

	fmt.Printf("Constant operation chains: %d, %d\n", chain1, chain2)
}

// BAD: Binary operations with variables
func badBinaryOperationsWithVariables(offset int) {
	const baseChain = 1

	// Operations involving variables should be flagged
	chain := ChainID(baseChain + offset) // Will be flagged - involves variable

	fmt.Printf("Variable operation chain: %d\n", chain)
}

// GOOD: Array/slice index with constants
func goodArrayAccess() {
	validChains := []uint16{1, 2, 3}

	// Constant index access should be safe if the array contains literals
	chain := ChainID(validChains[0]) // May be flagged depending on implementation

	fmt.Printf("Array access chain: %d\n", chain)
}

// BAD: Array/slice with dynamic index
func badDynamicArrayAccess(index int) {
	validChains := []uint16{1, 2, 3}

	// Dynamic index access should be flagged
	chain := ChainID(validChains[index]) // Will be flagged - dynamic access

	fmt.Printf("Dynamic array access chain: %d\n", chain)
}

// ============================================================================
// ADDITIONAL EDGE CASES AND REAL-WORLD PATTERNS
// ============================================================================

// BAD: Protobuf/gRPC common pattern - uint32 from external source
func badProtobufPattern(req interface{}) {
	// Simulating a protobuf message with ChainId uint32 field
	type Request struct {
		ChainId uint32
	}

	r := req.(*Request)

	// This is the exact pattern that causes problems in real code
	chain := ChainID(r.ChainId) // Will be flagged - external input without validation

	fmt.Printf("Protobuf chain: %d\n", chain)
}

// GOOD: Protobuf pattern with proper validation
func goodProtobufPattern(req interface{}) error {
	type Request struct {
		ChainId uint32
	}

	r := req.(*Request)

	// Proper validation of external input
	chain, err := ChainIDFromNumber(r.ChainId) // Will NOT be flagged - uses validation
	if err != nil {
		return fmt.Errorf("invalid chain ID: %w", err)
	}

	fmt.Printf("Validated protobuf chain: %d\n", chain)
	return nil
}

// BAD: JSON unmarshaling pattern
func badJSONUnmarshalPattern(data []byte) {
	type Message struct {
		Chain int `json:"chain"`
	}

	var msg Message
	// Assume json.Unmarshal happened here

	// Direct cast from JSON data - should be flagged
	chainID := ChainID(msg.Chain) // Will be flagged - external JSON data

	fmt.Printf("JSON chain: %d\n", chainID)
}

// GOOD: JSON pattern with validation
func goodJSONUnmarshalPattern(data []byte) error {
	type Message struct {
		Chain int `json:"chain"`
	}

	var msg Message
	// Assume json.Unmarshal happened here

	// Validate JSON data
	chainID, err := ChainIDFromNumber(msg.Chain) // Will NOT be flagged - uses validation
	if err != nil {
		return fmt.Errorf("invalid chain in JSON: %w", err)
	}

	fmt.Printf("Validated JSON chain: %d\n", chainID)
	return nil
}

// BAD: Network/RPC response pattern
func badNetworkResponsePattern(response map[string]interface{}) {
	// Common pattern when parsing network responses
	chainFloat, ok := response["chainId"].(float64) // JSON numbers come as float64
	if !ok {
		return
	}

	// Direct cast without validation - should be flagged
	chain := ChainID(chainFloat) // Will be flagged - network data without validation

	fmt.Printf("Network response chain: %d\n", chain)
}

// GOOD: Network response with validation
func goodNetworkResponsePattern(response map[string]interface{}) error {
	chainFloat, ok := response["chainId"].(float64)
	if !ok {
		return fmt.Errorf("missing chainId in response")
	}

	// Validate network data
	chain, err := ChainIDFromNumber(int64(chainFloat)) // Will NOT be flagged - uses validation
	if err != nil {
		return fmt.Errorf("invalid chainId in response: %w", err)
	}

	fmt.Printf("Validated network response chain: %d\n", chain)
	return nil
}

// BAD: Type assertion pattern
func badTypeAssertionPattern(value interface{}) {
	// Type assertions are common with interface{} values
	if chainInt, ok := value.(int32); ok {
		chain := ChainID(chainInt) // Will be flagged - type assertion without validation
		fmt.Printf("Type assertion chain: %d\n", chain)
	}
}

// GOOD: Type assertion with validation
func goodTypeAssertionPattern(value interface{}) error {
	if chainInt, ok := value.(int32); ok {
		chain, err := ChainIDFromNumber(chainInt) // Will NOT be flagged - uses validation
		if err != nil {
			return fmt.Errorf("invalid chain from type assertion: %w", err)
		}
		fmt.Printf("Validated type assertion chain: %d\n", chain)
	}
	return nil
}

// BAD: Mathematical operations
func badMathematicalOperations(base uint16) {
	offset := 10

	// Mathematical operations should be validated
	result := ChainID(base + uint16(offset)) // Will be flagged - math result without validation

	fmt.Printf("Math result chain: %d\n", result)
}

// GOOD: Constants in math operations (edge case)
func goodConstantMathOperations() {
	const base = 1
	const offset = 1

	// Pure constant operations might be safe
	result := ChainID(base + offset) // May or may not be flagged depending on implementation

	fmt.Printf("Constant math chain: %d\n", result)
}
