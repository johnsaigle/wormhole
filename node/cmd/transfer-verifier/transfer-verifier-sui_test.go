package transferverifier

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wormhole-foundation/wormhole/sdk/vaa"
	"go.uber.org/zap"
)

func StringPtr[T any](v T) *T {
	return &v
}

func InitTestValues() {
	suiCoreContract = "0x5306f64e312b581766351c07af79c72fcb1cd25147157fdc2f8ad76de9a3fb6a"
	suiTokenBridgeEmitter = "0xccceeb29348f71bdd22ffef43a2a19c1f5b5e17c5cca5411529120182672ade5"
	suiMoveEventType = fmt.Sprintf("%s::publish_message::WormholeMessage", suiCoreContract)
	suiTokenBridgeContract = "0x26efee2b51c911237888e5dc6702868abca3c7ac12c53f76ef8eba0697695e3d"
}

func TestParseTxForCoinTypesBase(t *testing.T) {

	InitTestValues()

	var changes []SuiObjectChanges

	version := "339405977"
	previousVersion := "339405976"
	coinType := "0x5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93bf::coin::COIN" // USDC

	// Wrapped Asset
	change1 := SuiObjectChanges{
		ObjectId:        "0xf8f80c0d569fb076adb5fdc3a717dcb9ac14f7fd7512dc17efbf0f80a8b7fa8a",
		ObjectType:      fmt.Sprintf("0x2::dynamic_field::Field<%s::token_registry::Key<%s>, %s::wrapped_asset::WrappedAsset<%s>>", suiTokenBridgeContract, coinType, suiTokenBridgeContract, coinType),
		Version:         version,
		PreviousVersion: previousVersion,
	}
	change1.Owner.Owner = "0x334881831bd89287554a6121087e498fa023ce52c037001b53a4563a00a281a5"

	changes = append(changes, change1)

	logger := zap.Must(zap.NewDevelopment())
	result, _ := parseTxForCoinTypes(changes, *logger)

	// Only 1 result
	assert.Equal(t, 1, len(result))
	entry := result[0]
	assert.Equal(t, entry.Version, version)
	assert.Equal(t, entry.PreviousVersion, previousVersion)
	assert.Equal(t, entry.IsWrapped, true)
	assert.Equal(t, entry.ID, change1.ObjectId)
	assert.Equal(t, entry.FullField, change1.ObjectType)
	assert.Equal(t, entry.CoinType, coinType)
}

func TestParseTxForCoinTypesBaseWrongPackageAndModule(t *testing.T) {
	var changes []SuiObjectChanges

	version := "339405977"
	previousVersion := "339405976"
	coinType := "0x5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93bf::coin::COIN" // USDC

	suiTokenBridgeContractFake := "0x1111111111111111111111111111111111111111111111111111111111111111"

	// Wrapped Asset
	baseChange := SuiObjectChanges{
		ObjectId:        "0xf8f80c0d569fb076adb5fdc3a717dcb9ac14f7fd7512dc17efbf0f80a8b7fa8a",
		ObjectType:      fmt.Sprintf("0x2::dynamic_field::Field<%s::token_registry::Key<%s>, %s::wrapped_asset::WrappedAsset<%s>>", suiTokenBridgeContractFake, coinType, suiTokenBridgeContract, coinType),
		Version:         version,
		PreviousVersion: previousVersion,
	}
	baseChange.Owner.Owner = "0x334881831bd89287554a6121087e498fa023ce52c037001b53a4563a00a281a5"

	changes = append(changes, baseChange)

	logger := zap.Must(zap.NewDevelopment())
	result, _ := parseTxForCoinTypes(changes, *logger)
	assert.Equal(t, 0, len(result))

	change1 := baseChange
	change1.ObjectType = fmt.Sprintf("0x2::dynamic_field::Field<%s::token_registry::Key<%s>, %s::wrapped_asset::WrappedAsset<%s>>", suiTokenBridgeContractFake, coinType, suiTokenBridgeContract, coinType)
	changes = append(changes[1:], change1)
	result, _ = parseTxForCoinTypes(changes, *logger)
	assert.Equal(t, 0, len(result))

	change2 := baseChange
	change2.ObjectType = fmt.Sprintf("0x2::dynamic_field::Field<%s::not_registry::Key<%s>, %s::wrapped_asset::WrappedAsset<%s>>", suiTokenBridgeContract, coinType, suiTokenBridgeContract, coinType)
	changes = append(changes[1:], change2)
	result, _ = parseTxForCoinTypes(changes, *logger)
	assert.Equal(t, 0, len(result))

	change3 := baseChange
	change3.ObjectType = fmt.Sprintf("0x2::dynamic_field::Field<%s::registry::Key<%s>, %s::not_wrapped_asset_module::WrappedAsset<%s>>", suiTokenBridgeContract, coinType, suiTokenBridgeContract, coinType)
	changes = append(changes[1:], change3)
	result, _ = parseTxForCoinTypes(changes, *logger)
	assert.Equal(t, 0, len(result))

	change4 := baseChange
	change4.ObjectType = fmt.Sprintf("0x2::dynamic_field::Field<%s::registry::Key<%s>, %s::wrapped_asset::NotWrappedAsssetType<%s>>", suiTokenBridgeContract, coinType, suiTokenBridgeContract, coinType)
	changes = append(changes[1:], change4)
	result, _ = parseTxForCoinTypes(changes, *logger)
	assert.Equal(t, 0, len(result))

	change5 := baseChange
	change5.ObjectType = fmt.Sprintf("0x2::not_dynamic_field::Field<%s::registry::Key<%s>, %s::wrapped_asset::WrappedAssset<%s>>", suiTokenBridgeContract, coinType, suiTokenBridgeContract, coinType)
	changes = append(changes[1:], change5)
	result, _ = parseTxForCoinTypes(changes, *logger)
	assert.Equal(t, 0, len(result))
}

func TestParseTxForCoinTypesParseMultipleChanges(t *testing.T) {

	InitTestValues()

	var changes []SuiObjectChanges

	version1 := "339405977"
	previousVersion1 := "339405976"
	coinType1 := "0x5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93bf::coin::COIN" // USDC

	version2 := "139405977"
	previousVersion2 := "139455976"
	coinType2 := "0x2::sui::SUI"

	// Wrapped Asset
	change1 := SuiObjectChanges{
		ObjectId:        "0xf8f80c0d569fb076adb5fdc3a717dcb9ac14f7fd7512dc17efbf0f80a8b7fa8a",
		ObjectType:      fmt.Sprintf("0x2::dynamic_field::Field<%s::token_registry::Key<%s>, %s::wrapped_asset::WrappedAsset<%s>>", suiTokenBridgeContract, coinType1, suiTokenBridgeContract, coinType1),
		Version:         version1,
		PreviousVersion: previousVersion1,
	}
	change1.Owner.Owner = "0x334881831bd89287554a6121087e498fa023ce52c037001b53a4563a00a281a5"

	change2 := SuiObjectChanges{
		ObjectId:        "0x831c45a8d512c9cf46e7a8a947f7cbbb5e0a59829aa72450ff26fb1873fd0e94",
		ObjectType:      fmt.Sprintf("0x2::dynamic_field::Field<%s::token_registry::Key<%s>, %s::native_asset::NativeAsset<%s>>", suiTokenBridgeContract, coinType2, suiTokenBridgeContract, coinType2),
		Version:         version2,
		PreviousVersion: previousVersion2,
	}
	change2.Owner.Owner = "0x334881831bd89287554a6121087e498fa023ce52c037001b53a4563a00a281a5"

	changes = append(changes, change1)
	changes = append(changes, change2)

	logger := zap.Must(zap.NewDevelopment())
	result, _ := parseTxForCoinTypes(changes, *logger)

	// Only 2 results
	assert.Equal(t, 2, len(result))
	entry := result[0]
	assert.Equal(t, entry.Version, version1)
	assert.Equal(t, entry.PreviousVersion, previousVersion1)
	assert.Equal(t, entry.IsWrapped, true)
	assert.Equal(t, entry.ID, change1.ObjectId)
	assert.Equal(t, entry.FullField, change1.ObjectType)
	assert.Equal(t, entry.CoinType, coinType1)

	entry2 := result[1]
	assert.Equal(t, entry2.Version, version2)
	assert.Equal(t, entry2.PreviousVersion, previousVersion2)
	assert.Equal(t, entry2.IsWrapped, false)
	assert.Equal(t, entry2.ID, change2.ObjectId)
	assert.Equal(t, entry2.FullField, change2.ObjectType)
	assert.Equal(t, entry2.CoinType, coinType2)
}

func TestParseEventsForWormholeBase(t *testing.T) {
	InitTestValues()

	var suiResults []SuiResult

	payload, _ := hex.DecodeString("01000000000000000000000000000000000000000000000000000000012b1d9451000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480002c7be3a35d5b3f85da514c24700a6c777f26b01a15211414a72a10787e5c9974a00160000000000000000000000000000000000000000000000000000000000000000")

	// Fields to be used for the call
	fields := FieldsData{
		Sender:   StringPtr(suiTokenBridgeEmitter),
		Sequence: StringPtr("111111"),
		// https://wormholescan.io/#/tx/8iLiTjfMdXkxJ4E5GBnFjmoZdCyhJVt8Am6FwWh2GL4D?network=Mainnet
		Payload: payload,
	}
	fieldsMarshalled, _ := json.Marshal(&fields)
	fieldsRaw := (*json.RawMessage)(&fieldsMarshalled)
	result1 := SuiResult{
		ID: struct {
			TxDigest *string `json:"txDigest"`
			EventSeq *string `json:"eventSeq"`
		}{
			TxDigest: StringPtr("A"),
			EventSeq: StringPtr("B"),
		},
		PackageID:         StringPtr(suiCoreContract),
		TransactionModule: StringPtr("post_message"),
		Sender:            StringPtr(suiTokenBridgeEmitter),
		Type:              StringPtr(suiMoveEventType),
		Bcs:               StringPtr("DK"),
		Timestamp:         StringPtr("DK"),
		Fields:            fieldsRaw,
	}
	suiResults = append(suiResults, result1)

	logger := zap.Must(zap.NewDevelopment())
	results, _ := parseEventsForWormhole(suiResults, suiMoveEventType, *logger)

	assert.Equal(t, 1, len(results))
	entry := results[0]
	assert.Equal(t, "21/ccceeb29348f71bdd22ffef43a2a19c1f5b5e17c5cca5411529120182672ade5/111111", entry.EventID)
	assert.Equal(t, 0, entry.Amount.Cmp(big.NewInt(5018326097)))

	// Check the token address
	tokenAddressRaw, _ := hex.DecodeString("000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
	tokenAddress, _ := vaa.BytesToAddress(tokenAddressRaw)
	assert.Equal(t, tokenAddress, entry.TokenAddress)

	// Check the token chain ID
	assert.Equal(t, uint16(2), entry.TokenChain)
}

func TestParseEventsForWormholeInvalid(t *testing.T) {
	InitTestValues()

	var suiResults []SuiResult

	payload, _ := hex.DecodeString("01000000000000000000000000000000000000000000000000000000012b1d9451000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480002c7be3a35d5b3f85da514c24700a6c777f26b01a15211414a72a10787e5c9974a00160000000000000000000000000000000000000000000000000000000000000000")

	// Fields to be used for the call
	fields := FieldsData{
		Sender:   StringPtr(suiTokenBridgeEmitter),
		Sequence: StringPtr("111111"),
		// https://wormholescan.io/#/tx/8iLiTjfMdXkxJ4E5GBnFjmoZdCyhJVt8Am6FwWh2GL4D?network=Mainnet
		Payload: payload,
	}
	fieldsMarshalled, _ := json.Marshal(&fields)
	fieldsRaw := (*json.RawMessage)(&fieldsMarshalled)
	baseResult := SuiResult{
		ID: struct {
			TxDigest *string `json:"txDigest"`
			EventSeq *string `json:"eventSeq"`
		}{
			TxDigest: StringPtr("A"),
			EventSeq: StringPtr("B"),
		},
		PackageID:         StringPtr(suiCoreContract),
		TransactionModule: StringPtr("post_message"),
		Sender:            StringPtr(suiTokenBridgeEmitter),
		Type:              StringPtr(suiMoveEventType),
		Bcs:               StringPtr("DK"),
		Timestamp:         StringPtr("DK"),
		Fields:            fieldsRaw,
	}
	suiResults = append(suiResults, baseResult)

	logger := zap.Must(zap.NewDevelopment())
	results, _ := parseEventsForWormhole(suiResults, suiMoveEventType, *logger)
	assert.Equal(t, 1, len(results))

	// Validate the sender of this call to be the token emitter
	result2 := baseResult
	fields2 := fields
	fields2.Sender = StringPtr("1111111111111111111111111111111111111111111111111111111111111111")
	fieldsMarshalled2, _ := json.Marshal(&fields2)
	fieldsRaw2 := (*json.RawMessage)(&fieldsMarshalled2)
	result2.Fields = fieldsRaw2
	suiResults = append(suiResults[1:], result2)
	results, _ = parseEventsForWormhole(suiResults, suiMoveEventType, *logger)
	assert.Equal(t, 0, len(results))

	// Check EventType. This checks that this event came from the proper contract of the proper type.
	result3 := baseResult
	result3.Type = StringPtr("1111111111111111111111111111111111111111111111111111111111111111::publish_message::WormholeMessage")
	suiResults = append(suiResults[1:], result3)
	results, _ = parseEventsForWormhole(suiResults, suiMoveEventType, *logger)
	assert.Equal(t, 0, len(results))
}

func TestParseEventsForWormholeMultipleValid(t *testing.T) {
	InitTestValues()

	var suiResults []SuiResult

	payload, _ := hex.DecodeString("01000000000000000000000000000000000000000000000000000000012b1d9451000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480002c7be3a35d5b3f85da514c24700a6c777f26b01a15211414a72a10787e5c9974a00160000000000000000000000000000000000000000000000000000000000000000")

	// Fields to be used for the call
	fields := FieldsData{
		Sender:   StringPtr(suiTokenBridgeEmitter),
		Sequence: StringPtr("111111"),
		// https://wormholescan.io/#/tx/8iLiTjfMdXkxJ4E5GBnFjmoZdCyhJVt8Am6FwWh2GL4D?network=Mainnet
		Payload: payload,
	}
	fieldsMarshalled, _ := json.Marshal(&fields)
	fieldsRaw := (*json.RawMessage)(&fieldsMarshalled)
	baseResult := SuiResult{
		ID: struct {
			TxDigest *string `json:"txDigest"`
			EventSeq *string `json:"eventSeq"`
		}{
			TxDigest: StringPtr("A"),
			EventSeq: StringPtr("B"),
		},
		PackageID:         StringPtr(suiCoreContract),
		TransactionModule: StringPtr("post_message"),
		Sender:            StringPtr(suiTokenBridgeEmitter),
		Type:              StringPtr(suiMoveEventType),
		Bcs:               StringPtr("DK"),
		Timestamp:         StringPtr("DK"),
		Fields:            fieldsRaw,
	}
	suiResults = append(suiResults, baseResult)

	result2 := baseResult
	payload2, _ := hex.DecodeString("030000000000000000000000000000000000000000000000000000000118244f009258181f5ceac8dbffb7030890243caed69a9599d2886d957a9cb7656af3bdb30015ae64091007e6ea18992097aa4fb68ee83f249ce912a8434f7d7e268804d98ff30c20e0d7df714c92c59dce2ddf508953e089a302f22dcae2ffe90035ea4b1038deaf7b22676174657761795f7472616e73666572223a7b22636861696e223a32302c226e6f6e6365223a343931382c22726563697069656e74223a2262334e74627a46334f546c6b4e6e6b79597a52324d6a6379626e526e4e327835636a686a4d6a4e684e444132635468796147677a5957526d62513d3d222c22666565223a2230227d7d")

	// Fields to be used for the call
	fields2 := FieldsData{
		Sender:   StringPtr(suiTokenBridgeEmitter),
		Sequence: StringPtr("222222"),
		// https://wormholescan.io/#/tx/8iLiTjfMdXkxJ4E5GBnFjmoZdCyhJVt8Am6FwWh2GL4D?network=Mainnet
		Payload: payload2,
	}
	fieldsMarshalled2, _ := json.Marshal(&fields2)
	fieldsRaw2 := (*json.RawMessage)(&fieldsMarshalled2)
	result2.Fields = fieldsRaw2
	suiResults = append(suiResults, result2)

	logger := zap.Must(zap.NewDevelopment())
	results, _ := parseEventsForWormhole(suiResults, suiMoveEventType, *logger)

	// Validate the results of the inputs
	assert.Equal(t, 2, len(results))
	entry1 := results[0]

	assert.Equal(t, "21/ccceeb29348f71bdd22ffef43a2a19c1f5b5e17c5cca5411529120182672ade5/111111", entry1.EventID)
	assert.Equal(t, 0, entry1.Amount.Cmp(big.NewInt(5018326097)))

	// Check the token address
	tokenAddressRaw, _ := hex.DecodeString("000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
	tokenAddress, _ := vaa.BytesToAddress(tokenAddressRaw)
	assert.Equal(t, tokenAddress, entry1.TokenAddress)

	// Check the token chain ID
	assert.Equal(t, uint16(2), entry1.TokenChain)

	entry2 := results[1]

	assert.Equal(t, "21/ccceeb29348f71bdd22ffef43a2a19c1f5b5e17c5cca5411529120182672ade5/222222", entry2.EventID)
	assert.Equal(t, 0, entry2.Amount.Cmp(big.NewInt(4700000000)))

	// Check the token address
	tokenAddressRaw2, _ := hex.DecodeString("9258181f5ceac8dbffb7030890243caed69a9599d2886d957a9cb7656af3bdb3")
	tokenAddress2, _ := vaa.BytesToAddress(tokenAddressRaw2)
	assert.Equal(t, tokenAddress2, entry2.TokenAddress)

	// Check the token chain ID
	assert.Equal(t, uint16(21), entry2.TokenChain)
}

func TestParseEventsForWormholeValidAndInvalid(t *testing.T) {
	InitTestValues()

	var suiResults []SuiResult

	payload, _ := hex.DecodeString("01000000000000000000000000000000000000000000000000000000012b1d9451000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480002c7be3a35d5b3f85da514c24700a6c777f26b01a15211414a72a10787e5c9974a00160000000000000000000000000000000000000000000000000000000000000000")

	// Fields to be used for the call
	fields := FieldsData{
		Sender:   StringPtr(suiTokenBridgeEmitter),
		Sequence: StringPtr("111111"),
		// https://wormholescan.io/#/tx/8iLiTjfMdXkxJ4E5GBnFjmoZdCyhJVt8Am6FwWh2GL4D?network=Mainnet
		Payload: payload,
	}
	fieldsMarshalled, _ := json.Marshal(&fields)
	fieldsRaw := (*json.RawMessage)(&fieldsMarshalled)
	baseResult := SuiResult{
		ID: struct {
			TxDigest *string `json:"txDigest"`
			EventSeq *string `json:"eventSeq"`
		}{
			TxDigest: StringPtr("A"),
			EventSeq: StringPtr("B"),
		},
		PackageID:         StringPtr(suiCoreContract),
		TransactionModule: StringPtr("post_message"),
		Sender:            StringPtr(suiTokenBridgeEmitter),
		Type:              StringPtr(suiMoveEventType),
		Bcs:               StringPtr("DK"),
		Timestamp:         StringPtr("DK"),
		Fields:            fieldsRaw,
	}
	suiResults = append(suiResults, baseResult)

	result2 := baseResult
	payload2, _ := hex.DecodeString("030000000000000000000000000000000000000000000000000000000118244f009258181f5ceac8dbffb7030890243caed69a9599d2886d957a9cb7656af3bdb30015ae64091007e6ea18992097aa4fb68ee83f249ce912a8434f7d7e268804d98ff30c20e0d7df714c92c59dce2ddf508953e089a302f22dcae2ffe90035ea4b1038deaf7b22676174657761795f7472616e73666572223a7b22636861696e223a32302c226e6f6e6365223a343931382c22726563697069656e74223a2262334e74627a46334f546c6b4e6e6b79597a52324d6a6379626e526e4e327835636a686a4d6a4e684e444132635468796147677a5957526d62513d3d222c22666565223a2230227d7d")

	// Fields to be used for the call
	fields2 := FieldsData{
		Sender:   StringPtr("1111111111111111111111111111111111111111111111111111111111111111"),
		Sequence: StringPtr("222222"),
		// https://wormholescan.io/#/tx/8iLiTjfMdXkxJ4E5GBnFjmoZdCyhJVt8Am6FwWh2GL4D?network=Mainnet
		Payload: payload2,
	}
	fieldsMarshalled2, _ := json.Marshal(&fields2)
	fieldsRaw2 := (*json.RawMessage)(&fieldsMarshalled2)
	result2.Fields = fieldsRaw2
	suiResults = append(suiResults, result2)

	logger := zap.Must(zap.NewDevelopment())
	results, _ := parseEventsForWormhole(suiResults, suiMoveEventType, *logger)

	// Validate the results of the inputs
	assert.Equal(t, 1, len(results))
	entry1 := results[0]

	assert.Equal(t, "21/ccceeb29348f71bdd22ffef43a2a19c1f5b5e17c5cca5411529120182672ade5/111111", entry1.EventID)
	assert.Equal(t, 0, entry1.Amount.Cmp(big.NewInt(5018326097)))

	// Check the token address
	tokenAddressRaw, _ := hex.DecodeString("000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
	tokenAddress, _ := vaa.BytesToAddress(tokenAddressRaw)
	assert.Equal(t, tokenAddress, entry1.TokenAddress)

	// Check the token chain ID
	assert.Equal(t, uint16(2), entry1.TokenChain)

}

/*
Test cases:
- Base simple
- Multiple
- Each has entry while the other doesn't
- token address bad
- token chain bad
- amount exceeds single
- amount exceeds AFTER multiple transfers
- Empty arrays
*/
func TestCompareTransfersBase(t *testing.T) {

	var amountChangedTracked = make(map[string]SuiAmountChanged)
	var wormholeTransferEvents []TransferDetailsSui

	amount := big.NewInt(1000 * int64(math.Pow(10, 8)))
	decimals := 8
	nativeDecimals := 18
	tokenChain := 2
	tokenAddressRaw, _ := hex.DecodeString("000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
	tokenAddress, _ := vaa.BytesToAddress(tokenAddressRaw)
	coinType := "0x5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93bf::coin::COIN"
	tokenKey := fmt.Sprintf("%d-%s", tokenChain, tokenAddress)
	eventID := fmt.Sprintf("21/%s/11111", suiTokenBridgeEmitter)
	amountChangedObj := SuiAmountChanged{Amount: amount, Decimals: uint8(decimals), NativeDecimals: uint8(nativeDecimals), TokenChain: uint16(tokenChain), TokenAddress: tokenAddress, CoinType: coinType}

	transferDetialSuiObj := TransferDetailsSui{
		TokenAddress: tokenAddress,
		TokenChain:   uint16(tokenChain),
		Amount:       amount,
		EventID:      eventID,
	}

	// Setup the objects for their list and maps for the call
	amountChangedTracked[tokenKey] = amountChangedObj
	wormholeTransferEvents = append(wormholeTransferEvents, transferDetialSuiObj)

	logger := zap.Must(zap.NewDevelopment())
	err := compareTransfers(amountChangedTracked, wormholeTransferEvents, *logger)
	assert.Equal(t, nil, err)
}

func TestCompareTransfersMultipleTokens(t *testing.T) {

	var amountChangedTracked = make(map[string]SuiAmountChanged)
	var wormholeTransferEvents []TransferDetailsSui

	amount := big.NewInt(1000 * int64(math.Pow(10, 8)))
	decimals := 8
	nativeDecimals := 18
	tokenChain := 2
	tokenAddressRaw, _ := hex.DecodeString("000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
	tokenAddress, _ := vaa.BytesToAddress(tokenAddressRaw)
	coinType := "0x5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93bf::coin::COIN"
	tokenKey := fmt.Sprintf("%d-%s", tokenChain, tokenAddress)
	eventID := fmt.Sprintf("21/%s/11111", suiTokenBridgeEmitter)
	amountChangedObj := SuiAmountChanged{Amount: amount, Decimals: uint8(decimals), NativeDecimals: uint8(nativeDecimals), TokenChain: uint16(tokenChain), TokenAddress: tokenAddress, CoinType: coinType}

	transferDetialSuiObj := TransferDetailsSui{
		TokenAddress: tokenAddress,
		TokenChain:   uint16(tokenChain),
		Amount:       amount,
		EventID:      eventID,
	}

	// Create the second object
	amountChangedObj2 := amountChangedObj
	tokenAddressRaw2, _ := hex.DecodeString("1111111111111111111111111111111111111111111111111111111111111111")
	tokenAddress2, _ := vaa.BytesToAddress(tokenAddressRaw2)
	amountChangedObj2.TokenAddress = tokenAddress2
	tokenChain2 := 3

	amount2 := big.NewInt(2000 * int64(math.Pow(10, 8)))
	amountChangedObj2.Amount = amount2
	amountChangedObj2.TokenChain = uint16(tokenChain2)
	tokenKey2 := fmt.Sprintf("%d-%s", tokenChain2, tokenAddress2)

	transferDetialSuiObj2 := transferDetialSuiObj
	transferDetialSuiObj2.Amount = amount2
	transferDetialSuiObj2.TokenAddress = tokenAddress2
	transferDetialSuiObj2.EventID = fmt.Sprintf("21/%s/222222", suiTokenBridgeEmitter)
	transferDetialSuiObj2.TokenChain = uint16(tokenChain2)

	// Setup the objects for their list and maps for the call
	amountChangedTracked[tokenKey] = amountChangedObj
	amountChangedTracked[tokenKey2] = amountChangedObj2

	wormholeTransferEvents = append(wormholeTransferEvents, transferDetialSuiObj)
	wormholeTransferEvents = append(wormholeTransferEvents, transferDetialSuiObj2)

	logger := zap.Must(zap.NewDevelopment())
	err := compareTransfers(amountChangedTracked, wormholeTransferEvents, *logger)
	assert.Equal(t, nil, err)
}

func TestCompareTransfersOverdrawAmount(t *testing.T) {

	var amountChangedTracked = make(map[string]SuiAmountChanged)
	var wormholeTransferEvents []TransferDetailsSui

	amount := big.NewInt(1000 * int64(math.Pow(10, 8)))
	evilAmount := big.NewInt(0).Mul(big.NewInt(100), amount)
	decimals := 8
	nativeDecimals := 18
	tokenChain := 2
	tokenAddressRaw, _ := hex.DecodeString("000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
	tokenAddress, _ := vaa.BytesToAddress(tokenAddressRaw)
	coinType := "0x5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93bf::coin::COIN"
	tokenKey := fmt.Sprintf("%d-%s", tokenChain, tokenAddress)
	eventID := fmt.Sprintf("21/%s/11111", suiTokenBridgeEmitter)
	amountChangedObj := SuiAmountChanged{Amount: amount, Decimals: uint8(decimals), NativeDecimals: uint8(nativeDecimals), TokenChain: uint16(tokenChain), TokenAddress: tokenAddress, CoinType: coinType}

	transferDetialSuiObj := TransferDetailsSui{
		TokenAddress: tokenAddress,
		TokenChain:   uint16(tokenChain),
		Amount:       evilAmount,
		EventID:      eventID,
	}

	// Setup the objects for their list and maps for the call
	amountChangedTracked[tokenKey] = amountChangedObj
	wormholeTransferEvents = append(wormholeTransferEvents, transferDetialSuiObj)

	// Should return an error because we're providing an extra amount than what can be verified
	logger := zap.Must(zap.NewDevelopment())
	err := compareTransfers(amountChangedTracked, wormholeTransferEvents, *logger)
	assert.NotEqual(t, nil, err)
}

func TestCompareTransfersDecimalsLarger(t *testing.T) {

	var amountChangedTracked = make(map[string]SuiAmountChanged)
	var wormholeTransferEvents []TransferDetailsSui

	amount := big.NewInt(1000 * int64(math.Pow(10, 8)))
	amountScaledDown := big.NewInt(100 * int64(math.Pow(10, 8)))

	decimals := 9 // Similar to the native Sui token
	nativeDecimals := 18
	tokenChain := 2
	tokenAddressRaw, _ := hex.DecodeString("000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
	tokenAddress, _ := vaa.BytesToAddress(tokenAddressRaw)
	coinType := "0x5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93bf::coin::COIN"
	tokenKey := fmt.Sprintf("%d-%s", tokenChain, tokenAddress)
	eventID := fmt.Sprintf("21/%s/11111", suiTokenBridgeEmitter)
	amountChangedObj := SuiAmountChanged{Amount: amount, Decimals: uint8(decimals), NativeDecimals: uint8(nativeDecimals), TokenChain: uint16(tokenChain), TokenAddress: tokenAddress, CoinType: coinType}

	transferDetialSuiObj := TransferDetailsSui{
		TokenAddress: tokenAddress,
		TokenChain:   uint16(tokenChain),
		Amount:       amountScaledDown,
		EventID:      eventID,
	}

	// Setup the objects for their list and maps for the call
	amountChangedTracked[tokenKey] = amountChangedObj
	wormholeTransferEvents = append(wormholeTransferEvents, transferDetialSuiObj)

	logger := zap.Must(zap.NewDevelopment())
	err := compareTransfers(amountChangedTracked, wormholeTransferEvents, *logger)
	assert.Equal(t, nil, err)
}

func TestCompareTransfersDecimalsSmaller(t *testing.T) {

	var amountChangedTracked = make(map[string]SuiAmountChanged)
	var wormholeTransferEvents []TransferDetailsSui

	amount := big.NewInt(1000 * int64(math.Pow(10, 8)))

	decimals := 6 // USDC, for instance. In this case, the AMOUNT shouldn't be scaled at all
	nativeDecimals := 18
	tokenChain := 2
	tokenAddressRaw, _ := hex.DecodeString("000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
	tokenAddress, _ := vaa.BytesToAddress(tokenAddressRaw)
	coinType := "0x5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93bf::coin::COIN"
	tokenKey := fmt.Sprintf("%d-%s", tokenChain, tokenAddress)
	eventID := fmt.Sprintf("21/%s/11111", suiTokenBridgeEmitter)
	amountChangedObj := SuiAmountChanged{Amount: amount, Decimals: uint8(decimals), NativeDecimals: uint8(nativeDecimals), TokenChain: uint16(tokenChain), TokenAddress: tokenAddress, CoinType: coinType}

	transferDetialSuiObj := TransferDetailsSui{
		TokenAddress: tokenAddress,
		TokenChain:   uint16(tokenChain),
		Amount:       amount,
		EventID:      eventID,
	}

	// Setup the objects for their list and maps for the call
	amountChangedTracked[tokenKey] = amountChangedObj
	wormholeTransferEvents = append(wormholeTransferEvents, transferDetialSuiObj)

	logger := zap.Must(zap.NewDevelopment())
	err := compareTransfers(amountChangedTracked, wormholeTransferEvents, *logger)
	assert.Equal(t, nil, err)
}

func TestCompareTransfersDoubleWithdrawalValid(t *testing.T) {

	var amountChangedTracked = make(map[string]SuiAmountChanged)
	var wormholeTransferEvents []TransferDetailsSui

	amount := big.NewInt(1000 * int64(math.Pow(10, 8)))
	decimals := 8
	nativeDecimals := 18
	tokenChain := 2
	tokenAddressRaw, _ := hex.DecodeString("000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
	tokenAddress, _ := vaa.BytesToAddress(tokenAddressRaw)
	coinType := "0x5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93bf::coin::COIN"
	tokenKey := fmt.Sprintf("%d-%s", tokenChain, tokenAddress)
	eventID := fmt.Sprintf("21/%s/11111", suiTokenBridgeEmitter)
	amountChangedObj := SuiAmountChanged{Amount: amount, Decimals: uint8(decimals), NativeDecimals: uint8(nativeDecimals), TokenChain: uint16(tokenChain), TokenAddress: tokenAddress, CoinType: coinType}

	// One third and two thirds respectively
	transferDetialSuiObj := TransferDetailsSui{
		TokenAddress: tokenAddress,
		TokenChain:   uint16(tokenChain),
		Amount:       big.NewInt(666 * int64(math.Pow(10, 8))),
		EventID:      eventID,
	}
	transferDetialSuiObj2 := TransferDetailsSui{
		TokenAddress: tokenAddress,
		TokenChain:   uint16(tokenChain),
		Amount:       big.NewInt(333 * int64(math.Pow(10, 8))),
		EventID:      eventID,
	}

	// Setup the objects for their list and maps for the call
	amountChangedTracked[tokenKey] = amountChangedObj // Only a single object but multiple Wormhole events
	wormholeTransferEvents = append(wormholeTransferEvents, transferDetialSuiObj)
	wormholeTransferEvents = append(wormholeTransferEvents, transferDetialSuiObj2)

	logger := zap.Must(zap.NewDevelopment())
	err := compareTransfers(amountChangedTracked, wormholeTransferEvents, *logger)
	assert.Equal(t, nil, err)
}

func TestCompareTransfersDoubleWithdrawalInValid(t *testing.T) {

	var amountChangedTracked = make(map[string]SuiAmountChanged)
	var wormholeTransferEvents []TransferDetailsSui

	amount := big.NewInt(1000 * int64(math.Pow(10, 8)))
	amount2 := big.NewInt(1000 * int64(math.Pow(10, 8)))

	decimals := 8
	nativeDecimals := 18
	tokenChain := 2
	tokenAddressRaw, _ := hex.DecodeString("000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
	tokenAddress, _ := vaa.BytesToAddress(tokenAddressRaw)
	coinType := "0x5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93bf::coin::COIN"
	tokenKey := fmt.Sprintf("%d-%s", tokenChain, tokenAddress)
	eventID := fmt.Sprintf("21/%s/11111", suiTokenBridgeEmitter)
	amountChangedObj := SuiAmountChanged{Amount: amount, Decimals: uint8(decimals), NativeDecimals: uint8(nativeDecimals), TokenChain: uint16(tokenChain), TokenAddress: tokenAddress, CoinType: coinType}

	// Amounts should be LARGER than the allowed amounts but NOT
	transferDetialSuiObj := TransferDetailsSui{
		TokenAddress: tokenAddress,
		TokenChain:   uint16(tokenChain),
		Amount:       amount,
		EventID:      eventID,
	}
	transferDetialSuiObj2 := TransferDetailsSui{
		TokenAddress: tokenAddress,
		TokenChain:   uint16(tokenChain),
		Amount:       amount2,
		EventID:      eventID,
	}

	// Setup the objects for their list and maps for the call
	amountChangedTracked[tokenKey] = amountChangedObj // Only a single object but multiple Wormhole events
	wormholeTransferEvents = append(wormholeTransferEvents, transferDetialSuiObj)
	wormholeTransferEvents = append(wormholeTransferEvents, transferDetialSuiObj2)

	logger := zap.Must(zap.NewDevelopment())
	err := compareTransfers(amountChangedTracked, wormholeTransferEvents, *logger)
	assert.NotEqual(t, nil, err)
}
