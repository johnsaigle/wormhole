package transferverifier

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/wormhole-foundation/wormhole/sdk/vaa"
	"go.uber.org/zap"
)

// Tokens
const (
	EthereumUsdcAddress = "000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
	SuiUsdcAddress      = "5d4b302506645c37ff133b98c4b50a5ae14841659738d6d733d59d0d217a93bf"
)

func initGlobals() {
	*suiCoreContract = "0x5306f64e312b581766351c07af79c72fcb1cd25147157fdc2f8ad76de9a3fb6a"
	*suiTokenBridgeContract = "0x26efee2b51c911237888e5dc6702868abca3c7ac12c53f76ef8eba0697695e3d"
	*suiTokenBridgeEmitter = "0xccceeb29348f71bdd22ffef43a2a19c1f5b5e17c5cca5411529120182672ade5"
	suiEventType = fmt.Sprintf("%s::%s::%s", *suiCoreContract, suiModule, suiEventName)
}

type MockSuiApiConnection struct {
	// The events to be returned by QueryEvents
	Events []SuiEvent
}

func NewMockSuiApiConnection(events []SuiEvent) SuiApiInterface {
	return &MockSuiApiConnection{
		Events: events,
	}
}

func (mock *MockSuiApiConnection) SetEvents(events []SuiEvent) {
	mock.Events = events
}

func (mock *MockSuiApiConnection) QueryEvents(filter string, cursor string, limit int, descending bool) (SuiQueryEventsResponse, error) {
	return SuiQueryEventsResponse{}, nil
}

func (mock *MockSuiApiConnection) GetTransactionBlock(txDigest string) (SuiGetTransactionBlockResponse, error) {
	return SuiGetTransactionBlockResponse{}, nil
}
func (mock *MockSuiApiConnection) TryMultiGetPastObjects(objectId string, version string, previousVersion string) (SuiTryMultiGetPastObjectsResponse, error) {
	return SuiTryMultiGetPastObjectsResponse{}, nil
}

func TestNewSuiApiConnection(t *testing.T) {
	sampleUrl := "http://localhost:8080"

	api := NewSuiApiConnection(sampleUrl)
	assert.Equal(t, sampleUrl, api.(*SuiApiConnection).rpc)
}

func TestProcessEvents(t *testing.T) {
	initGlobals()

	arbitraryEventType := "arbitrary::EventType"
	arbitraryEmitter := "0x3117"

	logger := zap.NewNop()

	// Define test cases
	tests := []struct {
		name           string
		events         []SuiEvent
		expectedResult map[string]*big.Int
		expectedCount  int
	}{
		{
			name:           "TestNoEvents",
			events:         []SuiEvent{},
			expectedResult: map[string]*big.Int{},
			expectedCount:  0,
		},
		{
			name: "TestSingleEthereumUSDCEvent",
			events: []SuiEvent{
				{
					Type: &suiEventType,
					Message: &WormholeMessage{
						Sender:  suiTokenBridgeEmitter,
						Payload: generatePayload(1, big.NewInt(100), EthereumUsdcAddress, 2),
					},
				},
			},
			expectedResult: map[string]*big.Int{
				fmt.Sprintf(KEY_FORMAT, EthereumUsdcAddress, vaa.ChainIDEthereum): big.NewInt(100),
			},
			expectedCount: 1,
		},
		{
			name: "TestMultipleEthereumUSDCEvents",
			events: []SuiEvent{
				{
					Type: &suiEventType,
					Message: &WormholeMessage{
						Sender:  suiTokenBridgeEmitter,
						Payload: generatePayload(1, big.NewInt(100), EthereumUsdcAddress, uint16(vaa.ChainIDEthereum)),
					},
				},
				{
					Type: &suiEventType,
					Message: &WormholeMessage{
						Sender:  suiTokenBridgeEmitter,
						Payload: generatePayload(1, big.NewInt(100), EthereumUsdcAddress, uint16(vaa.ChainIDEthereum)),
					},
				},
			},
			expectedResult: map[string]*big.Int{
				fmt.Sprintf(KEY_FORMAT, EthereumUsdcAddress, vaa.ChainIDEthereum): big.NewInt(200),
			},
			expectedCount: 2,
		},
		{
			name: "TestMixedEthereumAndSuiUSDCEvents",
			events: []SuiEvent{
				{
					Type: &suiEventType,
					Message: &WormholeMessage{
						Sender:  suiTokenBridgeEmitter,
						Payload: generatePayload(1, big.NewInt(100), EthereumUsdcAddress, uint16(vaa.ChainIDEthereum)),
					},
				},
				{
					Type: &suiEventType,
					Message: &WormholeMessage{
						Sender:  suiTokenBridgeEmitter,
						Payload: generatePayload(1, big.NewInt(100), SuiUsdcAddress, uint16(vaa.ChainIDSui)),
					},
				},
			},
			expectedResult: map[string]*big.Int{
				fmt.Sprintf(KEY_FORMAT, EthereumUsdcAddress, vaa.ChainIDEthereum): big.NewInt(100),
				fmt.Sprintf(KEY_FORMAT, SuiUsdcAddress, vaa.ChainIDSui):           big.NewInt(100),
			},
			expectedCount: 2,
		},
		{
			name: "TestIncorrectSender",
			events: []SuiEvent{
				{
					Type: &suiEventType,
					Message: &WormholeMessage{
						Sender:  &arbitraryEmitter,
						Payload: generatePayload(1, big.NewInt(100), EthereumUsdcAddress, uint16(vaa.ChainIDEthereum)),
					},
				},
			},
			expectedResult: map[string]*big.Int{},
			expectedCount:  0,
		},
		{
			name: "TestSkipNonWormholeEvents",
			events: []SuiEvent{
				{
					Type: &suiEventType,
					Message: &WormholeMessage{
						Sender:  suiTokenBridgeEmitter,
						Payload: generatePayload(1, big.NewInt(100), EthereumUsdcAddress, uint16(vaa.ChainIDEthereum)),
					},
				},
				{
					Type: &arbitraryEventType,
					Message: &WormholeMessage{
						Sender:  suiTokenBridgeEmitter,
						Payload: generatePayload(1, big.NewInt(100), SuiUsdcAddress, uint16(vaa.ChainIDSui)),
					},
				},
			},
			expectedResult: map[string]*big.Int{
				fmt.Sprintf(KEY_FORMAT, EthereumUsdcAddress, vaa.ChainIDEthereum): big.NewInt(100),
			},
			expectedCount: 1,
		},
		{
			name: "TestInvalidWormholePayloads",
			events: []SuiEvent{
				{ // Invalid payload type
					Type: &suiEventType,
					Message: &WormholeMessage{
						Sender:  suiTokenBridgeEmitter,
						Payload: generatePayload(0, big.NewInt(100), EthereumUsdcAddress, uint16(vaa.ChainIDEthereum)),
					},
				},
				{ // Empty payload
					Type: &suiEventType,
					Message: &WormholeMessage{
						Sender:  suiTokenBridgeEmitter,
						Payload: []byte{},
					},
				},
			},
			expectedResult: map[string]*big.Int{},
			expectedCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			result, count := processEvents(tt.events, logger)

			assert.Equal(t, tt.expectedResult, result)
			assert.Equal(t, tt.expectedCount, count)
		})
	}
}

// TODO
func TestProcessObjectUpdates(t *testing.T) {
	tests := []struct {
		name string
	}{
		{
			name: "TestProcessObjectUpdates",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
		})
	}
}

// TODO
func TestProcessDigest(t *testing.T) {

}

// Generate WormholeMessage payload.
//
//	Payload type: payload[0]
//	Amount: payload[1] for 32
//	Origin address: payload[33] for 32
//	Origin chain ID: payload[65] for 2
func generatePayload(payloadType byte, amount *big.Int, originAddressHex string, originChainID uint16) []byte {
	originAddress, _ := hex.DecodeString(originAddressHex)

	payload := make([]byte, 0, 101)

	// Append payload type
	payload = append(payload, payloadType)

	// Append amount (32 bytes)
	amountBytes := amount.FillBytes(make([]byte, 32))
	payload = append(payload, amountBytes...)

	// Append origin address (32 bytes)
	payload = append(payload, originAddress...)

	// Append origin chain ID (2 bytes)
	originChainIDBytes := []byte{byte(originChainID >> 8), byte(originChainID & 0xff)}
	payload = append(payload, originChainIDBytes...)

	// Right-pad the payload to 101 bytes
	padding := make([]byte, 101-len(payload))
	payload = append(payload, padding...)

	return payload
}
