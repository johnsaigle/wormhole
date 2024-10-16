package transferverifier

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	fmtString "fmt"
	"math/big"

	// "github.com/celo-org/celo-blockchain/ethclient"
	"github.com/certusone/wormhole/node/pkg/watchers/evm/connectors/ethabi"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/wormhole-foundation/wormhole/sdk/vaa"
	"go.uber.org/zap"
)

// Event Signatures
var (
	// LogMessagePublished(address indexed sender, uint64 sequence, uint32 nonce, bytes payload, uint8 consistencyLevel);
	EVENTHASH_WORMHOLE_LOG_MESSAGE_PUBLISHED = "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2"
	// Transfer(address,address,uint256)
	EVENTHASH_ERC20_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	// Deposit(address,uint256)
	EVENTHASH_WETH_DEPOSIT = "0xe1fffcc4923d04b559f4d29a8bfc6cda04eb5b0d3c460751c2402c5c5cc9109c"
)

// Function signatures
var (
	// wrappedAsset(uint16 tokenChainId, bytes32 tokenAddress) => 0x1ff1e286
	TOKEN_BRIDGE_WRAPPED_ASSET = []byte("\x1f\xf1\xe2\x86")
	// decimals() => 0x313ce567
	ERC20_DECIMALS_SIGNATURE = []byte("\x31\x3c\xe5\x67")
)

// Fixed addresses
var (
	// https://etherscan.io/token/0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2
	WETH_ADDRESS     = common.HexToAddress("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2")
	ZERO_ADDRESS     = common.BytesToAddress([]byte{0x00})
	ZERO_ADDRESS_VAA = VAAAddrFrom(ZERO_ADDRESS)
)

// EVM chain constants
const (
	// The Wormhole Chain ID for the chain being monitored
	NATIVE_CHAIN_ID = 2
	// EVM uses 32 bytes for words. Note that vaa.Address is an alias for a slice of 32 bytes
	EVM_WORD_LENGTH = 32
	// The expected total number of indexed topics for an ERC20 Transfer event
	TOPICS_COUNT_TRANSFER = 3
	// The expected total number of indexed topics for a WETH Deposit event
	TOPICS_COUNT_DEPOSIT = 2
)

// TransferVerifier contains configuration values for verifying transfers.
type TransferVerifier[E evmClient, C connector] struct {
	Addresses TVAddresses
	// Wormhole connector for wrapping contract-specific interactions
	logger zap.Logger
	// Corresponds to the connector interface for EVM chains
	ethConnector C
	// Corresponds to an ethClient from go-ethereum
	client E
}

// Important addresses for Transfer Verification.
type TVAddresses struct {
	CoreBridgeAddr common.Address
	// Address of the Wormhole token bridge contract for this chain
	TokenBridgeAddr common.Address
	// Wrapped version of the native asset, e.g. WETH for Ethereum
	WrappedNativeAddr common.Address
}

type connector interface {
	ParseLogMessagePublished(log types.Log) (*ethabi.AbiLogMessagePublished, error)
}

type evmClient interface {
	// getDecimals()
	CallContract(ctx context.Context, msg ethereum.CallMsg, blockNumber *big.Int) ([]byte, error)
}

// Abstraction over the fields that are expected to be present for Transfer types encoded in receipt logs: Deposits, Transfers,
// and LogMessagePublished events.
type TransferLog interface {
	// Amount after (de)normalization
	TransferAmount() *big.Int
	// The Transferror: EOA or contract that initiated the transfer. Not to be confused with msg.sender.
	Sender() vaa.Address
	// The Transferee. Ultimate recipient of funds.
	Destination() vaa.Address
	// Event emitter
	Emitter() common.Address // Emitter will always be an Ethereum address
	// Chain where the token was minted
	OriginChain() vaa.ChainID
	// Address that minted the token
	OriginAddress() vaa.Address
}

// Abstraction over a Deposit event for a wrapped native asset, e.g. WETH for Ethereum.
type NativeDeposit struct {
	// The address of the token.
	TokenAddress common.Address
	// The native chain of the token (where it was minted)
	TokenChain vaa.ChainID
	Receiver   common.Address
	Amount     *big.Int
}

func (d *NativeDeposit) TransferAmount() *big.Int {
	return d.Amount
}

func (d *NativeDeposit) Destination() vaa.Address {
	return VAAAddrFrom(d.Receiver)
}

// Deposit does not actually have a sender but this is required to implement the interface
func (d *NativeDeposit) Sender() vaa.Address {
	// Sender is not present in the Logs emitted for a Deposit
	return ZERO_ADDRESS_VAA
}

func (d *NativeDeposit) Emitter() common.Address {
	// Event emitter of the Deposit should be equal to TokenAddress.
	return d.TokenAddress
}

func (d *NativeDeposit) OriginChain() vaa.ChainID {
	return d.TokenChain
}

func (d *NativeDeposit) OriginAddress() vaa.Address {
	return VAAAddrFrom(d.TokenAddress)
}

// Abstraction over an ERC20 Transfer event.
type ERC20Transfer struct {
	// The address of the token. Also equivalent to the Emitter of the event.
	TokenAddress common.Address
	// The native chain of the token (where it was minted)
	TokenChain vaa.ChainID
	From       common.Address
	To         common.Address
	Amount     *big.Int
}

func (t *ERC20Transfer) TransferAmount() *big.Int {
	return t.Amount
}

func (t *ERC20Transfer) Sender() vaa.Address {
	return VAAAddrFrom(t.From)
}

func (t *ERC20Transfer) Destination() vaa.Address {
	return VAAAddrFrom(t.To)
}

func (t *ERC20Transfer) Emitter() common.Address {
	// The TokenAddress is equal to the Emitter for ERC20 Transfers
	return t.TokenAddress
}

func (t *ERC20Transfer) OriginChain() vaa.ChainID {
	return t.TokenChain
}

func (t *ERC20Transfer) OriginAddress() vaa.Address {
	return VAAAddrFrom(t.TokenAddress)
}

// Abstraction over a LogMessagePublished event emitted by the core bridge.
type LogMessagePublished struct {
	// Which contract emitted the event.
	EventEmitter common.Address
	// Which address sent the transaction that triggered the message publication.
	MsgSender common.Address
	// Abstraction over fields encoded in the event's Data field which in turn contains the transfer's payload.
	TransferDetails *TransferDetails
	// Note: these fields are non-exhaustive. Data not needed for Transfer Verification is not encoded here.
}

func (l *LogMessagePublished) Destination() (destination vaa.Address) {
	if l.TransferDetails != nil {
		destination = l.TransferDetails.TargetAddress
	}
	return
}

func (l *LogMessagePublished) Emitter() common.Address {
	return l.EventEmitter
}

func (l *LogMessagePublished) Sender() vaa.Address {
	return VAAAddrFrom(l.MsgSender)
}

func (l *LogMessagePublished) TransferAmount() (amount *big.Int) {
	if l.TransferDetails != nil {
		return l.TransferDetails.Amount
	}
	return
}

func (l *LogMessagePublished) OriginAddress() (origin vaa.Address) {
	if l.TransferDetails != nil {
		origin = VAAAddrFrom(l.TransferDetails.OriginAddress)
	}
	return
}

func (l *LogMessagePublished) OriginChain() (chainID vaa.ChainID) {
	if l.TransferDetails != nil {
		chainID = l.TransferDetails.TokenChain
	}
	return
}

// Abstraction over an EVM transaction receipt for Token Bridge transfer.
type TransferReceipt struct {
	Deposits  *[]*NativeDeposit
	Transfers *[]*ERC20Transfer
	// There must be at least one LogMessagePublished for a valid receipt.
	MessagePublicatons *[]*LogMessagePublished
}

// https://wormhole.com/docs/learn/infrastructure/vaas/#payload-types
type VAAPayloadType uint8

const (
	TransferTokens            VAAPayloadType = 1
	TransferTokensWithPayload VAAPayloadType = 3
)

// Abstraction of a Token Bridge transfer payload encoded in the Data field of a LogMessagePublished event.
type TransferDetails struct {
	PayloadType VAAPayloadType
	// Raw token address parsed from the payload. May be wrapped.
	OriginAddressRaw common.Address
	TokenChain       vaa.ChainID
	// Original address of the token when minted natively. Corresponds to the "unwrapped" address in the token bridge.
	OriginAddress common.Address
	// Not necessarily an EVM address, so vaa.Address is used instead
	TargetAddress vaa.Address
	// Amount as sent in the raw payload
	AmountRaw *big.Int
	// Denormalized amount, accounting for decimal differences between contracts and chains
	Amount *big.Int
}

func (td *TransferDetails) String() string {
	return fmt.Sprintf(
		"PayloadType: %d OriginAddressRaw: %s TokenChain: %d OriginAddress: %s TargetAddress: %s AmountRaw: %s Amount: %s",
		td.PayloadType,
		td.OriginAddressRaw,
		td.TokenChain,
		td.OriginAddress.String(),
		td.TargetAddress.String(),
		td.AmountRaw.String(),
		td.Amount.String(),
	)
}

// unwrapIfWrapped() returns the "unwrapped" address for a token a.k.a. the OriginAddress
// of the token's original minting contract.
func (tv *TransferVerifier[ethClient, connector]) unwrapIfWrapped(
	tokenAddress []byte,
	tokenChain vaa.ChainID,
) (unwrappedTokenAddress common.Address, err error) {
	ctx := context.TODO()

	tokenAddressAsKey := hex.EncodeToString(tokenAddress)

	// If the token address already exists in the wrappedCache mapping the
	// cached value can be returned.
	if addr, exists := wrappedCache[tokenAddressAsKey]; exists {
		tv.logger.Debug("wrapped asset found in cache, returning")
		return addr, nil
	}

	// prepare eth_call data, 4-byte signature + 2x 32 byte arguments
	calldata := make([]byte, 4+EVM_WORD_LENGTH+EVM_WORD_LENGTH)

	copy(calldata, TOKEN_BRIDGE_WRAPPED_ASSET)
	// Add the uint16 tokenChain as the last two bytes in the first argument
	binary.BigEndian.PutUint16(calldata[4+30:], uint16(tokenChain))
	copy(calldata[4+EVM_WORD_LENGTH:], tokenAddress)

	ethCallMsg := ethereum.CallMsg{
		To:   &tv.Addresses.TokenBridgeAddr,
		Data: calldata,
	}
	tv.logger.Debug("calling wrappedAsset", zap.String("tokenChain", tokenChain.String()), zap.String("tokenAddress", fmtString.Sprintf("%x", tokenAddress)))

	result, err := tv.client.CallContract(ctx, ethCallMsg, nil)
	if err != nil {
		return common.Address{}, fmtString.Errorf("failed to get mapping for token %s", tokenAddressAsKey)
	}

	tokenAddressNative := common.BytesToAddress(result)
	wrappedCache[tokenAddressAsKey] = tokenAddressNative

	return tokenAddressNative, nil
}

// Remove irrelevant logs from consideration. Returns a string of the form "address-chain" for relevant entries
func relevant[L TransferLog](tLog TransferLog, tv *TVAddresses) (key string, relevant bool) {

	switch log := tLog.(type) {
	case *NativeDeposit:
		// Skip native deposit events emitted by contracts other than the configured wrapped native address.
		if cmp(log.Emitter(), tv.WrappedNativeAddr) != 0 {
			return
		}

		if cmp(log.Destination(), tv.TokenBridgeAddr) != 0 {
			return
		}
	case *ERC20Transfer:
		if cmp(log.Destination(), tv.TokenBridgeAddr) != 0 {
			return
		}
	case *LogMessagePublished:
		// This check is already done elsewhere but it's important.
		if cmp(log.Emitter(), tv.CoreBridgeAddr) != 0 {
			return
		}
		// Only consider LogMessagePublished events with msg.sender equal to the Token Bridge
		if cmp(log.Sender(), tv.TokenBridgeAddr) != 0 {
			return
		}
		// The following values are not exposed by the interface, so check them directly here.
		if log.TransferDetails.PayloadType != TransferTokens && log.TransferDetails.PayloadType != TransferTokensWithPayload {
			return
		}
	}
	return fmtString.Sprintf(KEY_FORMAT, tLog.OriginAddress(), tLog.OriginChain()), true
}

// validate() ensures a TransferLog is well-formed. This means that its fields are not nil and in most cases are not
// equal to the zero-value for the field's type.
func validate[L TransferLog](tLog TransferLog) (err error) {

	if cmp(tLog.Emitter(), ZERO_ADDRESS) == 0 {
		return errors.New("invalid log: emitter is the zero address")
	}

	if tLog.OriginChain() == 0 {
		return errors.New("invalid log: originChain is 0")
	}

	// if cmp(tLog.OriginAddress(), ZERO_ADDRESS_VAA) == 0 {
	// 	return errors.New("originAddress is the zero address")
	// }

	if tLog.TransferAmount() == nil {
		return errors.New("invalid log: transfer amount is nil")
	}

	if cmp(tLog.Destination(), ZERO_ADDRESS_VAA) == 0 {
		return errors.New("invalid log: destination is not set")
	}

	switch log := tLog.(type) {
	case *NativeDeposit:
		// Deposit does not actually have a sender, so it should always be equal to the zero address.
		if cmp(log.Sender(), ZERO_ADDRESS_VAA) != 0 {
			return errors.New("invalid log: sender address for Deposit must be 0")
		}
		if cmp(log.Emitter(), log.TokenAddress) != 0 {
			return errors.New("invalid log: deposit emitter is not equal to its token address")
		}
	case *ERC20Transfer:
		// Transfers and LogMessagePublished cannot have a sender with a 0 address
		if cmp(log.Sender(), ZERO_ADDRESS_VAA) == 0 {
			return errors.New("invalid log: sender cannot be zero")
		}
		if cmp(log.Emitter(), log.TokenAddress) != 0 {
			return errors.New("invalid log: deposit emitter is not equal to its token address")
		}
	case *LogMessagePublished:
		// Transfers and LogMessagePublished cannot have a sender with a 0 address
		if cmp(log.Sender(), ZERO_ADDRESS_VAA) == 0 {
			return errors.New("invalid log: sender cannot be zero")
		}

		// TODO is this valid for assets that return the zero address from unwrap?
		// if cmp(log.OriginAddress(), ZERO_ADDRESS_VAA) == 0 {
		// 	return errors.New("origin cannot be zero")
		// }

		// The following values are not exposed by the interface, so check them directly here.
		if log.TransferDetails == nil {
			return errors.New("invalid log: TransferDetails cannot be nil")
		}
		if cmp(log.TransferDetails.TargetAddress, ZERO_ADDRESS_VAA) == 0 {
			return errors.New("invalid log: target address cannot be zero")
		}
		if cmp(log.TransferDetails.OriginAddressRaw, ZERO_ADDRESS_VAA) == 0 {
			return errors.New("invalid log: origin address raw cannot be zero")
		}
		if log.TransferDetails.AmountRaw == nil {
			return errors.New("invalid log: amountRaw cannot be nil")
		}
		if log.TransferDetails.PayloadType != TransferTokens && log.TransferDetails.PayloadType != TransferTokensWithPayload {
			return errors.New("invalid log: payload type is not a transfer type")
		}
	default:
		return errors.New("invalid log: invalid transfer log type: unknown")
	}

	return nil
}

// func (tv *TransferVerifier[E, C]) validate(t *TransferERC20) bool {
// 	return false
// }

// getDecimals() is equivalent to calling decimals() on a contract that follows the ERC20 standard.
func (tv *TransferVerifier[evmClient, connector]) getDecimals(
	tokenAddress common.Address,
) (decimals uint8, err error) {
	ctx := context.TODO()

	// First check if this token's decimals is stored in cache
	if _, exists := decimalsCache[tokenAddress]; exists {
		tv.logger.Debug("asset decimals found in cache, returning")
		return decimalsCache[tokenAddress], nil
	}

	// If the decimals aren't cached, perform an eth_call lookup for the decimals
	// This RPC call should only be made once per token, until the guardian is restarted
	ethCallMsg := ethereum.CallMsg{
		To:   &tokenAddress,
		Data: ERC20_DECIMALS_SIGNATURE,
	}

	result, err := tv.client.CallContract(ctx, ethCallMsg, nil)
	if err != nil || len(result) < EVM_WORD_LENGTH {
		tv.logger.Warn("failed to get decimals for token",
			zap.String("tokenAddress", tokenAddress.String()),
			zap.ByteString("result", result),
			zap.Error(err))
		return 0, err
	}

	// An ERC20 token's decimals should fit in a single byte. A call to `decimals()`
	// returns a uint8 value encoded in string with 32-bytes. To get the decimals,
	// we grab the last byte, expecting all the preceding bytes to be equal to 0.
	// TODO: find out if there is some official documentation for why this uint8 is in the last index of the 32byte return.
	decimals = result[EVM_WORD_LENGTH-1]

	// Add the decimal value to the cache
	decimalsCache[tokenAddress] = decimals
	tv.logger.Debug("adding new token's decimals to cache",
		zap.String("tokenAddress", tokenAddress.String()),
		zap.Uint8("tokenDecimals", decimals))

	return decimals, nil
}

// Gives the representation of a geth address in vaa.Address
func VAAAddrFrom(gethAddr common.Address) (vaaAddr vaa.Address) {
	// Geth uses 20 bytes to represent an address. A VAA address is equivalent if it has the same
	// final 20 bytes. The leading bytes are expected to be zero for both types.
	vaaAddr = vaa.Address(common.LeftPadBytes(gethAddr[:], EVM_WORD_LENGTH))
	return
}

// Interface useful for comparing vaa.Address and common.Address
type Bytes interface {
	Bytes() []byte
}

// Utility method for comparing common.Address and vaa.Address at the byte level. Under the hood, they are both 32 byte
// values.
func cmp[some Bytes, other Bytes](a some, b other) int {

	return bytes.Compare(
		common.LeftPadBytes(a.Bytes(), EVM_WORD_LENGTH),
		common.LeftPadBytes(b.Bytes(), EVM_WORD_LENGTH),
	)
}
