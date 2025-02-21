package main

import (
	"context"
	"fmt"
	"log"
	"math/big"

	// whcommon "github.com/certusone/wormhole/node/pkg/common"
	"github.com/certusone/wormhole/node/pkg/watchers/evm/connectors"
	"github.com/certusone/wormhole/node/pkg/watchers/evm/connectors/ethabi"
	geth "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/wormhole-foundation/wormhole/sdk/vaa"
)

const (
	// LogMessagePublished(address indexed sender, uint64 sequence, uint32 nonce, bytes payload, uint8 consistencyLevel);
	EVENTHASH_WORMHOLE_LOG_MESSAGE_PUBLISHED = "0x6eb224fb001ed210e379b335e35efe88672a8ce935d981a6896b27ffdf52a3b2"
)

type MessagePublication struct {
	TxID      []byte
	// Timestamp time.Time

	Nonce            uint32
	Sequence         uint64
	ConsistencyLevel uint8
	EmitterChain     vaa.ChainID
	EmitterAddress   vaa.Address
	Payload          []byte
	IsReobservation  bool

	// Unreliable indicates if this message can be reobserved. If a message is considered unreliable it cannot be
	// reobserved.
	Unreliable bool
}

func main() {
	fmt.Println("Running msgpub")
	coreBridgeAddr := "0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B"
	rpc := "ws://localhost:8545"

	height := int64(21896675) // Feb 21 2025

	ctx := context.TODO()
	evmConnector, connectErr := connectors.NewEthereumBaseConnector(
		ctx,
		"eth",
		rpc,
		common.HexToAddress(coreBridgeAddr),
		nil,
	)
	if connectErr != nil {
		log.Fatal(connectErr)
	}

	// Build query: we're looking only at the core bridge
	query := geth.FilterQuery{
		FromBlock: big.NewInt(height-1000),
		ToBlock:   big.NewInt(height),
		Addresses: []common.Address{
			common.BytesToAddress([]byte(coreBridgeAddr)),
		},
	}

	logs, filterErr := evmConnector.Client().FilterLogs(context.Background(), query)
	if filterErr != nil {
		log.Fatal(filterErr)
	}
	fmt.Printf("Got %d logs\n", len(logs))
	for _, vLog := range logs {
		receipt, receiptErr := evmConnector.Client().TransactionReceipt(ctx, vLog.TxHash)
		if receiptErr != nil {
			log.Fatal(filterErr)
		}
		for _, rlog := range receipt.Logs {
			log := rlog
			if rlog.Topics[0] == common.BytesToHash([]byte(EVENTHASH_WORMHOLE_LOG_MESSAGE_PUBLISHED)) {
				logMessagePublished, parseErr := evmConnector.ParseLogMessagePublished(*log)
				if parseErr != nil {
					return
				}
				msg := parseMessageEVM(logMessagePublished)
				fmt.Printf("%+v", msg)
			}
		}
	}
	fmt.Println("done")
}

func parseMessageEVM(ev *ethabi.AbiLogMessagePublished) *MessagePublication {
	msg := &MessagePublication{
		TxID: ev.Raw.TxHash.Bytes(),
		// Timestamp:        time.Unix(int64(blockTime), 0),
		Nonce:    ev.Nonce,
		Sequence: ev.Sequence,
		// EmitterChain:     chainID,
		EmitterAddress:   PadAddress(ev.Sender),
		Payload:          ev.Payload,
		ConsistencyLevel: ev.ConsistencyLevel,
	}
	return msg
}

// PadAddress creates 32-byte VAA.Address from 20-byte Ethereum addresses by adding 12 0-bytes at the left
func PadAddress(address common.Address) vaa.Address {
	paddedAddress := common.LeftPadBytes(address.Bytes(), 32)

	addr := vaa.Address{}
	copy(addr[:], paddedAddress)

	return addr
}
