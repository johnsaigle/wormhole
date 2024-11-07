// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.4;

import {Script, console} from "forge-std/Script.sol";
import {IERC20} from "forge-std/interfaces/IERC20.sol";
import {ERC20PresetMinterPauser} from "@openzeppelin/contracts/token/ERC20/presets/ERC20PresetMinterPauser.sol";
import {MockWETH9} from "../contracts/bridge/mock/MockWETH9.sol";

import "./ITokenBridge.sol";
import "./IWormhole.sol";
import "../src/MultiCall.sol";

contract PublishMessage is Script {

    // Mainnet
    // IWormhole wormhole = IWormhole(0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B);
    // ITokenBridge tokenBridge = ITokenBridge(0x3ee18B2214AFF97000D974cf647E7C347E8fa585);

    // Devnet
    IWormhole wormhole = IWormhole(0xC89Ce4735882C9F0f0FE26686c53074E09B0D550);
    ITokenBridge tokenBridge = ITokenBridge(0x0290FB167208Af455bB137780163b7B7a9a10C16);

    // Taken from DeployToken script and derived from the mnemonic used by anvil
    address user0 = 0x90F8bf6A479f320ead074411a4B0e7944Ea8c9C1;
    address user1 = 0xFFcf8FDEE72ac11b5c542428B35EEF5769C409f0;
    address user2 = 0x22d491Bde2303f2f43325b2108D26f1eAbA1e32b;


    // TODO: Replace these with the Deployed Test Token values
    // IERC20 testToken = IERC20(0xe4E2293e879c5b3A1b3bDc593Cf61802C22532c5);
    // IERC20 wftm = IERC20(0x4cD2690d86284e044cb63E60F1EB218a825a7e92);
    // TODO replace with mock weth
    IERC20 weth = IERC20(0x395F52D798a8Bd88eB649f6BFeD21Cae0d07123E);
    // These are deployed by DeployTestToken
    IERC20 testTokenA = IERC20(0x8E225686FdDB86DA290860C764Cf178ba02FDA0B);
    IERC20 testTokenB = IERC20(0x29fa1c214B7242b704063F2Ec52494f4639A9cc3);
   

    function setUp() public {
    }

    function run() public {

        vm.deal(address(testTokenA), 1e18 ether);
        vm.deal(address(testTokenB), 1e18 ether);
        // Give every account enough ether to send transactions
        vm.deal(address(tokenBridge), 1e18 ether);
        vm.deal(address(wormhole), 1e18 ether);

        vm.deal(address(user0), 1e18 ether);
        vm.deal(address(user1), 1e18 ether);
        // vm.deal(address(user2), 1e18 ether);

        vm.deal(address(testTokenA), 1e18 ether);
        vm.deal(address(testTokenB), 1e18 ether);
        vm.deal(address(weth), 1e18 ether);

        multipleTransfersSeparateTransactions();
        multipleTransfersInSingleTx();
        directlyPublishMessageAsTokenBridge();
    }

    // this function makes two token bridge transfer requests in separate
    // transactions
    function multipleTransfersSeparateTransactions() internal {
        fundAccountWithTokens(user0);

        // transfer 100 testToken
        vm.startBroadcast(user0);
        testTokenA.approve(address(tokenBridge), type(uint256).max);
        tokenBridge.transferTokens(
            address(testTokenA),          // token 
            100 * 1e6,              // amount
            1,                      // recipient chain
            addrToBytes32(user1),   // recipient address
            0, 
            0
        );

        // transfer 1 wftm
        testTokenB.approve(address(tokenBridge), type(uint256).max);
        tokenBridge.transferTokens(
            address(testTokenB), 
            1 * 1e18, 
            1, 
            addrToBytes32(user2), 
            0,
            0
        );
        vm.stopBroadcast();

    }

    // This function bundles two token bridging requests into a single evm transaction using multicall
    // Things to observe in transaction verification:
    //  two subsequent "bridge request processed" messages
    //  a "skip: transaction hash already processed" message, indicating that the 2nd
    //      LogMessagePublished is ignored.
    function multipleTransfersInSingleTx() internal {
        vm.startBroadcast(user0);
        MultiCall mc = new MultiCall();
        vm.stopBroadcast();

        // create calldata
        address[] memory targets = new address[](4);
        bytes[] memory calldatas = new bytes[](4);

        // approve token bridge to spend testTokenA
        targets[0]   = address(testTokenA);
        calldatas[0] = abi.encodeWithSelector(IERC20.approve.selector, address(tokenBridge), type(uint256).max);

        // transfer 100 testToken via token bridge
        targets[1]   = address(tokenBridge);
        calldatas[1] = abi.encodeWithSelector(ITokenBridge.transferTokens.selector,
            address(testTokenA),
            100 * 1e6,
            1,
            addrToBytes32(address(mc)),
            0,
            0
        );

        // approve token bridge to spend wftm
        targets[2]   = address(testTokenB);
        calldatas[2] = abi.encodeWithSelector(IERC20.approve.selector, address(tokenBridge), type(uint256).max);

        // transfer 1 WFTM via token bridge
        targets[3]   = address(tokenBridge);
        calldatas[3] = abi.encodeWithSelector(ITokenBridge.transferTokens.selector,
            address(testTokenB),
            1 * 1e18,
            1,
            addrToBytes32(address(mc)),
            0,
            0
        );

        // fund multicall and launch the request
        fundAccountWithTokens(address(mc));

        vm.broadcast(user0);
        mc.multiCall(targets, calldatas);

    }

    // This function emits a publish message event sent by the token bridge to the core bridge.
    // The receipt generated will contain no deposits or transfer events, and must
    // therefore be marked as invalid by the Transfer Verifier.
    function directlyPublishMessageAsTokenBridge() internal {
        publishArbitraryTransfer(1, 100_000 * 1e6, addrToBytes32(address(testTokenA)), 2);
    }

    // A helper function that transfers testToken and WFTM from addresses on the ethereum network
    function fundAccountWithTokens(address account) internal {

        vm.deal(account, 1e18 ether);

        vm.broadcast(address(user0));
        testTokenA.transfer(account, 10 * 1e18);

        vm.broadcast(address(user0));
        testTokenB.transfer(account, 10 * 1e18);
    }

    function publishArbitraryTransfer(uint8 payloadID, uint256 amount, bytes32 tokenAddress, uint16 tokenChain) internal {
        // Store original code
        bytes memory originalCode = address(tokenBridge).code;

        // Overwrite token bridge with the mocked contract data. This way we
        // avoid the need to impersonate the token bridge directly which
        // can be difficult to do when the transaction needs to be broadcasted
        // while impersonating a contract.
        bytes memory newCode = type(MockTokenBridge).creationCode;
        vm.etch(address(tokenBridge), newCode);

        vm.broadcast(address(user1));
        if (payloadID == 0x01) {
            ITokenBridge.Transfer memory transfer;

            transfer.payloadID = payloadID;
            transfer.amount = amount;
            transfer.tokenAddress = tokenAddress;
            transfer.tokenChain = tokenChain;

            bytes memory payload = encodeTransfer(transfer);

            // None of the arguments are used except for payload
            tokenBridge.transferTokensWithPayload(
                address(0),
                0,
                0,
                addrToBytes32(address(0)),
                0,
                payload
            );
            // wormhole.publishMessage(0x01, payload, 0x01);
        } else if (payloadID == 0x03) {
            ITokenBridge.TransferWithPayload memory transfer;
            
            transfer.payloadID = payloadID;
            transfer.amount = amount;
            transfer.tokenAddress = tokenAddress;
            transfer.tokenChain = tokenChain;

            bytes memory payload = encodeTransferWithPayload(transfer);

            // tokenBridge.publishMessage(0x01, payload, 0x01);
            // wormhole.publishMessage(0x01, payload, 0x01);
            // None of the arguments are used except for payload
            tokenBridge.transferTokensWithPayload(
                address(0),
                0,
                0,
                addrToBytes32(address(0)),
                0,
                payload
            );
        }

        // Restore the original contract code
        vm.etch(address(tokenBridge), originalCode);
    }

    // https://github.com/wormhole-foundation/wormhole/blob/6b810acbecf67e1bb8a663db97dc352e13589529/ethereum/contracts/bridge/Bridge.sol#L606
    function encodeTransfer(ITokenBridge.Transfer memory transfer) public pure returns (bytes memory encoded) {
        encoded = abi.encodePacked(
            transfer.payloadID,
            transfer.amount,
            transfer.tokenAddress,
            transfer.tokenChain,
            transfer.to,
            transfer.toChain,
            transfer.fee
        );
    }

    // https://github.com/wormhole-foundation/wormhole/blob/6b810acbecf67e1bb8a663db97dc352e13589529/ethereum/contracts/bridge/Bridge.sol#L618
    function encodeTransferWithPayload(ITokenBridge.TransferWithPayload memory transfer) public pure returns (bytes memory encoded) {
        encoded = abi.encodePacked(
            transfer.payloadID,
            transfer.amount,
            transfer.tokenAddress,
            transfer.tokenChain,
            transfer.to,
            transfer.toChain,
            transfer.fromAddress,
            transfer.payload
        );
    }

    function addrToBytes32(address a) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(a)));
    } 

}

contract MockTokenBridge {
    
    // params other than payload are not used.
    function transferTokensWithPayload(
        address _token, 
        uint256 _amount, 
        uint16 _recipientChain,
        address _recipientAddress, 
        uint8 _nonce, 
        bytes memory payload
    ) public payable returns (uint64 sequence) {

        IWormhole wormhole = IWormhole(0xC89Ce4735882C9F0f0FE26686c53074E09B0D550);
        // arguments: nonce, payload, consistencyLevel
        sequence = wormhole.publishMessage(uint32(0x01), payload, uint8(0x01));
        return sequence;
    }
}
