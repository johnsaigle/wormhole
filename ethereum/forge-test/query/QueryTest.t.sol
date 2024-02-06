// SPDX-License-Identifier: Apache 2

// forge test --match-contract QueryTest

pragma solidity ^0.8.4;

import "forge-std/Test.sol";
import "./QueryTest.sol";

contract TestQueryTest is Test, QueryTest {

    function test_buildQueryResponseBytes() public {
        bytes memory resp = buildQueryResponseBytes(
            /* version */              1,
            /* senderChainId */        0,
            /* signature */            hex"11b03bdbbe15a8f12b803d2193de5ddff72d92eaabd2763553ec3c3133182d1443719a05e2b65c87b923c6bd8aeff49f34937f90f3ab7cd33449388c60fa30a301",
            /* queryRequestLen */      79,
            /* queryRequest */         hex"0100000001010002010000004200000005307837343402ddb64fe46a91d46ee29420539fc25fd07c5fea3e0000000406fdde03ddb64fe46a91d46ee29420539fc25fd07c5fea3e00000004313ce567",
            /* numPerChainResponses */ 1,
            /* perChainResponses */    hex"000201000000b900000000000007446a0b819aee8945e659e37537a0bdbe03c06275be23e499819138d1eee8337e9b000000006ab13b8002000000600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d5772617070656420457468657200000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000012"
        );
        assertEq(resp, hex"01000011b03bdbbe15a8f12b803d2193de5ddff72d92eaabd2763553ec3c3133182d1443719a05e2b65c87b923c6bd8aeff49f34937f90f3ab7cd33449388c60fa30a3010000004f0100000001010002010000004200000005307837343402ddb64fe46a91d46ee29420539fc25fd07c5fea3e0000000406fdde03ddb64fe46a91d46ee29420539fc25fd07c5fea3e00000004313ce56701000201000000b900000000000007446a0b819aee8945e659e37537a0bdbe03c06275be23e499819138d1eee8337e9b000000006ab13b8002000000600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d5772617070656420457468657200000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000012");
    }

    function test_buildPerChainResponseBytes() public {
        bytes memory pcr = buildPerChainResponseBytes(
            /* chainId */       2,
            /* queryType */     1,
            /* responseLen */   185,
            /* responseBytes */ hex"00000000000007446a0b819aee8945e659e37537a0bdbe03c06275be23e499819138d1eee8337e9b000000006ab13b8002000000600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d5772617070656420457468657200000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000012"
        );
        assertEq(pcr, hex"000201000000b900000000000007446a0b819aee8945e659e37537a0bdbe03c06275be23e499819138d1eee8337e9b000000006ab13b8002000000600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d5772617070656420457468657200000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000012");
    }

    function test_buildEthCallResponseBytes() public {
        bytes memory ecr = buildEthCallResponseBytes(
            /* blockNumber */ 1860,
            /* blockHash */   hex"6a0b819aee8945e659e37537a0bdbe03c06275be23e499819138d1eee8337e9b",
            /* blockTimeUs */ 0x6ab13b80,
            /* numResults */  2,
            /* results */     hex"000000600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d5772617070656420457468657200000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000012"
        );
        assertEq(ecr, hex"00000000000007446a0b819aee8945e659e37537a0bdbe03c06275be23e499819138d1eee8337e9b000000006ab13b8002000000600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d5772617070656420457468657200000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000012");
    }

    function test_buildEthCallByTimestampResponseBytes() public {
        bytes memory ecr = buildEthCallByTimestampResponseBytes(
            /* targetBlockNumber */    349,
            /* targetBlockHash */      hex"966cd846f812be43c4ee2d310f962bc592ba944c66de878e53584b8e75c6051f",
            /* targetBlockTimeUs */    0x10642ac0,
            /* followingBlockNumber */ 350,
            /* followingBlockHash */   hex"04b022afaab8da2dd80bd8e6ae55e6303473a5e1de846a5de76d619e162429ce",
            /* followingBlockTimeUs */ 0x10736d00,            
            /* numResults */           2,
            /* results */              hex"000000600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d5772617070656420457468657200000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000012"
        );
        assertEq(ecr, hex"000000000000015d966cd846f812be43c4ee2d310f962bc592ba944c66de878e53584b8e75c6051f0000000010642ac0000000000000015e04b022afaab8da2dd80bd8e6ae55e6303473a5e1de846a5de76d619e162429ce0000000010736d0002000000600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d5772617070656420457468657200000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000012");
    }

    function test_buildEthCallWithFinalityResponseBytes() public {
        bytes memory ecr = buildEthCallWithFinalityResponseBytes(
            /* blockNumber */ 1860,
            /* blockHash */   hex"6a0b819aee8945e659e37537a0bdbe03c06275be23e499819138d1eee8337e9b",
            /* blockTimeUs */ 0x6ab13b80,
            /* numResults */  2,
            /* results */     hex"000000600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d5772617070656420457468657200000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000012"
        );
        assertEq(ecr, hex"00000000000007446a0b819aee8945e659e37537a0bdbe03c06275be23e499819138d1eee8337e9b000000006ab13b8002000000600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d5772617070656420457468657200000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000012");
    }

    function test_buildEthCallResultBytes() public {
        bytes memory ecr1 = buildEthCallResultBytes(
            /* resultLen */ 96,
            /* result */    hex"0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d5772617070656420457468657200000000000000000000000000000000000000"
        );
        assertEq(ecr1, hex"000000600000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d5772617070656420457468657200000000000000000000000000000000000000");
        bytes memory ecr2 = buildEthCallResultBytes(
            /* resultLen */ 32,
            /* result */    hex"0000000000000000000000000000000000000000000000000000000000000012"
        );
        assertEq(ecr2, hex"000000200000000000000000000000000000000000000000000000000000000000000012");
    }

    function test_buildSolanaAccountResponseBytes() public {
        bytes memory ecr = buildSolanaAccountResponseBytes(
            /* slotNumber */  5603,
            /* blockTimeUs */ 0x610cdf2510500,
            /* blockHash */   hex"e0eca895a92c0347e30538cd07c50777440de58e896dd13ff86ef0dae3e12552",
            /* numResults */  2,
            /* results */     hex"0000000000164d6000000000000000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a90000005201000000574108aed69daf7e625a361864b1f74d13702f2ca56de9660e566d1d8691848d0000e8890423c78a09010000000000000000000000000000000000000000000000000000000000000000000000000000000000164d6000000000000000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a90000005201000000574108aed69daf7e625a361864b1f74d13702f2ca56de9660e566d1d8691848d01000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000"
        );
        assertEq(ecr, hex"00000000000015e3000610cdf2510500e0eca895a92c0347e30538cd07c50777440de58e896dd13ff86ef0dae3e12552020000000000164d6000000000000000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a90000005201000000574108aed69daf7e625a361864b1f74d13702f2ca56de9660e566d1d8691848d0000e8890423c78a09010000000000000000000000000000000000000000000000000000000000000000000000000000000000164d6000000000000000000006ddf6e1d765a193d9cbe146ceeb79ac1cb485ed5f5b37913a8cf5857eff00a90000005201000000574108aed69daf7e625a361864b1f74d13702f2ca56de9660e566d1d8691848d01000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000");
    }
}
