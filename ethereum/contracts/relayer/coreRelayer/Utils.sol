// SPDX-License-Identifier: Apache 2

pragma solidity ^0.8.0;

error NotAnEvmAddress(bytes32);

function pay(address payable receiver, uint256 amount) returns (bool success) {
  if (amount != 0)
    (success,) = receiver.call{value: amount}("");
  else
    success = true;
}

uint256 constant MAX_U256 = 2**256 - 1;
uint256 constant MAX_U128 = 2**128 - 1;

function min(uint256 a, uint256 b) pure returns (uint256) {
  return a < b ? a : b;
}

function max(uint256 a, uint256 b) pure returns (uint256) {
  return a > b ? a : b;
}

function toWormholeFormat(address addr) pure returns (bytes32) {
  return bytes32(uint256(uint160(addr)));
}

function fromWormholeFormat(bytes32 whFormatAddress) pure returns (address) {
  if (uint256(whFormatAddress) >> 160 != 0)
    revert NotAnEvmAddress(whFormatAddress);
  return address(uint160(uint256(whFormatAddress)));
}

function fromWormholeFormatUnchecked(bytes32 whFormatAddress) pure returns (address) {
  return address(uint160(uint256(whFormatAddress)));
}