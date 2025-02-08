// SPDX-License-Identifier: MIT
/*
  A quick and dirty contract allowing high-powered delegates to cancel timelock transactions. For testing purposes only.
*/
pragma solidity ^0.8.13;

// import {console2} from "forge-std/console2.sol";

import "@openzeppelin/contracts/governance/utils/IVotes.sol";
import "@openzeppelin/contracts/governance/IGovernor.sol";
import "@openzeppelin/contracts/governance/TimelockController.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract DelegateCanceller is Ownable {
  IGovernor public governor;
  IVotes public token;
  uint256 public thresholdPercentage = 10;
  
  constructor(IGovernor _governor, IVotes _token, uint256 _threshold) {
    governor = _governor;
    token = _token;
    thresholdPercentage = _threshold;
  }

  function _meetsThreshold(address delegate) internal view returns (bool) {
    uint256 totalSupply = token.getPastTotalSupply(block.number - 1);
    uint256 delegateVotes = token.getPastVotes(delegate, block.number - 1);
    return delegateVotes > (totalSupply * thresholdPercentage / 100);
  }

  function cancel(TimelockController tc, bytes32 id) external {
    require(_meetsThreshold(msg.sender), "DelegateCanceller: insufficient voting power");
    tc.cancel(id);
  }

  function setThreshold(uint256 newThreshold) external onlyOwner() {
    thresholdPercentage = newThreshold;
  }
}