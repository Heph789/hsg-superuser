// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/ProofOfConcept/DelegateCanceller.sol";
import "../src/ProofOfConcept/MyToken.sol";
import "@openzeppelin/contracts/governance/utils/IVotes.sol";
import "@openzeppelin/contracts/governance/IGovernor.sol";
import "@openzeppelin/contracts/governance/TimelockController.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

// contract MockToken is ERC20, IVotes {
//   constructor() ERC20("MockToken", "MTK") {}

//   function getPastTotalSupply(uint256 blockNumber) external view override returns (uint256) {
//     return totalSupply();
//   }

//   function getPastVotes(address account, uint256 blockNumber) external view override returns (uint256) {
//     return balanceOf(account);
//   }
// }

contract DelegateCancellerTest is Test {
  DelegateCanceller public canceller;
  MyToken public token;
  TimelockController public timelock;
  IGovernor public governor;
  address public delegate;
  address public owner;

  function setUp() public {
    token = new MyToken();
    governor = IGovernor(address(0x123)); // Mock governor address
    canceller = new DelegateCanceller(governor, token, 10);
    address[] memory executors = new address[](1);
    executors[0] = address(this);
    // address[] memory cancellers = new address[](1);
    // cancellers[0] = address(canceller);
    timelock = new TimelockController(1 days, executors, executors, address(this));
    timelock.grantRole(timelock.CANCELLER_ROLE(), address(canceller));
    delegate = address(0x456);
    owner = address(this);

    token.mint(delegate, 1000 ether);
    token.mint(owner, 1000 ether);
    token.delegate(delegate); // should give delegate address half of voting supply
    vm.roll(block.number + 1);
  }

  function testCancel() public {
    bytes32 salt = bytes32(0);
    bytes32 id = timelock.hashOperation(address(this), 0, "", bytes32(0), salt);
    timelock.schedule(address(this), 0, "", bytes32(0), salt, 1 days);
    vm.prank(delegate);
    canceller.cancel(timelock, id);
    assertTrue(timelock.isOperationPending(id) == false);
  }

  function testFailCancelWithoutThreshold() public {
    bytes32 salt = bytes32(0);
    bytes32 id = timelock.hashOperation(address(this), 0, "", bytes32(0), salt);
    timelock.schedule(address(this), 0, "", bytes32(0), salt, 1 days);
    vm.prank(owner);
    canceller.cancel(timelock, id);
  }

  function testSetThreshold() public {
    uint256 newThreshold = 60;
    canceller.setThreshold(newThreshold);
    assertEq(canceller.thresholdPercentage(), newThreshold);
  }

  function testFailSetThresholdNotOwner() public {
    uint256 newThreshold = 20;
    vm.prank(delegate);
    canceller.setThreshold(newThreshold);
  }
}

// forge test --match-contract DelegateCanceller