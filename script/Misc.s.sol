// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";

import "@openzeppelin/contracts/governance/IGovernor.sol";

// contract CreateCouncilHatSettings {
// }

// forge script script/Misc.s.sol:Misc -f sepolia
contract Misc is Script {
  IGovernor public governor = IGovernor(0xa9347068F7C903B3530192f121D8a896260f25D1);

  function run() external {
    uint256 privKey = vm.envUint("PRIVATE_KEY");
    address deployer = vm.rememberKey(privKey);
    vm.startBroadcast(deployer);
    
    bytes memory callData = abi.encodeWithSignature("setVotingPeriod(uint256)", 100); // sets voting period to 100 blocks
    // propose
    address[] memory targets = new address[](1);
    targets[0] = address(governor);
    
    uint256[] memory values = new uint256[](1);
    values[0] = 0;
    
    bytes[] memory calldatas = new bytes[](1);
    calldatas[0] = callData;
    
    // governor.propose(targets, values, calldatas, "Set voting period to 100 blocks");
    // execute
    governor.execute(targets, values, calldatas, keccak256(bytes("Set voting period to 100 blocks")));
    

    vm.stopBroadcast();
    
  }

}