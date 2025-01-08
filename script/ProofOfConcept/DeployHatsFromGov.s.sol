// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";

import "../../src/HSGSuperMod.sol";
// import "../../src/HSGSuperFactory.sol";
import "hats-protocol/Interfaces/IHats.sol";
import "@openzeppelin/contracts/governance/IGovernor.sol";

contract CreateCouncilHatSettings {
  IGovernor public governor = IGovernor(0xa9347068F7C903B3530192f121D8a896260f25D1);
  IHats public hats = IHats(0x3bc1A0Ad72417f2d411118085256fC53CBdDd137);

  string public tophatDesc = "";
  // manually set, or don't set if you plan on minting
  uint256 public tophatID = 19680761067019967050106921013524330391755115428454617911205635481927680;
  string public councilHatDesc = "";
  uint32 public councilHatMaxSupply = 10;
  bool councilHatIsMutable = true;
  address[] public hatOwners = [0x719E4F1B69efbf4da45f70Ec4bE5dd2321B0a821, 0x1b6967Bc7868F5a0CB78971427ef75ee4F8EE1c8, 0x8908dccF5A1aB99D6bE0d973eD49693283607bC7];

  string public propDesc = "Proposal to create council hat";
}

// forge script script/ProofOfConcept/DeployHatsFromGov.s.sol:CreateCouncilHat -f sepolia
contract CreateCouncilHat is CreateCouncilHatSettings, Script {
    // HSGSuperFactory public factory = HSGSuperFactory(0x89F804D4Bf5A49966423cBCd259288F24d41d447); // factory on sepolia

    function run() external {
        uint256 privKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.rememberKey(privKey);
        vm.startBroadcast(deployer);
        // mint the tophat to governor. comment out if manually setting tophatID
        // tophatID = hats.mintTopHat(address(governor), tophatDesc, "");
        // console2.log("Top hat ID: ", tophatID);

        // propose governor for creating hat
        // createHat can't have 0 addresses for eligibility module or toggle module. set to governor instead
        bytes memory createHatCall = abi.encodeWithSignature("createHat(uint256,string,uint32,address,address,bool,string)", tophatID, councilHatDesc, councilHatMaxSupply, address(governor), address(governor), councilHatIsMutable, "");
        uint256 newHatId = hats.getNextId(tophatID);
        console2.log("Hat ID: ", newHatId);

        bytes memory mintHatCall = abi.encodeWithSignature("batchMintHats(uint256[],address[])", [newHatId, newHatId, newHatId], hatOwners);
        address[] memory targets = new address[](2);
        targets[0] = address(hats);
        targets[1] = address(hats);

        uint256[] memory values = new uint256[](2);
        values[0] = 0;
        values[1] = 0;

        bytes[] memory calldatas = new bytes[](2);
        calldatas[0] = createHatCall;
        calldatas[1] = mintHatCall;

        for (uint256 i = 0; i < targets.length; i++) {
          console2.log("Target[", i, "]: ", targets[i]);
        }
        for (uint256 i = 0; i < values.length; i++) {
          console2.log("Value[", i, "]: ", values[i]);
        }
        for (uint256 i = 0; i < calldatas.length; i++) {
          console2.log("Calldata[", i, "]: ", vm.toString(calldatas[i]));
        }

        uint256 propId = governor.propose(targets, values, calldatas, propDesc);
        console2.log("Proposal id: ", propId);

        vm.stopBroadcast();
    }
}

// forge script script/ProofOfConcept/DeployHatsFromGov.s.sol:ExecuteCreateCouncilHat -f sepolia
contract ExecuteCreateCouncilHat is CreateCouncilHatSettings, Script {
  uint256 public hatId = 19680761478396106380408431552266626031092741674138584319600601319079936; // have to set manually

  function run() external {
    uint256 privKey = vm.envUint("PRIVATE_KEY");
    address executor = vm.rememberKey(privKey);
    vm.startBroadcast(executor);

    bytes memory createHatCall = abi.encodeWithSignature("createHat(uint256,string,uint32,address,address,bool,string)", tophatID, councilHatDesc, councilHatMaxSupply, address(governor), address(governor), councilHatIsMutable, "");
    uint256 newHatId = hats.getNextId(tophatID);
    console2.log("Hat ID: ", newHatId);

    bytes memory mintHatCall = abi.encodeWithSignature("batchMintHats(uint256[],address[])", [newHatId, newHatId, newHatId], hatOwners);
    address[] memory targets = new address[](2);
    targets[0] = address(hats);
    targets[1] = address(hats);

    uint256[] memory values = new uint256[](2);
    values[0] = 0;
    values[1] = 0;

    bytes[] memory calldatas = new bytes[](2);
    calldatas[0] = createHatCall;
    calldatas[1] = mintHatCall;

    for (uint256 i = 0; i < targets.length; i++) {
      console2.log("Target[", i, "]: ", targets[i]);
    }
    for (uint256 i = 0; i < values.length; i++) {
      console2.log("Value[", i, "]: ", values[i]);
    }
    for (uint256 i = 0; i < calldatas.length; i++) {
      console2.log("Calldata[", i, "]: ", vm.toString(calldatas[i]));
    }
    
    // some testing
    // uint256 proposalHash = governor.hashProposal(targets, values, calldatas, keccak256(bytes(propDesc)));
    // console2.log("Proposal Hash: ", proposalHash);

    // uint256 currentBlock = block.number;
    // console2.log("Current Block Number: ", currentBlock);

    // uint256 proposalDeadline = governor.proposalDeadline(proposalHash);
    // console2.log("Proposal Deadline: ", proposalDeadline);

    // uint256 blocksUntilDeadline = proposalDeadline - currentBlock;
    // console2.log("Blocks Until Deadline: ", blocksUntilDeadline);

    governor.execute(targets, values, calldatas, keccak256(bytes(propDesc)));
    

    vm.stopBroadcast();
  }
}

contract CastVote is Script {
  IGovernor public governor = IGovernor(0xa9347068F7C903B3530192f121D8a896260f25D1);

  function run(uint256 propId) external {
    uint256 privKey = vm.envUint("PRIVATE_KEY");
    address delegate = vm.rememberKey(privKey);
    vm.startBroadcast(delegate);
    governor.castVote(propId, 1);

    vm.stopBroadcast();
  }
}