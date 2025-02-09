// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";

import "../src/HSGSuperMod.sol";
import { HSGSuperFactory } from "../src/HSGSuperFactory.sol";
import "hats-protocol/Interfaces/IHats.sol";
import "@openzeppelin/contracts/governance/IGovernor.sol";

contract CreateCouncilHatSettings { // set these settings mannualy
  // hats contract address for sepolia. set manually for different chains
  IHats public hats = IHats(0x3bc1A0Ad72417f2d411118085256fC53CBdDd137);

  string public tophatDesc = "";
  // manually set, or set to 0 if you plan on minting
  uint256 public tophatID = 0;
  // set to a non-zero address
  address public mintTopHatTo = address(0);
  // eligibility/toggle module CANNOT be 0 address
  address public eligibilityModule = address(0);
  address public toggleModule = address(0);
  string public councilHatDesc = "";
  uint32 public councilHatMaxSupply = 10;
  bool councilHatIsMutable = true;
  // set manually to the addresses you want to wear the signer hat
  address[] public hatOwners = [address(0)];

  // HSG settings
  // set manually to the address you want to give ability to veto transactions
  address canceller = address(0);
  // sepolia factory address, set manually for other chains
  HSGSuperFactory factory = HSGSuperFactory(0x89F804D4Bf5A49966423cBCd259288F24d41d447);
  uint256 public timelockDelay = 10 minutes;
  uint256 public minThreshold = 1;
  uint256 public targetThreshold = 2;
  uint256 public maxSigners = 5;
}
// // simulate
// forge script script/DeployHatsMod.s.sol:DeployHatsMod -f sepolia
// // broadcast
// forge script script/DeployHatsMod.s.sol:DeployHatsMod -f sepolia --broadcast
contract DeployHatsMod is CreateCouncilHatSettings, Script {

    function run() external {
        uint256 privKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.rememberKey(privKey);
        vm.startBroadcast(deployer);

        if (mintTopHatTo == address(0)) {
          mintTopHatTo = deployer;
        }

        if (eligibilityModule == address(0)) {
          eligibilityModule = mintTopHatTo;
        }

        if (toggleModule == address(0)) {
          toggleModule = mintTopHatTo;
        }

        if (tophatID == 0) {
          // mint the tophat to governor. comment out if manually setting tophatID
          tophatID = hats.mintTopHat(deployer, tophatDesc, "");
          console2.log("Top hat ID: ", tophatID);
        }

        // propose governor for creating hat
        // createHat can't have 0 addresses for eligibility module or toggle module. set to governor instead
        uint256 newHatId = hats.createHat(tophatID, councilHatDesc, councilHatMaxSupply, eligibilityModule, toggleModule, councilHatIsMutable, "");

        console2.log("New hat ID: ", newHatId);

        uint256 hatOwnersLength = hatOwners.length;

        uint256[] memory hatIdArr = new uint256[](hatOwnersLength);
        for (uint i = 0; i < hatOwnersLength; i++) {
          hatIdArr[i] = newHatId;
        }

        // // for catching errors
        hats.batchMintHats(hatIdArr, hatOwners);

        // deploy the hsg from factory
        (address hsg, address safe) = factory.deployHSGSuperModAndSafeWithTimelock(tophatID, newHatId, canceller, minThreshold, targetThreshold, maxSigners, timelockDelay); // should run this separately, since this part actually doesn't require verification
        console2.log("Hsg deployed to: %s\nSafe deployed to: %s", hsg, safe);

        if (mintTopHatTo != deployer) {
          hats.transferHat(tophatID, deployer, mintTopHatTo);
        }

        vm.stopBroadcast();
    }
}