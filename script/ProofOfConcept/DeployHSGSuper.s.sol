// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";

import "../../src/HSGSuperFactory.sol";
// import { HSGSuperMod } from "../../src/HSGSuperMod.sol";
import { DelegateCanceller, IVotes } from "../../src/ProofOfConcept/DelegateCanceller.sol";
import "hats-protocol/Interfaces/IHats.sol";
import {IGovernor} from "@openzeppelin/contracts/governance/IGovernor.sol";

contract Settings {
  IGovernor governor = IGovernor(0xa9347068F7C903B3530192f121D8a896260f25D1);
  IVotes token = IVotes(0xB90b42a823d5d8462CDE39efA3BEAe17FB4d27Ec);
  IHats hats = IHats(0x3bc1A0Ad72417f2d411118085256fC53CBdDd137);
  HSGSuperFactory factory = HSGSuperFactory(0x89F804D4Bf5A49966423cBCd259288F24d41d447);
  DelegateCanceller canceller = DelegateCanceller(0x57bbb5bBa304Df937Bd1086bC0B220442024d1E0);

  uint256 public tophatID = 19680761067019967050106921013524330391755115428454617911205635481927680;
  uint256 public councilHatID = 19680761478396106380408431552266626031092741674138584319600601319079936;
  uint256 public timelockDelay = 15 minutes;
}

// forge script script/ProofOfConcept/DeployHSGSuper.s.sol:DeployHSGSuperWithTimelock -f sepolia
contract DeployHSGSuperWithTimelock is Settings, Script {
    // HSGSuperFactory public factory = HSGSuperFactory(0x89F804D4Bf5A49966423cBCd259288F24d41d447); // factory on sepolia

    function run() external {
        uint256 privKey = vm.envUint("PRIVATE_KEY");
        address deployer = vm.rememberKey(privKey);
        vm.startBroadcast(deployer);

        // deploy the canceller
        // DelegateCanceller canceller = new DelegateCanceller(governor, token, 10); // for some reason when running the script this is the only transaction that goes through. might need to run with a different setting
        canceller.transferOwnership(address(governor));
        console2.log("Canceller deployed to: ", address(canceller));

        // deploy the hsg from factory
        (address hsg, address safe) = factory.deployHSGSuperModAndSafeWithTimelock(tophatID, councilHatID, address(canceller), 1, 2, 5, timelockDelay); // should run this separately, since this part actually doesn't require verification
        console2.log("Hsg deployed to: %s\nSafe deployed to: %s", hsg, safe);

        vm.stopBroadcast();
    }
}

// forge verify-contract 0x57bbb5bBa304Df937Bd1086bC0B220442024d1E0 DelegateCanceller --constructor-args $(cast abi-encode "constructor(address,address,uint256)" 0xa9347068F7C903B3530192f121D8a896260f25D1 0xB90b42a823d5d8462CDE39efA3BEAe17FB4d27Ec 10) --chain-id 11155111 --watch