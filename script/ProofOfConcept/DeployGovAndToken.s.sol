// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {MyToken} from "../../src/ProofOfConcept/MyToken.sol";
import {MyGovernor} from "../../src/ProofOfConcept/MyGovernor.sol";

contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        // Retrieve private key from environment variable
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address delegateTo = vm.envAddress("DELEGATE_TO");
        
        // Start broadcasting transactions
        vm.startBroadcast(deployerPrivateKey);

        // Deploy the token contract
        MyToken token = new MyToken();
        console.log("Token deployed at:", address(token));

        // Deploy the governor contract with the token address
        MyGovernor governor = new MyGovernor(token);
        console.log("Governor deployed at:", address(governor));

        // Optional: Set up initial token distribution
        // Mint some tokens to the deployer
        token.mint(msg.sender, 100000 * 10**18); // 100,000 tokens
        console.log("Minted initial tokens to deployer:", msg.sender);

        // // Delegate voting power to the deployer
        token.delegate(delegateTo);
        console.log("Delegated voting power to DELEGATE_TO");

        vm.stopBroadcast();
    }
    // // simulate
    // forge script script/ProofOfConcept/DeployGovAndToken.s.sol:DeployScript -f sepolia

    // // deploy
    // forge script script/ProofOfConcept/DeployGovAndToken.s.sol:DeployScript -f sepolia --broadcast --verify
}