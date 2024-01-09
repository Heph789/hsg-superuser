// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

// import { Test, console2 } from "forge-std/Test.sol"; // remove after testing
import { HatsSignerGateBase, IGnosisSafe, Enum } from "./HatsSignerGateBase.sol";
import { TimelockController } from "@openzeppelin/contracts/governance/TimelockController.sol";
import "./HSGLib.sol";

contract HSGSuperMod is HatsSignerGateBase {
    uint256 public signersHatId;
    TimelockController public timelock; // should probably switch the access to this later


    /// @notice Initializes a new instance of HatsSignerGate
    /// @dev Can only be called once
    /// @param initializeParams ABI-encoded bytes with initialization parameters
    function setUp(bytes calldata initializeParams) public payable override initializer {
        (
            uint256 _ownerHatId,
            uint256 _signersHatId,
            address _safe,
            address _hats,
            address payable _timelock,
            uint256 _minThreshold,
            uint256 _targetThreshold,
            uint256 _maxSigners,
            string memory _version,
        ) = abi.decode(
            initializeParams, (uint256, uint256, address, address, address, uint256, uint256, uint256, string, uint256)
        );

        _setUp(_ownerHatId, _safe, _hats, _minThreshold, _targetThreshold, _maxSigners, _version);

        signersHatId = _signersHatId;

        timelock = TimelockController(_timelock);
    }

    /// @notice Function to become an owner on the safe if you are wearing the signers hat
    /// @dev Reverts if `maxSigners` has been reached, the caller is either invalid or has already claimed. Swaps caller with existing invalid owner if relevant.
    function claimSigner() public virtual {
        uint256 maxSigs = maxSigners; // save SLOADs
        address[] memory owners = safe.getOwners();
        uint256 currentSignerCount = _countValidSigners(owners);

        if (currentSignerCount >= maxSigs) {
            revert MaxSignersReached();
        }

        if (safe.isOwner(msg.sender)) {
            revert SignerAlreadyClaimed(msg.sender);
        }

        if (!isValidSigner(msg.sender)) {
            revert NotSignerHatWearer(msg.sender);
        }

        /*
        We check the safe owner count in case there are existing owners who are no longer valid signers.
        If we're already at maxSigners, we'll replace one of the invalid owners by swapping the signer.
        Otherwise, we'll simply add the new signer.
        */
        uint256 ownerCount = owners.length;
        if (ownerCount >= maxSigs) {
            bool swapped = _swapSigner(owners, ownerCount, msg.sender);
            if (!swapped) {
                // if there are no invalid owners, we can't add a new signer, so we revert
                revert NoInvalidSignersToReplace();
            }
        } else {
            _grantSigner(owners, currentSignerCount, msg.sender);
        }
    }

    /// @notice Checks if `_account` is a valid signer, ie is wearing the signer hat
    /// @dev Must be implemented by all flavors of HatsSignerGate
    /// @param _account The address to check
    /// @return valid Whether `_account` is a valid signer
    function isValidSigner(address _account) public view override returns (bool valid) { // NOTE: might want to reconcile signers before trying to call this
        valid = HATS.isWearerOfHat(_account, signersHatId);
    }

    // Chase's edits (yay)

    /// @notice Allows admin to execute arbitrary transactions from the safe
    /// @dev Params mirror safe.execTransactionFromModule() with exception to call type
    function superExecute(address to, uint256 value, bytes memory data) external {
        if (!HATS.isAdminOfHat(msg.sender, signersHatId)) revert("Not admin");
        if (address(safe).balance < value) revert("Insufficient balance");
        bool executed = safe.execTransactionFromModule(
            to,
            value,
            data,
            Enum.Operation.Call // we force it to be a call since transactions should come from safe, not the module
        );
        if (!executed) revert("Could not execute.");
    }

    /// @notice wraps an execution to be proposed through the timelock controller. signers can just create an execution like they would normally and it will handle the timelock stuff
    /// @dev Params mirror safe.execTransaction
    function scheduleTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures
    ) public payable returns (bytes32) {
        require(isValidSigner(msg.sender), "Non-signer trying to schedule transaction."); // in current implementation, ANYONE wearing the signer hat can execute transactions, not just those on the multi-sig
        bytes memory call = abi.encodeWithSignature(
            "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
            to,
            value,
            data,
            operation,
            safeTxGas,
            baseGas,
            gasPrice,
            gasToken,
            refundReceiver,
            signatures
        );
        timelock.schedule(
            address(safe), // target
            0, // value
            call, // data
            bytes32(0), // predecessor
            bytes32(0), // salt. NOTE: should eventually auto increment salt for repeat proposals
            timelock.getMinDelay() // delay
        );
        // Since timelock already logs scheduled transactions, probably don't need to log here. Maybe don't even need to return data. 
        return timelock.hashOperation(
            address(safe), // target
            0, // value
            call, // data
            bytes32(0), // predecessor
            bytes32(0) // salt
        );
    }

    /// @notice Executes a previously scheduled timelock transaction. Proposal must be READY in timelock controller. 
    /// @dev params mirror safe.execTransaction
    function executeTimelockTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures
    ) public payable {
        require(isValidSigner(msg.sender), "Non-signer trying to execute transaction."); // in current implementation, ANYONE wearing the signer hat can execute transactions, not just those on the multi-sig
        bytes memory call = abi.encodeWithSignature(
            "execTransaction(address,uint256,bytes,uint8,uint256,uint256,uint256,address,address,bytes)",
            to,
            value,
            data,
            operation,
            safeTxGas,
            baseGas,
            gasPrice,
            gasToken,
            refundReceiver,
            signatures
        );
        timelock.execute(
            address(safe), // target
            0, // value
            call, // data
            bytes32(0), // predecessor
            bytes32(0) // salt
        );
    }

    /// @notice prevent user from executing transactions outside of timelock
    /// @dev params mirror checkTransaction (HatsSignerGateBase)
    function _additionalCheckTransaction(
        address to,
        uint256,
        bytes calldata,
        Enum.Operation,
        uint256,
        uint256,
        uint256,
        address,
        address payable,
        bytes memory,
        address msgSender
    ) override internal view {
        // requires regular transactions to go through the timelock
        if (msgSender != address(timelock)) require(to == address(timelock), "Transactions must go through the timelock.");
    }
}
