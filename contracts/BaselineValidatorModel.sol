// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import "hardhat/console.sol";

/**
 * @title BaselineValidatorModel
 * @author Niomi Langaliya
 * @notice This contract simulates a traditional 3-of-5 multi-signature bridge.
 * It serves as the baseline for our security and performance comparison against Aegis.
 * Its primary vulnerability is the reliance on a small set of keys, which, if
 * compromised, allows for the complete draining of funds.
 */
contract BaselineValidatorModel {
    // --- State Variables ---

    // The array of validator addresses.
    // NOTE: This is not 'immutable' because arrays are non-value types.
    // However, it is only set once in the constructor and never changed,
    // making it effectively constant.
    address[5] public i_validators;
    uint256 public constant REQUIRED_SIGNATURES = 3;

    // Mapping to prevent replay attacks on the same transaction hash
    mapping(bytes32 => bool) private s_executedTransactions;

    // --- Events ---

    event TransactionExecuted(bytes32 indexed txHash);

    // --- Constructor ---

    constructor(address[5] memory initialValidators) {
        require(initialValidators.length == 5, "Must provide 5 validators");
        i_validators = initialValidators;
    }

    // --- Core Logic ---

    /**
     * @notice Executes a transaction if it has enough valid signatures from validators.
     * @param _to The target address.
     * @param _value The amount of ETH to send.
     * @param _data The calldata for the transaction.
     * @param _signatures An array of signatures from the validators.
     */
    function executeTransaction(
        address _to,
        uint256 _value,
        bytes calldata _data,
        bytes[] calldata _signatures
    ) public {
        // 1. Calculate the transaction hash that the validators should have signed.
        // The hash includes the address of this contract to prevent cross-contract replay attacks.
        bytes32 txHash = getTransactionHash(_to, _value, _data);

        // 2. Check for replays to ensure this exact transaction can't be executed twice.
        require(
            !s_executedTransactions[txHash],
            "Baseline: Transaction already executed"
        );

        // 3. Verify the signatures.
        _verifySignatures(txHash, _signatures);

        // 4. Mark as executed to prevent future replays.
        s_executedTransactions[txHash] = true;

        // 5. Execute the actual call.
        (bool success, ) = _to.call{value: _value}(_data);
        require(success, "Baseline: Transaction failed");

        emit TransactionExecuted(txHash);
    }

    // --- Internal & View Functions ---

    /**
     * @notice Verifies that the required number of valid validator signatures have been provided.
     * @param _txHash The hash of the transaction being verified.
     * @param _signatures The array of signatures to check.
     */
    function _verifySignatures(
        bytes32 _txHash,
        bytes[] calldata _signatures
    ) private view {
        require(
            _signatures.length >= REQUIRED_SIGNATURES,
            "Baseline: Not enough signatures provided"
        );

        address lastSigner = address(0); // To enforce strict ordering and prevent duplicates

        for (uint256 i = 0; i < _signatures.length; i++) {
            bytes32 messageHash = _getEthSignedMessageHash(_txHash);
            address signer = _recoverSigner(messageHash, _signatures[i]);

            // Security Check 1: Ensure the signer is a designated validator.
            require(_isValidator(signer), "Baseline: Signer is not a validator");

            // Security Check 2: Enforce strict ordering of signers.
            // This prevents replay of the same signature within this transaction
            // and is a standard, gas-efficient security pattern.
            require(signer > lastSigner, "Baseline: Invalid signature order");
            
            lastSigner = signer;
        }
    }

    /**
     * @notice Recovers the address of the signer from a signature.
     */
    function _recoverSigner(
        bytes32 _ethSignedMessageHash,
        bytes memory _signature
    ) private pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(
            _signature,
            (bytes32, bytes32, uint8)
        );
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    /**
     * @notice Checks if a given address is one of the designated validators.
     */
    function _isValidator(address _addr) private view returns (bool) {
        for (uint256 i = 0; i < i_validators.length; i++) {
            if (i_validators[i] == _addr) {
                return true;
            }
        }
        return false;
    }

    /**
     * @notice Creates the standard EIP-191 signed message hash.
     */
    function _getEthSignedMessageHash(
        bytes32 _messageHash
    ) private pure returns (bytes32) {
        return
            keccak256(
                abi.encodePacked("\x19Ethereum Signed Message:\n32", _messageHash)
            );
    }

    /**
     * @notice Public view function to calculate the transaction hash.
     */
    function getTransactionHash(
        address _to,
        uint256 _value,
        bytes calldata _data
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), _to, _value, _data));
    }
}
