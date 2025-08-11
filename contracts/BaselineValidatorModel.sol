// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title BaselineValidatorModel (Gas Optimized)
 * @author Niomi Langaliya & Dr. Gemini
 * @notice This version has been optimized for gas efficiency. The primary
 * optimization replaces the `validators` array and the `isValidator` loop
 * with a mapping for O(1) lookups, significantly reducing gas costs for
 * signature verification. All require strings have also been converted to
 * custom errors for cheaper reverts.
 */
contract BaselineValidatorModel {
    // ✨ GAS OPTIMIZATION: Using a mapping for validator checks is much cheaper (O(1) complexity)
    // than iterating through an array (O(n) complexity).
    mapping(address => bool) public isValidator;
    uint256 public immutable validatorCount;
    uint256 public immutable threshold;
    mapping(bytes32 => bool) public executedTransactions;

    // ✨ GAS OPTIMIZATION: Custom errors are cheaper than require strings.
    error ExactlyFiveValidatorsRequired();
    error InsufficientSignatures();
    error TransactionAlreadyExecuted();
    error InvalidSigner();
    error SignersNotInAscendingOrder();
    error TransactionFailed();
    error InvalidSignatureLength();

    event TransactionExecuted(
        address indexed to,
        uint256 value,
        bytes data,
        bytes32 txHash
    );

    constructor(address[] memory _validators) {
        if (_validators.length != 5) {
            revert ExactlyFiveValidatorsRequired();
        }

        // ✨ GAS OPTIMIZATION: Populate the mapping once at deployment.
        for (uint256 i = 0; i < _validators.length; i++) {
            address validator = _validators[i];
            // Ensures no zero-address validators are added.
            require(validator != address(0), "Invalid validator address");
            isValidator[validator] = true;
        }

        validatorCount = 5;
        threshold = 3;
    }

    function executeTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        bytes[] calldata signatures
    ) external {
        bytes32 messageHash = getMessageHash(to, value, data);
        bytes32 ethSignedMessageHash = getEthSignedMessageHash(messageHash);

        if (signatures.length < threshold) {
            revert InsufficientSignatures();
        }
        if (executedTransactions[ethSignedMessageHash]) {
            revert TransactionAlreadyExecuted();
        }

        address lastSigner = address(0);

        for (uint i = 0; i < signatures.length; i++) {
            address signer = recoverSigner(ethSignedMessageHash, signatures[i]);
            
            // ✨ GAS OPTIMIZATION: Replaced the expensive loop-based `isValidator(signer)`
            // call with a cheap O(1) mapping lookup.
            if (!isValidator[signer]) {
                revert InvalidSigner();
            }
            if (signer <= lastSigner) {
                revert SignersNotInAscendingOrder();
            }
            lastSigner = signer;
        }

        executedTransactions[ethSignedMessageHash] = true;
        (bool success, ) = to.call{value: value}(data);
        if (!success) {
            revert TransactionFailed();
        }

        emit TransactionExecuted(to, value, data, ethSignedMessageHash);
    }

    function getMessageHash(
        address to,
        uint256 value,
        bytes calldata data
    ) public view returns (bytes32) {
        return keccak256(abi.encodePacked(address(this), to, value, data));
    }

    function getEthSignedMessageHash(bytes32 messageHash) public pure returns (bytes32) {
        return keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );
    }

    function recoverSigner(bytes32 _ethSignedMessageHash, bytes memory _signature) public pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(_signature);
        return ecrecover(_ethSignedMessageHash, v, r, s);
    }

    function splitSignature(bytes memory sig) public pure returns (bytes32 r, bytes32 s, uint8 v) {
        // ✨ GAS OPTIMIZATION: Using a custom error for the revert.
        if (sig.length != 65) {
            revert InvalidSignatureLength();
        }
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}
