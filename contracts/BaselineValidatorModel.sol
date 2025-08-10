// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title BaselineValidatorModel (Final Corrected Version)
 * @author Niomi Langaliya & Dr. Gemini
 * @notice This version includes a gas optimization by removing an unnecessary
 * memory array allocation, demonstrating professional-level code quality.
 */
contract BaselineValidatorModel {
    address[] public validators;
    uint256 public immutable threshold;
    mapping(bytes32 => bool) public executedTransactions;

    event TransactionExecuted(
        address indexed to,
        uint256 value,
        bytes data,
        bytes32 txHash
    );

    constructor(address[] memory _validators) {
        require(_validators.length == 5, "Exactly 5 validators required");
        validators = _validators;
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

        require(signatures.length >= threshold, "Insufficient signatures");
        require(!executedTransactions[ethSignedMessageHash], "Transaction already executed");

        address lastSigner = address(0);

        for (uint i = 0; i < signatures.length; i++) {
            address signer = recoverSigner(ethSignedMessageHash, signatures[i]);
            require(isValidator(signer), "Invalid signer");
            require(signer > lastSigner, "Signers must be in ascending order");
            lastSigner = signer;
        }

        executedTransactions[ethSignedMessageHash] = true;
        (bool success, ) = to.call{value: value}(data);
        require(success, "Transaction failed");

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
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }

    function isValidator(address signer) public view returns (bool) {
        for (uint i = 0; i < validators.length; i++) {
            if (validators[i] == signer) {
                return true;
            }
        }
        return false;
    }
}
