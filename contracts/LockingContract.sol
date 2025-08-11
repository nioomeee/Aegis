// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

/**
 * @title LockingContract (Gas Optimized)
 * @author Niomi Langaliya & Dr. Gemini
 * @notice This version has been optimized for gas efficiency by converting
 * the require string to a cheaper custom error.
 */
contract LockingContract {
    // ✨ GAS OPTIMIZATION: Custom errors are cheaper than require strings.
    error ZeroDepositNotAllowed();

    event DepositMade(
        address indexed depositor,
        uint256 indexed amount,
        uint256 indexed destinationChainId,
        bytes32 eventHash
    );

    function depositForBridge(
        uint256 _destinationChainId,
        uint256 _secret
    ) external payable {
        if (msg.value == 0) {
            revert ZeroDepositNotAllowed();
        }

        bytes32 eventHash = keccak256(
            abi.encodePacked(
                msg.sender,
                msg.value,
                _destinationChainId,
                _secret
            )
        );

        emit DepositMade(
            msg.sender,
            msg.value,
            _destinationChainId,
            eventHash
        );
    }
}
