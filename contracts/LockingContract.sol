// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract LockingContract {
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
        require(msg.value > 0, "Deposit must be greater than 0");

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