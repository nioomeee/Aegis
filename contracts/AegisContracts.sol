// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "hardhat/console.sol";

interface IVerifier {
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory input
    ) external view returns (bool r);
}

/**
 * @title LockingContract
 * @notice This contract lives on the SOURCE chain (e.g., Ethereum).
 * It accepts user deposits and emits a secure, provable event.
 */
contract LockingContract {
    event DepositMade(
        address indexed depositor,
        uint256 indexed amount,
        uint256 indexed destinationChainId,
        bytes32 eventHash
    );

    /**
     * @notice User calls this to deposit funds for bridging.
     * @param _destinationChainId The chain ID of the destination network.
     * @param _secret A secret value chosen by the user, used to generate the hashes.
     */
    function depositForBridge(
        uint256 _destinationChainId,
        uint256 _secret
    ) public payable {
        require(msg.value > 0, "Aegis: Deposit must be > 0");

        bytes32 eventHash = keccak256(
            abi.encodePacked(
                msg.sender,
                msg.value,
                _destinationChainId,
                _secret
            )
        );

        console.logString("Source Chain: Deposit event emitted with hash:");
        console.logBytes32(eventHash);
        emit DepositMade(
            msg.sender,
            msg.value,
            _destinationChainId,
            eventHash
        );
    }
}

/**
 * @title AegisVerifier
 * @notice This contract lives on the DESTINATION chain (e.g., Polygon).
 * It verifies ZK proofs and releases bridged funds.
 */
contract AegisVerifier {
    IVerifier public immutable verifier;
    mapping(bytes32 => bool) public usedNullifiers;

    event FundsReleased(address indexed to, uint256 amount);

    constructor(address verifierAddress) {
        require(verifierAddress != address(0), "Aegis: Invalid verifier address");
        verifier = IVerifier(verifierAddress);
    }

    /**
     * @notice Verifies a ZK proof and releases funds.
     * @param a The ZK proof component 'a'.
     * @param b The ZK proof component 'b'.
     * @param c The ZK proof component 'c'.
     * @param publicInputs The public inputs: [eventHash, nullifierHash].
     * @param _depositor The original depositor's address.
     * @param _amount The deposited amount.
     */
    function releaseFunds(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory publicInputs,
        address payable _depositor, // Changed to payable
        uint256 _amount
    ) public {
        require(_depositor != address(0), "Aegis: Invalid depositor address");
        require(_amount > 0, "Aegis: Amount must be > 0");

        bytes32 nullifierHash = bytes32(publicInputs[1]);
        require(!usedNullifiers[nullifierHash], "Aegis: Proof already used");

        bool isValid = verifier.verifyProof(a, b, c, publicInputs);
        require(isValid, "Aegis: Invalid ZK proof");

        usedNullifiers[nullifierHash] = true;

        (bool success, ) = _depositor.call{value: _amount}("");
        require(success, "Aegis: Fund transfer failed");

        emit FundsReleased(_depositor, _amount);
    }

    // Allow contract to receive funds
    receive() external payable {}
}