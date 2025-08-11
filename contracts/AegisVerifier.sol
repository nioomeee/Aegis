// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

interface IVerifier {
    function verifyProof(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory input
    ) external view returns (bool);
}

/**
 * @title AegisVerifier (Gas Optimized)
 * @author Niomi Langaliya & Dr. Gemini
 * @notice This version has been optimized for gas efficiency by converting
 * all require strings to cheaper custom errors.
 */
contract AegisVerifier {
    IVerifier public immutable verifier;
    mapping(bytes32 => bool) public usedNullifiers;

    // ✨ GAS OPTIMIZATION: Custom errors are cheaper than require strings.
    error InvalidVerifierAddress();
    error ProofAlreadyUsed();
    error InvalidProof();
    error TransferFailed();

    event FundsReleased(address indexed to, uint256 amount);

    constructor(address _verifier) {
        if (_verifier == address(0)) {
            revert InvalidVerifierAddress();
        }
        verifier = IVerifier(_verifier);
    }

    function releaseFunds(
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[2] memory publicInputs,
        address payable _depositor,
        uint256 _amount
    ) external {
        bytes32 nullifierHash = bytes32(publicInputs[1]);
        
        if (usedNullifiers[nullifierHash]) {
            revert ProofAlreadyUsed();
        }
        if (!verifier.verifyProof(a, b, c, publicInputs)) {
            revert InvalidProof();
        }
        
        usedNullifiers[nullifierHash] = true;
        
        (bool success, ) = _depositor.call{value: _amount}("");
        if (!success) {
            revert TransferFailed();
        }
        
        emit FundsReleased(_depositor, _amount);
    }

    receive() external payable {}
}
