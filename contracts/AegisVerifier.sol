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

contract AegisVerifier {
    IVerifier public immutable verifier;
    mapping(bytes32 => bool) public usedNullifiers;

    event FundsReleased(address indexed to, uint256 amount);

    constructor(address _verifier) {
        require(_verifier != address(0), "Invalid verifier address");
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
        
        // 1. Check nullifier
        require(!usedNullifiers[nullifierHash], "Proof already used");
        
        // 2. Verify proof
        require(verifier.verifyProof(a, b, c, publicInputs), "Invalid proof");
        
        // 3. Update state
        usedNullifiers[nullifierHash] = true;
        
        // 4. Execute effect
        (bool success, ) = _depositor.call{value: _amount}("");
        require(success, "Transfer failed");
        
        emit FundsReleased(_depositor, _amount);
    }

    receive() external payable {}
}