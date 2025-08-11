<div align="center">

🛡️ Aegis: A ZKP-Based Security Paradigm for Cross-Chain Bridges
A provably secure, trust-minimized protocol to mitigate the most common cross-chain bridge exploits using Zero-Knowledge Proofs.

</div>

<p align="center">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/Solidity-^0.8.19-blue?logo=solidity" alt="Solidity Version">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/Hardhat-^2.22.0-blue?logo=hardhat" alt="Hardhat">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/Circom-2.0.0-blue" alt="Circom">
<img src="https://www.google.com/search?q=https://img.shields.io/badge/License-MIT-yellow" alt="License">
</p>

📖 Abstract
Cross-chain bridges, with a liability of over $2.5 billion in exploited funds, signify a foundational crisis of trust in the DeFi space. These catastrophic failures have emerged from flawed assumptions of trust inherent in architectures that rely on vulnerable validator sets. This paper addresses this systemic threat by proposing and validating Aegis, a protocol that leverages ZKPs for trustless state verification. To validate our approach, we implemented a proof-of-concept on a local Hardhat network and benchmarked it against a baseline validator-set model. Subsequently, we subjected each system to simulated attack vectors inspired by high-profile exploits. This repository contains the full implementation, test suite, and benchmark results of that research.

💡 The Problem: A Foundational Crisis of Trust
Traditional cross-chain bridges rely on a small set of validators to approve transactions. If a majority of these validators' private keys are compromised—a common attack vector—malicious actors can unilaterally drain the bridge of all its funds. This creates a centralized point of failure and has been the root cause of the largest hacks in DeFi history. Security is based on trusting a few, which has proven to be a flawed model.

🛡️ The Solution: Trustless Verification with Aegis
Aegis eliminates this trusted validator set entirely. Instead of relying on signatures, it uses a Groth16 ZK-SNARK to prove the validity of a withdrawal.

A user wishing to withdraw funds generates a cryptographic proof that they initiated a valid deposit event, without revealing any sensitive information. The on-chain smart contract simply verifies this mathematical proof.

This means that even if every "validator" were compromised, they would be powerless to forge a proof and steal funds. Security is enforced by math, not by trust.

🛠️ Tech Stack
Category

Technology

Smart Contracts

Solidity ^0.8.19

ZK Circuits

Circom 2.0.0

ZK Proving System

snarkjs (Groth16)

Development

Hardhat, Ethers.js, Chai

Cryptography

circomlib (Poseidon Hash)

📊 V2 Benchmark Results
These results were achieved after implementing comprehensive gas and circuit-level optimizations. The tests empirically prove the security of Aegis while establishing an honest L1 performance benchmark.

Metric

Result

Status

Security Validation

100% Success Rate vs. Exploit

✅ Achieved

Proof Generation Latency

0.363 seconds

✅ Achieved

Optimized Baseline Gas

82,265 gas

-

Aegis Verifier Gas

267,583 gas

-

Final Gas Overhead (L1)

225.27%

-

🚀 Getting Started
Follow these steps to set up the project locally, re-compile the circuit, and run the full test suite to verify the results.

Prerequisites
Node.js (v18 or later)

NPM

1. Installation
Clone the repository and install the required dependencies.

git clone <your-repo-url>
cd Aegis
npm install

2. ZK Circuit Compilation & Setup
These commands compile the Circom circuit and perform the trusted setup required to generate proofs.

# 1. Compile the circuit (generates .r1cs and .wasm files)
circom circuits/AegisCircuit.circom --r1cs --wasm --sym -o circuits

# 2. Start the Powers of Tau ceremony
snarkjs powersoftau new bn128 12 pot12_0000.ptau -v

# 3. Contribute to the ceremony
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v

# 4. Finalize the ceremony
snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v

# 5. Setup the circuit-specific proving and verification keys
snarkjs groth16 setup circuits/AegisCircuit.r1cs pot12_final.ptau circuits/AegisCircuit_0000.zkey

# 6. Contribute to the circuit-specific key
snarkjs zkey contribute circuits/AegisCircuit_0000.zkey circuits/AegisCircuit_final.zkey --name="Niomi's Aegis Key" -v

# 7. Export the verification key as a JSON file
snarkjs zkey export verificationkey circuits/AegisCircuit_final.zkey circuits/verification_key.json

# 8. IMPORTANT: Export the verifier contract
snarkjs zkey export solidityverifier circuits/AegisCircuit_final.zkey contracts/Groth16Verifier.sol

3. Running the Tests
After the setup is complete, run the full test suite. This will deploy the contracts, simulate the attacks, and generate the gas benchmark report in your terminal.

npx hardhat test

🗺️ V2 Roadmap: Future Work
The V1 implementation of Aegis established a crucial performance benchmark on an L1 environment. The V2 roadmap focuses on enhancing economic feasibility for production use.

Chosen L2: Polygon zkEVM

Reasoning: As a ZK-native project, deploying Aegis to a ZK-Rollup offers thematic synergy and leverages cutting-edge scaling technology. Polygon zkEVM provides strong EVM-compatibility, which allows for a seamless migration of the existing smart contracts.

Projected Impact: Migrating the AegisVerifier contract to a Layer 2 network is projected to reduce gas overhead by over 90%, making the protocol economically viable for widespread adoption without compromising its cryptographic security.
