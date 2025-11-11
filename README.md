# 🛡️ Aegis: A ZKP-Based Security Paradigm for Cross-Chain Bridge Exploits  

Aegis introduces a **Zero-Knowledge Proof-based framework** to secure cross-chain bridge communication by eliminating overreliance on multisig trust models.  
This system integrates **zkSNARKs**, **Groth16**, and **on-chain verification circuits** to ensure **trustless, verifiable message passing** between heterogeneous blockchains.

---

## 📋 Table of Contents
- [Abstract](#-abstract)
- [The Problem](#-the-problem)
- [The Solution: Aegis](#-the-solution-aegis)
- [Tech Stack](#️-tech-stack)
- [Benchmark Results](#-benchmark-results)
- [Getting Started](#-getting-started)
- [Future Work](#️-future-work)
- [Author](#️-author)

---

## 📖 Abstract  

Cross-chain bridges, with a liability of over **$2.5 billion** in exploited funds, signify a foundational crisis of trust in the DeFi space.  
These catastrophic failures have emerged from flawed assumptions of trust inherent in architectures that rely on vulnerable validator sets.  

This paper addresses this systemic threat by proposing and validating **Aegis**, a protocol that leverages ZKPs for **trustless state verification**.  
To validate our approach, we implemented a proof-of-concept on a local Hardhat network and benchmarked it against a baseline validator-set model.  

This repository contains the full implementation, test suite, and benchmark results of that research.

---

## 💡 The Problem: A Foundational Crisis of Trust  

Traditional cross-chain bridges rely on a small set of validators to approve transactions.  
If a majority of these validators' private keys are compromised—a common attack vector—malicious actors can unilaterally drain the bridge of all its funds.  

This creates a **centralized point of failure** and has been the root cause of the largest hacks in DeFi history.  
Security is based on **trusting a few**, which has proven to be a flawed model.

---

## 🛡️ The Solution: Trustless Verification with Aegis  

Aegis eliminates the trusted validator set entirely.  
Instead of relying on signatures, it uses a **Groth16 ZK-SNARK** to prove the validity of a withdrawal.  

A user wishing to withdraw funds generates a cryptographic proof that they initiated a valid deposit event, without revealing any sensitive information.  
The on-chain smart contract simply verifies this **mathematical proof**.  

This means that even if every validator were compromised, they would be powerless to forge a proof and steal funds.  
Security is enforced by **math, not trust**.  

---

## 🛠️ Tech Stack  

| Category | Technology |
|-----------|-------------|
| Smart Contracts | Solidity ^0.8.19 |
| ZK Circuits | Circom 2.0.0 |
| ZK Proving System | snarkjs (Groth16) |
| Development | Hardhat, Ethers.js, Chai |
| Cryptography | circomlib (Poseidon Hash) |

---

## 📊 Benchmark Results (v2)

| Metric | Result | Status |
|--------|---------|--------|
| Security Validation | 100% Success Rate vs. Exploit | ✅ Achieved |
| Proof Generation Latency | 0.363 seconds | ✅ Achieved |
| Optimized Baseline Gas | 82,265 gas | — |
| Aegis Verifier Gas | 267,583 gas | — |
| Final Gas Overhead (L1) | 225.27% | ⚙️ Benchmark Established |

---

## 🚀 Getting Started  

Follow these steps to set up the project locally, compile the circuits, and run tests.

```bash
# 1️⃣ Prerequisites
# Make sure you have Node.js (v18+) and npm installed.

# 2️⃣ Clone the repository
git clone https://github.com/nioomeee/Aegis.git
cd Aegis

# 3️⃣ Install dependencies
npm install

# 4️⃣ Folder structure (auto-create if missing)
mkdir -p circuits contracts test
mkdir -p circuits/build

# 5️⃣ Compile Circom circuit and perform trusted setup

# Step 1: Compile the circuit (generates .r1cs and .wasm files)
circom circuits/AegisCircuit.circom --r1cs --wasm --sym -o circuits

# Step 2: Start the Powers of Tau ceremony
snarkjs powersoftau new bn128 12 pot12_0000.ptau -v

# Step 3: Contribute to the ceremony
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau --name="First contribution" -v

# Step 4: Finalize the ceremony
snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v

# Step 5: Setup circuit-specific proving and verification keys
snarkjs groth16 setup circuits/AegisCircuit.r1cs pot12_final.ptau circuits/AegisCircuit_0000.zkey

# Step 6: Contribute to circuit-specific key
snarkjs zkey contribute circuits/AegisCircuit_0000.zkey circuits/AegisCircuit_final.zkey --name="Niomi's Aegis Key" -v

# Step 7: Export the verification key
snarkjs zkey export verificationkey circuits/AegisCircuit_final.zkey circuits/verification_key.json

# Step 8: Export Solidity verifier
snarkjs zkey export solidityverifier circuits/AegisCircuit_final.zkey contracts/Groth16Verifier.sol

# 6️⃣ Run tests and benchmarks
npx hardhat test
```

## 🗺️ V2 Roadmap: Future Work

The V1 implementation of Aegis established a crucial performance benchmark on an L1 environment.
The V2 roadmap focuses on enhancing economic feasibility for production.

Chosen L2: Polygon zkEVM
Reasoning: As a ZK-native project, deploying Aegis to a ZK-Rollup offers synergy with cutting-edge scaling technology and strong EVM compatibility.

Projected Impact: Migrating the AegisVerifier contract to a Layer 2 network is projected to reduce gas overhead by over 90%, making the protocol economically viable for widespread adoption.

---

## ✍️ Author

Niomi Langaliya
