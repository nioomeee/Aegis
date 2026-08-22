<div align="center">

<img src="https://img.shields.io/badge/status-research%20prototype-blueviolet?style=for-the-badge" />
<img src="https://img.shields.io/badge/license-MIT-informational?style=for-the-badge" />
<img src="https://img.shields.io/badge/version-v2.0-success?style=for-the-badge" />

# 🛡️ AEGIS

### *Zero-Knowledge Security for Cross-Chain Bridges*

**Aegis** is a ZKP-native bridge security protocol that replaces fragile multisig trust models with cryptographic certainty — where **math enforces security, not validators.**  
Built with Groth16 zkSNARKs and on-chain verification circuits, Aegis enables trustless, verifiable cross-chain message passing without any centralized point of failure.

---

![Solidity](https://img.shields.io/badge/Solidity-%5E0.8.19-363636?style=flat-square&logo=solidity&logoColor=white)
![Circom](https://img.shields.io/badge/Circom-2.0.0-6E40C9?style=flat-square&logo=ethereum&logoColor=white)
![snarkjs](https://img.shields.io/badge/snarkjs-Groth16-FF6B6B?style=flat-square&logo=ethereum)
![Hardhat](https://img.shields.io/badge/Hardhat-Dev%20Env-yellow?style=flat-square&logo=ethereum)
![Ethers.js](https://img.shields.io/badge/Ethers.js-v6-2535A0?style=flat-square&logo=javascript&logoColor=white)
![Chai](https://img.shields.io/badge/Chai-Testing-A30701?style=flat-square&logo=mocha&logoColor=white)
![Node.js](https://img.shields.io/badge/Node.js-v18%2B-339933?style=flat-square&logo=nodedotjs&logoColor=white)
![Poseidon](https://img.shields.io/badge/Crypto-Poseidon%20Hash-8E44AD?style=flat-square)
![Polygon zkEVM](https://img.shields.io/badge/Target%20L2-Polygon%20zkEVM-8247E5?style=flat-square&logo=polygon&logoColor=white)

</div>

---

## 📋 Table of Contents

- [Abstract](#-abstract)
- [The Problem](#-the-problem-a-foundational-crisis-of-trust)
- [The Solution](#-the-solution-trustless-verification-with-aegis)
- [Architecture](#-architecture)
- [Tech Stack](#️-tech-stack)
- [Benchmark Results](#-benchmark-results-v2)
- [Getting Started](#-getting-started)
- [Project Structure](#-project-structure)
- [Future Work](#️-roadmap--future-work)
- [Author](#️-author)

---

## 📖 Abstract

Cross-chain bridges represent a **$2.5B+ liability** in the DeFi ecosystem — not from implementation bugs, but from a foundational crisis of trust. Architectures that rely on vulnerable validator sets create centralized points of failure that have been exploited repeatedly.

**Aegis** proposes and validates a new paradigm: replace validator trust with **zero-knowledge cryptography**. By using Groth16 zkSNARKs, any withdrawal can be proven valid without revealing sensitive data, and no compromised validator can forge a proof. This repository contains the full proof-of-concept implementation, test suite, and benchmark results.

---

## 💀 The Problem: A Foundational Crisis of Trust

```
Traditional Bridge Architecture — The Attack Surface
─────────────────────────────────────────────────────

  Chain A            Validator Set          Chain B
  ───────       ┌────────────────────┐      ───────
  Deposit  ───► │  Val 1 | Val 2 | Val 3 │ ───►  Release
                └────────────────────┘
                         ▲
                         │
                  ☠️  EXPLOIT HERE
              Compromise 2 of 3 keys
              → Drain entire bridge
```

Traditional bridges trust a **small, enumerable set of validators** to approve transactions. The math is simple and brutal:

- **Compromise `m` of `n` keys** → drain everything
- **Attack surface** = a handful of private keys
- **Security model** = hope nobody gets hacked

This has failed. Repeatedly. At billion-dollar scale.

---

## 🛡️ The Solution: Trustless Verification with Aegis

```
Aegis Architecture — Zero Attack Surface
──────────────────────────────────────────────────────────────────

  Chain A                 Off-Chain Prover              Chain B
  ───────                 ────────────────              ───────

  [ Deposit Event ]                                  [ AegisVerifier.sol ]
       │                                                      │
       │   ┌──────────────────────────────────┐               │
       └──►│         AegisCircuit.circom       │               │
           │                                  │               │
           │  Private Inputs:                 │               │
           │    • deposit secret              │               │
           │    • nullifier                   │               │
           │                                  │               │
           │  Public Inputs:                  │               │
           │    • eventHash                   │               │
           │    • nullifierHash               │               │
           │                                  │               │
           │  Output: π (Groth16 Proof)       │               │
           └──────────────────────────────────┘               │
                         │                                     │
                         │     π submitted on-chain            │
                         └────────────────────────────────────►│
                                                               │
                                               verifyProof(π) ──► ✅ / ❌
                                                               │
                                                       [ Release Funds ]

  ☠️  Validators compromised? Irrelevant. Math can't be forged.
```

**How it works:**

1. **Deposit** — User deposits funds on Chain A; a commitment hash is stored on-chain
2. **Prove** — User locally generates a Groth16 ZK proof of their valid deposit, off-chain
3. **Verify** — The `AegisVerifier` contract on Chain B verifies the mathematical proof
4. **Withdraw** — Funds are released. No validator signed off. No trust was extended.

---

## 🛠️ Tech Stack

| Layer | Technology | Role |
|-------|-----------|------|
| **Smart Contracts** | Solidity `^0.8.19` | On-chain verifier and bridge logic |
| **ZK Circuits** | Circom `2.0.0` | Constraint system for proof generation |
| **Proving System** | snarkjs · Groth16 | Proof generation and trusted setup |
| **Cryptography** | circomlib · Poseidon Hash | ZK-friendly hash function |
| **Dev Environment** | Hardhat · Ethers.js | Local network, deployment, scripting |
| **Testing** | Chai | Unit and integration test suite |
| **Target L2** | Polygon zkEVM | Production deployment target |

---

## 📊 Benchmark Results (v2)

> All benchmarks were run on a local Hardhat network simulating an L1 environment.


| Metric | Result | Status |
|--------|--------|--------|
| 🔐 Security Validation | 100% success rate vs. simulated exploit | ✅ Achieved |
| ⚡ Proof Generation Latency | **0.363 seconds** | ✅ Achieved |
| 📦 Baseline Validator Gas | 82,265 gas | — |
| 📦 Aegis Verifier Gas | 267,583 gas | — |
| 📈 Gas Overhead (L1) | **225.27%** | ⚙️ Benchmark Established |


| **Merkle Membership Proof** | Circuit does not yet verify the deposit belongs to a tracked set on Chain A — currently only proves knowledge of the pre-image hash and binds a nullifier. Membership proof is a planned V2 addition. |

> **Note on Gas:** The L1 overhead is a known and expected tradeoff for cryptographic verification. The [V2 roadmap](#️-roadmap--future-work) projects **>90% gas reduction** via Polygon zkEVM deployment, making the protocol economically viable.

---

## 🚀 Getting Started

### Prerequisites

- Node.js `v18+` and `npm`
- Circom `2.0.0` — [Install Guide](https://docs.circom.io/getting-started/installation/)
- snarkjs — installed automatically via `npm install`

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/nioomeee/Aegis.git
cd Aegis

# 2. Install all dependencies
npm install
```

### ZK Circuit Setup (One-Time)

This performs the trusted setup ceremony and generates all proving/verification keys.

```bash
# Compile the Circom circuit → produces .r1cs and .wasm files
circom circuits/AegisCircuit.circom --r1cs --wasm --sym -o circuits

# --- Powers of Tau Ceremony (Groth16 Trusted Setup) ---

# Phase 1: Initialize ceremony
snarkjs powersoftau new bn128 12 pot12_0000.ptau -v

# Phase 1: Contribute entropy
snarkjs powersoftau contribute pot12_0000.ptau pot12_0001.ptau \
  --name="First contribution" -v

# Phase 1: Finalize
snarkjs powersoftau prepare phase2 pot12_0001.ptau pot12_final.ptau -v

# Phase 2: Circuit-specific setup
snarkjs groth16 setup circuits/AegisCircuit.r1cs pot12_final.ptau \
  circuits/AegisCircuit_0000.zkey

# Phase 2: Contribute to circuit key
snarkjs zkey contribute circuits/AegisCircuit_0000.zkey \
  circuits/AegisCircuit_final.zkey --name="Niomi's Aegis Key" -v

# Export keys
snarkjs zkey export verificationkey \
  circuits/AegisCircuit_final.zkey circuits/verification_key.json

# Export Solidity verifier contract
snarkjs zkey export solidityverifier \
  circuits/AegisCircuit_final.zkey contracts/Groth16Verifier.sol
```

### Run Tests & Benchmarks

```bash
npx hardhat test
```

---

## 📁 Project Structure

```
Aegis/
├── circuits/
│   ├── AegisCircuit.circom          # Main ZK circuit definition
│   ├── AegisCircuit.r1cs            # Compiled constraint system
│   ├── AegisCircuit_final.zkey      # Final proving key
│   ├── verification_key.json        # Exported verification key
│   └── build/
│       └── AegisCircuit_js/         # WASM witness generator
│
├── contracts/
│   ├── AegisBridge.sol              # Core bridge contract
│   └── Groth16Verifier.sol          # Auto-generated ZK verifier
│
├── test/
│   └── aegis.test.js                # Full test & benchmark suite
│
├── hardhat.config.js
└── package.json
```

---

## 🗺️ Roadmap & Future Work

### V1 — ✅ Complete
- Proof-of-concept on local Hardhat (L1 simulation)
- Groth16 circuit + on-chain verifier
- Full exploit simulation benchmark

### V2 — 🔄 In Progress

| Goal | Detail |
|------|--------|
| **L2 Deployment** | Migrate to **Polygon zkEVM** for ZK-native synergy and full EVM compatibility |
| **Gas Reduction** | Projected **>90% reduction** in gas overhead on L2 |
| **Production Viability** | Make the protocol economically feasible for real-world bridge deployments |
| **Recursive Proofs** | Explore proof aggregation for batched cross-chain messages |

> **Why Polygon zkEVM?** As a ZK-Rollup, it natively compresses verification costs — the exact overhead that makes L1 Aegis deployment expensive becomes negligible on an L2 designed around ZK proofs.

---

## ✍️ Author

**Niomi Langaliya**  
[![GitHub](https://img.shields.io/badge/GitHub-nioomeee-181717?style=flat-square&logo=github)](https://github.com/nioomeee)

---

<div align="center">

*Security enforced by math, not trust.*

**⭐ Star this repo if you find it useful!**

</div>
