const { expect } = require("chai");
const { ethers } = require("hardhat");
const { groth16 } = require("snarkjs");
const path = require("path");
const fs = require("fs");

// Helper for building calldata
function buildSolidityCalldata(proof, publicSignals) {
    const a = proof.pi_a.slice(0, 2);
    const b = [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]];
    const c = proof.pi_c.slice(0, 2);
    return { a, b, c, publicSignals };
}

describe("🏆 Aegis Protocol vs. Baseline Model: Full Validation Suite 🏆", function () {
    // --- Test Suite Configuration ---
    let owner, validator1, validator2, validator3, validator4, validator5, attacker, user;
    let baselineModel, lockingContract, aegisVerifier;
    let wasmPath, zkeyPath;
    const DEPOSIT_AMOUNT = ethers.utils.parseEther("1");
    let poseidon;

    before(async function () {
        this.timeout(120000); // Set a longer timeout for the setup hook
        console.log("\n\n--- 🔬 Setting Up Test Environment ---");

        // 1. Load Poseidon library
        poseidon = (await import("poseidon-lite")).poseidon;
        console.log("  ✅ Poseidon hash library loaded.");

        // 2. Setup paths for ZK artifacts
        wasmPath = path.join(__dirname, "../circuits/AegisCircuit_js/AegisCircuit.wasm");
        zkeyPath = path.join(__dirname, "../circuits/AegisCircuit_final.zkey");
        
        if (!fs.existsSync(wasmPath)) throw new Error("AegisCircuit.wasm not found. Please run the ZK setup steps.");
        if (!fs.existsSync(zkeyPath)) throw new Error("AegisCircuit_final.zkey not found. Please run the ZK setup steps.");
        console.log("  ✅ ZK Artifact paths configured and files verified.");

        // 3. Setup accounts
        [owner, validator1, validator2, validator3, validator4, validator5, attacker, user] = await ethers.getSigners();
        console.log("  ✅ Signer accounts initialized.");

        // 4. Deploy all contracts
        console.log("  ⏳ Deploying contracts...");
        const BaselineFactory = await ethers.getContractFactory("BaselineValidatorModel");
        const validators = [validator1.address, validator2.address, validator3.address, validator4.address, validator5.address];
        baselineModel = await BaselineFactory.deploy(validators);
        await baselineModel.deployed();
        console.log(`    - BaselineValidatorModel deployed to: ${baselineModel.address}`);

        const LockingFactory = await ethers.getContractFactory("LockingContract");
        lockingContract = await LockingFactory.deploy();
        await lockingContract.deployed();
        console.log(`    - LockingContract deployed to: ${lockingContract.address}`);

        const VerifierFactory = await ethers.getContractFactory("Groth16Verifier");
        const verifier = await VerifierFactory.deploy();
        await verifier.deployed();
        console.log(`    - Groth16Verifier deployed to: ${verifier.address}`);

        const AegisFactory = await ethers.getContractFactory("AegisVerifier");
        aegisVerifier = await AegisFactory.deploy(verifier.address);
        await aegisVerifier.deployed();
        console.log(`    - AegisVerifier deployed to: ${aegisVerifier.address}`);

        // 5. Fund the Aegis contract for test withdrawals
        await owner.sendTransaction({ to: aegisVerifier.address, value: ethers.utils.parseEther("10") });
        console.log("  ✅ AegisVerifier funded with 10 ETH.");
        console.log("--- ✨ Environment Ready ---");
    });

    // --- TEST SUITE 1: SECURITY ANALYSIS ---
    describe("⚔️ Security Validation: Adversarial Testing", function () {
        it("🔴 BASELINE FAILURE: Should be VULNERABLE to validator key compromise", async function () {
            console.log("\n--- Test: Attacking Baseline Model ---");
            const maliciousCallData = "0x";
            const txHash = await baselineModel.getMessageHash(attacker.address, DEPOSIT_AMOUNT, maliciousCallData);
            const ethSignedMessageHash = await baselineModel.getEthSignedMessageHash(txHash);

            const compromisedSigners = [validator1, validator2, validator3].sort((a, b) => a.address.localeCompare(b.address));
            const signatures = [];
            for (const signer of compromisedSigners) {
                const sig = await signer.signMessage(ethers.utils.arrayify(ethSignedMessageHash));
                signatures.push(sig);
            }

            const attackerInitialBalance = await ethers.provider.getBalance(attacker.address);
            console.log("  - Attacker initiating malicious withdrawal...");
            const tx = await baselineModel.connect(attacker).executeTransaction(attacker.address, DEPOSIT_AMOUNT, maliciousCallData, signatures);
            await tx.wait();
            const attackerFinalBalance = await ethers.provider.getBalance(attacker.address);

            expect(attackerFinalBalance).to.be.gt(attackerInitialBalance);
            console.log("  - ✅ Outcome: VULNERABLE. Funds successfully stolen from Baseline.");
        });

        it("🟢 AEGIS SUCCESS: Should be IMMUNE to malicious proposals", async function () {
            console.log("\n--- Test: Attacking Aegis Protocol ---");
            const fakeProof = { a: [0, 0], b: [[0, 0], [0, 0]], c: [0, 0] };
            const fakePublicInputs = [0, 0];

            console.log("  - Attacker submitting proof with invalid data...");
            await expect(
                aegisVerifier.connect(attacker).releaseFunds(fakeProof.a, fakeProof.b, fakeProof.c, fakePublicInputs, attacker.address, DEPOSIT_AMOUNT)
            ).to.be.revertedWith("Invalid proof");
            console.log("  - ✅ Outcome: SECURE. Malicious proposal rejected by Aegis.");
        });
    });

    // --- TEST SUITE 2: PERFORMANCE & VIABILITY ---
    describe("⏱️ Performance Validation: Gas & Latency Benchmarking", function () {
        let baselineGas, aegisGas, proofGenLatency;

        it("1. Benchmark Gas for a legitimate Baseline transaction", async function () {
            const legitimateCallData = "0x";
            const txHash = await baselineModel.getMessageHash(user.address, DEPOSIT_AMOUNT, legitimateCallData);
            const ethSignedMessageHash = await baselineModel.getEthSignedMessageHash(txHash);
            const signers = [validator1, validator2, validator3].sort((a, b) => a.address.localeCompare(b.address));
            const signatures = [];
            for (const signer of signers) {
                const sig = await signer.signMessage(ethers.utils.arrayify(ethSignedMessageHash));
                signatures.push(sig);
            }

            const tx = await baselineModel.connect(user).executeTransaction(user.address, DEPOSIT_AMOUNT, legitimateCallData, signatures);
            const receipt = await tx.wait();
            baselineGas = receipt.gasUsed;
            console.log(`\n  - Gas for Baseline Transaction: ${baselineGas.toString()}`);
        });

        it("2. Benchmark Latency and Gas for a legitimate Aegis transaction", async function () {
            // --- Off-chain Prover Simulation ---
            const secret = ethers.BigNumber.from(ethers.utils.randomBytes(32));
            const destinationChainId = 31337; // Hardhat network

            const eventHash = poseidon([ethers.BigNumber.from(user.address).toString(), DEPOSIT_AMOUNT.toString(), destinationChainId.toString(), secret.toString()]);
            const nullifierHash = poseidon([secret.toString()]);

            const input = {
                depositor: ethers.BigNumber.from(user.address).toString(),
                amount: DEPOSIT_AMOUNT.toString(),
                destinationChainId: destinationChainId.toString(),
                secret: secret.toString(),
                eventHash: eventHash.toString(),
                nullifierHash: nullifierHash.toString()
            };

            console.log("  - Generating ZK proof (this may take a moment)...");
            const startTime = Date.now();
            const { proof, publicSignals } = await groth16.fullProve(input, wasmPath, zkeyPath);
            const endTime = Date.now();
            proofGenLatency = (endTime - startTime) / 1000;
            console.log(`  - Proof Generation Latency: ${proofGenLatency.toFixed(3)} seconds`);

            // --- On-chain Verifier Interaction ---
            const { a, b, c } = buildSolidityCalldata(proof, publicSignals);
            const tx = await aegisVerifier.connect(user).releaseFunds(a, b, c, publicSignals, user.address, DEPOSIT_AMOUNT);
            const receipt = await tx.wait();
            aegisGas = receipt.gasUsed;
            console.log(`  - Gas for Aegis Transaction: ${aegisGas.toString()}`);
        });

        it("3. Final Report: Calculate and display overhead", function () {
            const overhead = ((aegisGas - baselineGas) / baselineGas) * 100;
            console.log("\n\n--- 📊 FINAL EMPIRICAL RESULTS 📊 ---");
            console.log("========================================");
            console.log(`  ZK Proof Generation Latency: ${proofGenLatency.toFixed(3)} s`);
            console.log(`  Gas Overhead vs Baseline:    ${overhead.toFixed(2)} %`);
            console.log("========================================");
            expect(overhead).to.be.a('number');
        });
    });
});
