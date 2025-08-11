const { expect } = require("chai");
const { ethers } = require("hardhat");
const { groth16 } = require("snarkjs");
const path = require("path");
const fs = require("fs");
const { buildPoseidon } = require("circomlibjs");

// Helper function for building calldata
function buildSolidityCalldata(proof, publicSignals) {
    return {
        a: [proof.pi_a[0], proof.pi_a[1]],
        b: [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]],
        c: [proof.pi_c[0], proof.pi_c[1]],
        publicSignals
    };
}

describe("🏆 Aegis Protocol vs. Baseline Model: Full Validation Suite 🏆", function () {
    // Test accounts
    let owner, validator1, validator2, validator3, validator4, validator5, attacker, user;
    
    // Contracts
    let baselineModel, lockingContract, aegisVerifier;
    
    // ZK artifacts
    let wasmPath, zkeyPath;
    
    // Constants
    const DEPOSIT_AMOUNT = ethers.parseEther("1");
    let poseidon;

    before(async function () {
        this.timeout(300000); // Extended timeout for setup

        console.log("\n\n--- 🔬 Setting Up Test Environment ---");

        // 1. Load Poseidon hash function
        try {
            console.log("[1/5] Loading cryptographic libraries...");
            poseidon = await buildPoseidon();
            console.log("  ✅ Poseidon hash function loaded");
            
            const testHash = poseidon.F.toString(poseidon([1, 2]));
            console.log(`  Test hash: ${testHash}`);
        } catch (error) {
            console.error("  ❌ Failed to load Poseidon:", error);
            throw new Error(`Please install circomlibjs: npm install circomlibjs`);
        }

        // 2. Setup paths for ZK artifacts
        try {
            console.log("[2/5] Configuring ZK artifact paths...");
            wasmPath = path.join(__dirname, "../circuits/AegisCircuit_js/AegisCircuit.wasm");
            zkeyPath = path.join(__dirname, "../circuits/AegisCircuit_final.zkey");
            
            if (!fs.existsSync(wasmPath)) throw new Error(`Missing: ${wasmPath}`);
            if (!fs.existsSync(zkeyPath)) throw new Error(`Missing: ${zkeyPath}`);
            console.log("  ✅ ZK artifacts verified");
        } catch (error) {
            console.error("  ❌ ZK setup failed:", error);
            throw error;
        }

        // 3. Initialize accounts
        try {
            console.log("[3/5] Initializing signer accounts...");
            [owner, validator1, validator2, validator3, validator4, validator5, attacker, user] = await ethers.getSigners();
            console.log(`  ✅ Accounts initialized (${await user.getAddress()} as test user)`);
        } catch (error) {
            console.error("  ❌ Account initialization failed:", error);
            throw error;
        }

        // 4. Deploy contracts
        try {
            console.log("[4/5] Deploying contracts...");
            
            // Deploy Baseline Model
            const BaselineFactory = await ethers.getContractFactory("BaselineValidatorModel");
            const validators = [
                await validator1.getAddress(),
                await validator2.getAddress(),
                await validator3.getAddress(),
                await validator4.getAddress(),
                await validator5.getAddress()
            ];
            baselineModel = await BaselineFactory.deploy(validators);
            await baselineModel.waitForDeployment();
            console.log(`  - Baseline: ${await baselineModel.getAddress()}`);

            // Deploy Locking Contract
            const LockingFactory = await ethers.getContractFactory("LockingContract");
            lockingContract = await LockingFactory.deploy();
            await lockingContract.waitForDeployment();
            console.log(`  - Locking: ${await lockingContract.getAddress()}`);

            // Deploy Verifier
            const VerifierFactory = await ethers.getContractFactory("Groth16Verifier");
            const verifier = await VerifierFactory.deploy();
            await verifier.waitForDeployment();
            console.log(`  - Groth16: ${await verifier.getAddress()}`);

            // Deploy Aegis Verifier
            const AegisFactory = await ethers.getContractFactory("AegisVerifier");
            aegisVerifier = await AegisFactory.deploy(await verifier.getAddress());
            await aegisVerifier.waitForDeployment();
            console.log(`  - Aegis: ${await aegisVerifier.getAddress()}`);

            // ✨ THE REAL FIX: Artificially fund the contracts for testing.
            // Since the contracts don't have a `receive()` function, we use a Hardhat-specific
            // "cheat code" to set their balance. This is the correct way to test this scenario.
            console.log("  - Artificially funding contracts for testing...");
            const fundingAmountHex = ethers.parseEther("10").toString(16);
            
            await ethers.provider.send("hardhat_setBalance", [
                await baselineModel.getAddress(),
                "0x" + fundingAmountHex,
            ]);
            await ethers.provider.send("hardhat_setBalance", [
                await aegisVerifier.getAddress(),
                "0x" + fundingAmountHex,
            ]);
            console.log("  ✅ Contracts deployed and funded correctly.");

        } catch (error) {
            console.error("  ❌ Contract deployment failed:", error);
            throw error;
        }

        console.log("--- ✨ Environment Ready ---");
    });

    describe("⚔️ Security Validation: Adversarial Testing", function () {
        it("🔴 BASELINE FAILURE: Should be VULNERABLE to validator key compromise", async function () {
            console.log("\n--- Test: Attacking Baseline Model ---");
            
            const maliciousCallData = "0x";
            const txHash = await baselineModel.getMessageHash(attacker.address, DEPOSIT_AMOUNT, maliciousCallData);
            
            // Correctly sign the raw transaction hash to solve the 'Invalid signer' error.
            const compromisedSigners = [validator1, validator2, validator3].sort((a, b) => 
                a.address.toLowerCase().localeCompare(b.address.toLowerCase())
            );

            const signatures = await Promise.all(compromisedSigners.map(async (signer) => {
                return await signer.signMessage(ethers.getBytes(txHash));
            }));

            // Execute attack
            const attackerInitialBalance = await ethers.provider.getBalance(attacker.address);
            console.log("  - Attacker initiating malicious withdrawal...");
            
            const tx = await baselineModel.connect(attacker).executeTransaction(
                attacker.address, 
                DEPOSIT_AMOUNT, 
                maliciousCallData, 
                signatures
            );
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
                aegisVerifier.connect(attacker).releaseFunds(
                    fakeProof.a, 
                    fakeProof.b, 
                    fakeProof.c, 
                    fakePublicInputs, 
                    attacker.address, 
                    DEPOSIT_AMOUNT
                )
            ).to.be.revertedWithCustomError(aegisVerifier, "InvalidProof");
            console.log("  - ✅ Outcome: SECURE. Malicious proposal rejected by Aegis.");
        });
    });

    describe("⏱️ Performance Validation: Gas & Latency Benchmarking", function () {
        let baselineGas, aegisGas, proofGenLatency;

        it("1. Benchmark Gas for a legitimate Baseline transaction", async function () {
            const legitimateCallData = "0x";
            const txHash = await baselineModel.getMessageHash(user.address, DEPOSIT_AMOUNT, legitimateCallData);
            
            const signers = [validator1, validator2, validator3].sort((a, b) => 
                a.address.toLowerCase().localeCompare(b.address.toLowerCase())
            );

            const signatures = await Promise.all(signers.map(async (signer) => {
                return await signer.signMessage(ethers.getBytes(txHash));
            }));

            const tx = await baselineModel.connect(user).executeTransaction(
                user.address, 
                DEPOSIT_AMOUNT, 
                legitimateCallData, 
                signatures
            );
            const receipt = await tx.wait();
            baselineGas = receipt.gasUsed;
            console.log(`\n  - Gas for Baseline Transaction: ${baselineGas.toString()}`);
            expect(baselineGas).to.be.gt(0);
        });

        it("2. Benchmark Latency and Gas for a legitimate Aegis transaction", async function () {
            const secret = ethers.toBigInt(ethers.randomBytes(32));
            const destinationChainId = 31337; // Hardhat network

            // Fixed typo from `poseon` to `poseidon`
            const eventHash = poseidon.F.toString(poseidon([
                ethers.toBigInt(user.address).toString(),
                DEPOSIT_AMOUNT.toString(),
                destinationChainId.toString(),
                secret.toString()
            ]));
            const nullifierHash = poseidon.F.toString(poseidon([secret.toString()]));

            const input = {
                depositor: ethers.toBigInt(user.address).toString(),
                amount: DEPOSIT_AMOUNT.toString(),
                destinationChainId: destinationChainId.toString(),
                secret: secret.toString(),
                eventHash: eventHash,
                nullifierHash: nullifierHash
            };

            console.log("  - Generating ZK proof (this may take a moment)...");
            const startTime = Date.now();
            const { proof, publicSignals } = await groth16.fullProve(input, wasmPath, zkeyPath);
            const endTime = Date.now();
            proofGenLatency = (endTime - startTime) / 1000;
            console.log(`  - Proof Generation Latency: ${proofGenLatency.toFixed(3)} seconds`);

            const { a, b, c } = buildSolidityCalldata(proof, publicSignals);
            const tx = await aegisVerifier.connect(user).releaseFunds(
                a, 
                b, 
                c, 
                publicSignals, 
                user.address, 
                DEPOSIT_AMOUNT
            );
            const receipt = await tx.wait();
            aegisGas = receipt.gasUsed;
            console.log(`  - Gas for Aegis Transaction: ${aegisGas.toString()}`);
            expect(aegisGas).to.be.gt(0);
        });

        it("3. Final Report: Calculate and display overhead", function () {
            if (!aegisGas || !baselineGas) {
                throw new Error("Gas measurements not available. A previous test likely failed.");
            }
            
            const overhead = (Number(aegisGas - baselineGas) / Number(baselineGas)) * 100;
            console.log("\n\n--- 📊 FINAL EMPIRICAL RESULTS 📊 ---");
            console.log("========================================");
            console.log(`  ZK Proof Generation Latency: ${proofGenLatency.toFixed(3)} s`);
            console.log(`  Baseline Gas Used:          ${baselineGas.toString()}`);
            console.log(`  Aegis Gas Used:            ${aegisGas.toString()}`);
            console.log(`  Gas Overhead vs Baseline:  ${overhead.toFixed(2)}%`);
            console.log("========================================");
            
            expect(overhead).to.be.a('number');
            expect(proofGenLatency).to.be.a('number');
        });
    });
});
