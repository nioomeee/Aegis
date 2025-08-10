const { expect } = require("chai");
const { ethers } = require("hardhat");
const { groth16 } = require("snarkjs");
const path = require("path");
const fs = require("fs");

// Helper function for proof formatting
function formatProof(proof) {
    return {
        a: [proof.pi_a[0], proof.pi_a[1]],
        b: [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]],
        c: [proof.pi_c[0], proof.pi_c[1]],
    };
}

describe("🏆 Aegis Protocol Test Suite", function () {
    // Test configuration
    const DEPOSIT_AMOUNT = ethers.utils.parseEther("1");
    const CHAIN_ID = 31337; // Hardhat network ID

    // Contract instances
    let baselineModel, aegisVerifier;
    
    // Accounts
    let owner, validators, attacker, user;

    // ZK setup
    let wasmPath, zkeyPath, poseidon;

    before(async function () {
        this.timeout(300000); // 5 minute timeout for setup

        console.log("\n=== Setting Up Test Environment ===");

        // 1. Initialize Poseidon
        const poseidonModule = require("poseidon-lite");
        poseidon = poseidonModule.poseidon;
        if (typeof poseidon !== 'function') throw new Error("Poseidon not properly initialized");
        console.log("✓ Poseidon initialized");

        // 2. Setup ZK artifact paths
        wasmPath = path.join(__dirname, "../circuits/AegisCircuit_js/AegisCircuit.wasm");
        zkeyPath = path.join(__dirname, "../circuits/AegisCircuit_0001.zkey");
        
        if (!fs.existsSync(wasmPath)) throw new Error("WASM file missing");
        if (!fs.existsSync(zkeyPath)) throw new Error("Zkey file missing");
        console.log("✓ ZK artifacts verified");

        // 3. Get signers
        [owner, ...signers] = await ethers.getSigners();
        validators = signers.slice(0, 5); // First 5 as validators
        attacker = signers[5];
        user = signers[6];
        console.log("✓ Accounts initialized");

        // 4. Deploy contracts
        console.log("\nDeploying contracts...");
        
        // Deploy Baseline
        const validatorAddresses = validators.map(v => v.address).sort((a, b) => 
            a.toLowerCase().localeCompare(b.toLowerCase())
        );
        const Baseline = await ethers.getContractFactory("BaselineValidatorModel");
        baselineModel = await Baseline.deploy(validatorAddresses);
        await baselineModel.deployed();
        console.log(`- Baseline: ${baselineModel.address}`);
        
        // Deploy Verifier
        const Verifier = await ethers.getContractFactory("Groth16Verifier");
        const verifier = await Verifier.deploy();
        await verifier.deployed();
        
        // Deploy Aegis
        const Aegis = await ethers.getContractFactory("AegisVerifier");
        aegisVerifier = await Aegis.deploy(verifier.address);
        await aegisVerifier.deployed();
        console.log(`- Aegis: ${aegisVerifier.address}`);
        
        // Fund contracts
        await owner.sendTransaction({
            to: aegisVerifier.address,
            value: ethers.utils.parseEther("10")
        });
        await owner.sendTransaction({
            to: baselineModel.address,
            value: ethers.utils.parseEther("10")
        });
        console.log("✓ Contracts funded");
    });

    describe("🔒 Security Tests", function () {
        it("Baseline: Should allow malicious withdrawal with validator signatures", async function () {
            // Prepare transaction
            const txData = {
                to: attacker.address,
                value: DEPOSIT_AMOUNT,
                data: "0x"
            };
            
            // Get hash and sign
            const messageHash = await baselineModel.getMessageHash(
                txData.to, 
                txData.value, 
                txData.data
            );
            
            const ethMessageHash = ethers.utils.arrayify(
                await baselineModel.getEthSignedMessageHash(messageHash)
            );
            
            // Get signatures from first 3 validators
            const signingValidators = validators.slice(0, 3)
                .sort((a, b) => a.address.toLowerCase().localeCompare(b.address.toLowerCase()));
            
            const signatures = await Promise.all(
                signingValidators.map(v => v.signMessage(ethMessageHash))
            );

            // Execute attack
            const initialBalance = await ethers.provider.getBalance(attacker.address);
            const tx = await baselineModel.connect(attacker).executeTransaction(
                txData.to,
                txData.value,
                txData.data,
                signatures,
                { gasLimit: 1000000 }
            );
            
            const receipt = await tx.wait();
            const finalBalance = await ethers.provider.getBalance(attacker.address);
            
            expect(finalBalance.sub(initialBalance).eq(DEPOSIT_AMOUNT)).to.be.true;
        });

        it("Aegis: Should reject invalid proofs", async function () {
            const fakeProof = {
                a: ["0", "0"],
                b: [["0", "0"], ["0", "0"]],
                c: ["0", "0"]
            };
            const fakeInputs = ["0", "0"];
            
            await expect(
                aegisVerifier.releaseFunds(
                    fakeProof.a,
                    fakeProof.b,
                    fakeProof.c,
                    fakeInputs,
                    attacker.address,
                    DEPOSIT_AMOUNT
                )
            ).to.be.revertedWith("Invalid proof");
        });
    });

    describe("⚡ Performance Tests", function () {
        let baselineGas, aegisGas, proofTime;

        it("Baseline: Measure gas costs", async function () {
            // Prepare legitimate transaction
            const txData = {
                to: user.address,
                value: DEPOSIT_AMOUNT,
                data: "0x"
            };
            
            // Get properly ordered signatures
            const signingValidators = validators.slice(0, 3)
                .sort((a, b) => a.address.toLowerCase().localeCompare(b.address.toLowerCase()));
            
            const messageHash = await baselineModel.getMessageHash(
                txData.to, 
                txData.value, 
                txData.data
            );
            
            const ethMessageHash = ethers.utils.arrayify(
                await baselineModel.getEthSignedMessageHash(messageHash)
            );
            
            const signatures = await Promise.all(
                signingValidators.map(v => v.signMessage(ethMessageHash))
            );

            // Execute transaction
            const tx = await baselineModel.connect(signingValidators[0]).executeTransaction(
                txData.to,
                txData.value,
                txData.data,
                signatures,
                { gasLimit: 1000000 }
            );
            
            const receipt = await tx.wait();
            baselineGas = receipt.gasUsed;
            console.log(`Baseline Gas: ${baselineGas}`);
        });

        it("Aegis: Measure proof generation and verification", async function () {
            // Generate ZK proof
            const secret = ethers.BigNumber.from(ethers.utils.randomBytes(32));
            
            // Calculate hashes
            const inputs = [
                ethers.BigNumber.from(user.address).toString(),
                DEPOSIT_AMOUNT.toString(),
                CHAIN_ID.toString(),
                secret.toString()
            ];
            
            const eventHash = poseidon(inputs);
            const nullifierHash = poseidon([secret.toString()]);

            // Generate proof
            const start = Date.now();
            const { proof, publicSignals } = await groth16.fullProve(
                {
                    depositor: user.address,
                    amount: DEPOSIT_AMOUNT.toString(),
                    destinationChainId: CHAIN_ID.toString(),
                    secret: secret.toString(),
                    eventHash: eventHash.toString(),
                    nullifierHash: nullifierHash.toString()
                },
                wasmPath,
                zkeyPath
            );
            
            proofTime = (Date.now() - start) / 1000;
            
            // Verify on-chain
            const formattedProof = formatProof(proof);
            const tx = await aegisVerifier.releaseFunds(
                formattedProof.a,
                formattedProof.b,
                formattedProof.c,
                publicSignals,
                user.address,
                DEPOSIT_AMOUNT,
                { gasLimit: 1000000 }
            );
            
            const receipt = await tx.wait();
            aegisGas = receipt.gasUsed;
            console.log(`Aegis Gas: ${aegisGas}`);
        });

        it("Compare results", function () {
            if (!proofTime || !aegisGas || !baselineGas) {
                throw new Error("Missing benchmark data");
            }
            const overhead = ((aegisGas - baselineGas) / baselineGas) * 100;
            console.log("\n=== Results ===");
            console.log(`Proof Time: ${proofTime.toFixed(3)} sec`);
            console.log(`Gas Overhead: ${overhead.toFixed(2)}%`);
            expect(overhead).to.be.a('number');
        });
    });
});