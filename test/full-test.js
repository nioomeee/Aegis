const { expect } = require("chai");
const { ethers } = require("hardhat");
const { groth16 } = require("snarkjs");
const path = require("path");

// Visual Constants
const SUCCESS = "🟢";
const FAILURE = "🔴";
const INFO = "🔵";
const WARNING = "🟠";
const DIVIDER = "=".repeat(60);

describe("Aegis Protocol Validation", function () {
    let baseline, locking, verifierContract, verifier;
    let validators, users;
    let wasm, zkey;

    before(async function () {
        console.log(`\n${DIVIDER}`);
        console.log(`${INFO} STARTING CONTRACT DEPLOYMENT`);
        console.log(`${DIVIDER}\n`);

        // =====================
        // 1. Load Proving Artifacts
        // =====================
        try {
            console.log(`${INFO} Loading SNARK artifacts...`);
            wasm = path.join(__dirname, "../circuits/build/AegisCircuit_js/AegisCircuit.wasm");
            zkey = path.join(__dirname, "../circuits/build/AegisCircuit.zkey");
            
            if (!fs.existsSync(wasm)) throw new Error("WASM file not found");
            if (!fs.existsSync(zkey)) throw new Error("ZKEY file not found");
            
            console.log(`${SUCCESS} Artifacts loaded successfully`);
            console.log(`   WASM: ${wasm}`);
            console.log(`   ZKEY: ${zkey}`);
        } catch (error) {
            console.log(`${FAILURE} Failed to load artifacts`);
            throw error;
        }

        // =====================
        // 2. Initialize Signers
        // =====================
        try {
            console.log(`\n${INFO} Initializing signers...`);
            [owner, ...users] = await ethers.getSigners();
            validators = users.slice(0, 5);
            
            console.log(`${SUCCESS} Signers initialized`);
            console.log(`   Owner: ${owner.address}`);
            console.log(`   Validators: ${validators.length} addresses`);
        } catch (error) {
            console.log(`${FAILURE} Failed to initialize signers`);
            throw error;
        }

        // =====================
        // 3. Contract Deployment
        // =====================
        try {
            console.log(`\n${INFO} Deploying contracts...`);

            // Deploy Baseline
            console.log(`\n${INFO} Deploying BaselineValidatorModel...`);
            const Baseline = await ethers.getContractFactory("contracts/BaselineValidatorModel.sol:BaselineValidatorModel");
            baseline = await Baseline.deploy(validators.map(v => v.address));
            await baseline.deployTransaction.wait();
            console.log(`${SUCCESS} Baseline deployed to: ${baseline.address}`);

            // Deploy Locking
            console.log(`\n${INFO} Deploying LockingContract...`);
            const Locking = await ethers.getContractFactory("contracts/LockingContract.sol:LockingContract");
            locking = await Locking.deploy();
            await locking.deployTransaction.wait();
            console.log(`${SUCCESS} Locking deployed to: ${locking.address}`);

            // Deploy Verifier
            console.log(`\n${INFO} Deploying Groth16Verifier...`);
            const Verifier = await ethers.getContractFactory("contracts/Groth16Verifier.sol:Groth16Verifier");
            verifierContract = await Verifier.deploy();
            await verifierContract.deployTransaction.wait();
            console.log(`${SUCCESS} Verifier deployed to: ${verifierContract.address}`);

            // Deploy AegisVerifier
            console.log(`\n${INFO} Deploying AegisVerifier...`);
            const AegisVerifier = await ethers.getContractFactory("contracts/AegisVerifier.sol:AegisVerifier");
            verifier = await AegisVerifier.deploy(verifierContract.address);
            await verifier.deployTransaction.wait();
            console.log(`${SUCCESS} AegisVerifier deployed to: ${verifier.address}`);

            // Fund verifier
            console.log(`\n${INFO} Funding verifier contract...`);
            const fundTx = await owner.sendTransaction({
                to: verifier.address,
                value: ethers.utils.parseEther("10")
            });
            await fundTx.wait();
            console.log(`${SUCCESS} Verifier funded with 10 ETH`);

            console.log(`\n${SUCCESS} ALL CONTRACTS DEPLOYED SUCCESSFULLY`);
        } catch (error) {
            console.log(`\n${FAILURE} DEPLOYMENT FAILED`);
            console.error(error);
            throw error;
        }
    });

    // =====================
    // TEST CASES
    // =====================

    it("should demonstrate baseline vulnerability to validator compromise", async function () {
        console.log(`\n${INFO} Running baseline vulnerability test...`);
        
        const maliciousTx = {
            to: owner.address,
            value: ethers.utils.parseEther("1"),
            data: "0x"
        };

        console.log(`${INFO} Generating validator signatures...`);
        const messageHash = await baseline.getMessageHash(
            maliciousTx.to,
            maliciousTx.value,
            maliciousTx.data
        );
        const signatures = await Promise.all(
            validators.slice(0, 3).map(async v => {
                return await v.signMessage(ethers.utils.arrayify(messageHash));
            })
        );

        console.log(`${INFO} Executing malicious transaction...`);
        const tx = await baseline.executeTransaction(
            maliciousTx.to,
            maliciousTx.value,
            maliciousTx.data,
            signatures
        );
        const receipt = await tx.wait();

        console.log(`${INFO} Verifying funds were stolen...`);
        const balance = await ethers.provider.getBalance(owner.address);
        
        expect(tx).to.emit(baseline, "TransactionExecuted");
        expect(balance).to.be.gt(0);
        console.log(`${SUCCESS} Test passed - baseline vulnerability confirmed`);
    });

    it("should reject malicious proposal on AegisVerifier", async function () {
        console.log(`\n${INFO} Running malicious proposal test...`);
        
        const secret = 12345;
        const amount = ethers.utils.parseEther("1");
        const destinationChainId = 137;

        console.log(`${INFO} Making deposit...`);
        await locking.connect(users[5]).depositForBridge(destinationChainId, secret, {
            value: amount
        });

        console.log(`${INFO} Generating proof...`);
        const { proof, publicSignals } = await groth16.fullProve(
            {
                depositor: users[5].address,
                amount: amount.toString(),
                destinationChainId: destinationChainId.toString(),
                secret: secret.toString()
            },
            wasm,
            zkey
        );

        console.log(`${INFO} Attempting malicious withdrawal...`);
        await expect(
            verifier.releaseFunds(
                [proof.pi_a[0], proof.pi_a[1]],
                [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]],
                [proof.pi_c[0], proof.pi_c[1]],
                publicSignals,
                owner.address, // Malicious recipient
                amount
            )
        ).to.be.revertedWith("Invalid proof");
        
        console.log(`${SUCCESS} Test passed - malicious proposal rejected`);
    });

    it("should benchmark gas usage", async function () {
        console.log(`\n${INFO} Running gas benchmark test...`);

        // Baseline Transaction
        console.log(`${INFO} Executing baseline transaction...`);
        const tx = {
            to: users[6].address,
            value: ethers.utils.parseEther("0.5"),
            data: "0x"
        };
        const messageHash = await baseline.getMessageHash(tx.to, tx.value, tx.data);
        const signatures = await Promise.all(
            validators.slice(0, 3).map(async v => {
                return await v.signMessage(ethers.utils.arrayify(messageHash));
            })
        );
        const baselineTx = await baseline.executeTransaction(tx.to, tx.value, tx.data, signatures);
        const baselineReceipt = await baselineTx.wait();
        const baselineGas = baselineReceipt.gasUsed.toString();

        // Aegis Transaction
        console.log(`${INFO} Executing Aegis transaction...`);
        const secret = 54321;
        const amount = ethers.utils.parseEther("0.5");
        await locking.connect(users[7]).depositForBridge(137, secret, { value: amount });
        
        const { proof, publicSignals } = await groth16.fullProve(
            {
                depositor: users[7].address,
                amount: amount.toString(),
                destinationChainId: "137",
                secret: secret.toString()
            },
            wasm,
            zkey
        );
        
        const aegisTx = await verifier.releaseFunds(
            [proof.pi_a[0], proof.pi_a[1]],
            [[proof.pi_b[0][1], proof.pi_b[0][0]], [proof.pi_b[1][1], proof.pi_b[1][0]]],
            [proof.pi_c[0], proof.pi_c[1]],
            publicSignals,
            users[7].address,
            amount
        );
        const aegisReceipt = await aegisTx.wait();
        const aegisGas = aegisReceipt.gasUsed.toString();

        // Calculate overhead
        const overhead = ((aegisGas - baselineGas) / baselineGas * 100).toFixed(2);

        console.log(`\n${SUCCESS} Gas Benchmark Results:`);
        console.log(`${DIVIDER}`);
        console.log(`   Baseline Gas Used: ${baselineGas}`);
        console.log(`   Aegis Gas Used:    ${aegisGas}`);
        console.log(`   Gas Overhead:      ${overhead}%`);
        console.log(`${DIVIDER}`);
    });

    after(async function () {
        console.log(`\n${DIVIDER}`);
        console.log(`${INFO} TESTING COMPLETE`);
        console.log(`${DIVIDER}`);
    });
});