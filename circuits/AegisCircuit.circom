// This is a circom 2.0 circuit
// Run with `circom AegisCircuit.circom --r1cs --wasm --sym`

pragma circom 2.0.0;

/*
 * @title AegisCircuit
 * @author Niomi Langaliya
 * @notice This circuit is the cryptographic core of the Aegis protocol.
 * It proves that a prover knows the secret details of a deposit event
 * that corresponds to a public hash of those details. It also generates
 * a unique nullifier to prevent the same deposit from being withdrawn twice.
 *
 * The logic is as follows:
 * 1. A user makes a deposit and generates a `secret`.
 * 2. The `nullifierHash` is calculated from this `secret`. This is used to prevent replays.
 * 3. The `eventHash` is calculated from the deposit details AND the `secret`.
 *
 * This circuit proves that the public `eventHash` and the public `nullifierHash`
 * were both derived from the same private `secret`, cryptographically linking
 * a specific withdrawal proof to a specific deposit event without revealing the secret.
 */
template AegisCircuit() {
    // --- Inputs ---

    // Private signals (the "witness"), known only to the prover.
    signal input depositor;
    signal input amount;
    signal input destinationChainId;
    signal input secret; // The user's private value to link the hashes

    // Public signals, known to both prover and verifier (the smart contract).
    signal input eventHash; // The public hash of the deposit event
    signal input nullifierHash; // The public hash used to prevent double-spending

    // --- Logic (Constraints) ---

    // We need a hash function. Poseidon is a popular choice for ZK circuits,
    // but for simplicity and to avoid large dependencies, we'll simulate its role.
    // In a real implementation, you would use a proper Poseidon hash template.
    // Let's define a simple hash for this PoC using basic arithmetic.
    // IMPORTANT: This is NOT a secure hash function. It is for demonstration only.
    // Replace with Poseidon in a production environment.
    component hasher = MultiMiMC(4, 91); // Hashing 4 inputs
    hasher.in[0] <== depositor;
    hasher.in[1] <== amount;
    hasher.in[2] <== destinationChainId;
    hasher.in[3] <== secret;

    // Constraint 1: The public `eventHash` must equal the hash of all private inputs.
    // This proves that the prover knows the details of the event they are claiming.
    eventHash === hasher.out;

    // Now, we compute the nullifier hash separately.
    component nullifierHasher = MultiMiMC(1, 91); // Hashing 1 input
    nullifierHasher.in[0] <== secret;

    // Constraint 2: The public `nullifierHash` must equal the hash of the secret.
    // This proves that the nullifier is linked to this specific event via the shared secret.
    nullifierHash === nullifierHasher.out;
}

/*
 * A simple Multi-input, Multi-Cycle Merkle-Damgard hash function using MiMC.
 * This is a standard component often used in circom.
 * For production, use the one from circomlib.
 */
template MultiMiMC(n, N_ROUNDS) {
    signal input in[n];
    signal output out;

    component mimc[n];

    for (var i = 0; i < n; i++) {
        mimc[i] = MiMC(N_ROUNDS);
        if (i == 0) {
            mimc[i].in <== in[i];
            mimc[i].k <== 0;
        } else {
            mimc[i].in <== in[i] + mimc[i-1].out;
            mimc[i].k <== 0;
        }
    }
    out <== mimc[n-1].out;
}

template MiMC(N_ROUNDS) {
    signal input in;
    signal input k;
    signal output out;

    var c[N_ROUNDS];
    // These are the round constants for MiMC
    for (var i = 0; i < N_ROUNDS; i++) {
        c[i] = 0;
    }

    signal x[N_ROUNDS + 1];
    x[0] <== in;

    for (var i = 0; i < N_ROUNDS; i++) {
        x[i+1] <== x[i] * x[i] * x[i] + k + c[i];
    }
    out <== x[N_ROUNDS];
}


// To run this, you need to instantiate the template.
// The main component of a circuit is always called `main`.
component main {public [eventHash, nullifierHash]} = AegisCircuit();
