// This is a circom 2.0 circuit
// Run with `circom AegisCircuit.circom --r1cs --wasm --sym -o circuits`

pragma circom 2.0.0;

/*
 * @title AegisCircuit (Final Corrected Version)
 * @author Niomi Langaliya & Dr. Gemini
 * @notice This circuit cryptographically proves knowledge of a deposit event.
 * The core correction is in the `main` component declaration, ensuring only
 * the hashes are made public, while the deposit details remain private.
 */

// We will use the Poseidon hash function from the circomlib library.
// It's a standard, SNARK-friendly hash function.
include "../node_modules/circomlib/circuits/poseidon.circom";

template AegisCircuit() {
    // --- Inputs ---

    // Private signals (the "witness"), known only to the prover.
    signal input depositor;
    signal input amount;
    signal input destinationChainId;
    signal input secret; // The user's private value to link the hashes

    // Public signals, known to both prover and verifier (the smart contract).
    // In Circom 2, public inputs are declared as `input` just like private ones.
    // What makes them public is the declaration in the `main` component.
    signal input eventHash;
    signal input nullifierHash;

    // --- Logic (Constraints) ---

    // Constraint 1: The public `eventHash` must equal the hash of all private inputs.
    // This proves that the prover knows the details of the event they are claiming.
    component eventHasher = Poseidon(4);
    eventHasher.inputs[0] <== depositor;
    eventHasher.inputs[1] <== amount;
    eventHasher.inputs[2] <== destinationChainId;
    eventHasher.inputs[3] <== secret;
    eventHash === eventHasher.out;

    // Constraint 2: The public `nullifierHash` must equal the hash of the secret.
    // This proves that the nullifier is linked to this specific event via the shared secret.
    component nullifierHasher = Poseidon(1);
    nullifierHasher.inputs[0] <== secret;
    nullifierHash === nullifierHasher.out;
}

// THE CRITICAL FIX IS HERE:
// We declare that `eventHash` and `nullifierHash` are the public signals for this circuit.
component main {public [eventHash, nullifierHash]} = AegisCircuit();
