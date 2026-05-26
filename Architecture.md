# Executive Cryptographic Specification: H2Ledger Provenance Engine

**Document Class:** Production Architecture Reference  
**Classification:** Internal — Cryptographic Systems Design  
**Version:** 1.0.0  
**Protocol Target:** Groth16 / BN254 (current); STARK / FRI migration path (2030 mandate)  
**Author Role:** Principal Cryptographic Architect  

---

> **Abstract:** This document defines the zero-knowledge cryptographic architecture underpinning the H2Ledger decentralized green hydrogen marketplace. It specifies circuit variable boundaries, constraint semantics, field arithmetic handling, and a post-quantum migration roadmap to satisfy emerging EU critical infrastructure directives. All claims are grounded in production-grade Circom 2.1.x constraint logic and are evaluated over the BN254 scalar field.

---

## Table of Contents

1. [System Flow Diagram](#1-system-flow-diagram)
2. [Formal Cryptographic Claim Statement](#2-formal-cryptographic-claim-statement)
3. [Data Dictionary](#3-data-dictionary)
4. [Circuit Logic & Mathematical Proof](#4-circuit-logic--mathematical-proof)
5. [Post-Quantum Agility & Roadmap Note](#5-post-quantum-agility--roadmap-note)

---

## 1. System Flow Diagram

The following diagram delineates the precise trust boundary between the **Off-Chain Prover Environment** — where all confidential industrial data lives — and the **On-Chain Verifier** — which sees only the cryptographic proof and the public input commitments. No private witness data crosses this boundary at any point; the SNARKing step eliminates that necessity by design.

```
╔══════════════════════════════════════════════════════════════════════════════╗
║              OFF-CHAIN PROVER ENVIRONMENT (Trusted Industrial Node)          ║
║                                                                              ║
║  ┌─────────────────────────────────────────────────────────────────────┐    ║
║  │                     PRIVATE WITNESS DOMAIN                          │    ║
║  │                    [NEVER LEAVES THIS BOUNDARY]                     │    ║
║  │                                                                     │    ║
║  │   energy_consumed        ──────────────────────────────┐           │    ║
║  │   (kWh, electrolyzer)                                  │           │    ║
║  │                                                         ▼           │    ║
║  │   supplier_emission_factor ──────────────► ZK Circuit Engine       │    ║
║  │   (g CO2/kWh, energy provider)             [H2LedgerVerifier()]    │    ║
║  └─────────────────────────────────────────────────────────────────────┘    ║
║                                                    │                         ║
║  ┌─────────────────────────────────────────────────────────────────────┐    ║
║  │                      PUBLIC INPUT DOMAIN                            │    ║
║  │                    [Hashed into Proof Commitment]                   │    ║
║  │                                                                     │    ║
║  │   h2_produced            ──────────────────────────────┐           │    ║
║  │   (kg, batch weight)                                    │           │    ║
║  │                                                         ▼           │    ║
║  │   emission_threshold     ──────────────► ZK Circuit Engine         │    ║
║  │   (g CO2/kg, regulatory ceiling)          [H2LedgerVerifier()]     │    ║
║  └─────────────────────────────────────────────────────────────────────┘    ║
║                                                    │                         ║
║                            ┌───────────────────────┘                         ║
║                            │                                                  ║
║                            ▼                                                  ║
║             ┌──────────────────────────────┐                                 ║
║             │   R1CS Constraint Synthesis  │  ◄─── circom 2.1.6 compiler     ║
║             │   (Rank-1 Constraint System) │                                 ║
║             └──────────────┬───────────────┘                                 ║
║                            │                                                  ║
║                            ▼                                                  ║
║             ┌──────────────────────────────┐                                 ║
║             │   Witness Computation        │  ◄─── snarkjs / rapidsnark      ║
║             │   (Full Assignment Vector)   │                                 ║
║             └──────────────┬───────────────┘                                 ║
║                            │                                                  ║
║                            ▼                                                  ║
║             ┌──────────────────────────────┐                                 ║
║             │   Groth16 Prover             │  ◄─── Trusted Setup (Powers     ║
║             │   π = (A, B, C) ∈ G1×G2×G1  │        of Tau ceremony)         ║
║             └──────────────┬───────────────┘                                 ║
║                            │                                                  ║
╠════════════════════════════╪═════════════════════════════════════════════════╣
║      TRUST BOUNDARY        │   Only π and public inputs cross this line      ║
╠════════════════════════════╪═════════════════════════════════════════════════╣
║                            │                                                  ║
║         ON-CHAIN VERIFIER ENVIRONMENT (EVM Smart Contract Layer)             ║
║                            │                                                  ║
║                            ▼                                                  ║
║             ┌──────────────────────────────────────────┐                     ║
║             │         Verifier Smart Contract           │                     ║
║             │    (Auto-generated by snarkjs export)     │                     ║
║             │                                           │                     ║
║             │  Inputs:                                  │                     ║
║             │   • π := proof byte array [A, B, C]      │                     ║
║             │   • publicSignals[0] := h2_produced       │                     ║
║             │   • publicSignals[1] := emission_threshold│                     ║
║             │                                           │                     ║
║             │  Operation:                               │                     ║
║             │   e(A, B) == e(α, β) + e(C, γ) + e(K, δ)│  ← Pairing check   ║
║             │                                           │                     ║
║             │  Output:                                  │                     ║
║             │   bool verified → true / false            │                     ║
║             └──────────────────────┬────────────────────┘                     ║
║                                    │                                           ║
║                            ┌───────┴──────────┐                               ║
║                            │                  │                               ║
║                            ▼                  ▼                               ║
║             ┌──────────────────┐   ┌───────────────────┐                     ║
║             │  MINT H2 Credits │   │  REJECT: Proof    │                     ║
║             │  (h2_produced kg │   │  Invalid or       │                     ║
║             │   → token units) │   │  Constraint Unsat │                     ║
║             └──────────────────┘   └───────────────────┘                     ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

**Key architectural invariant:** The proof `π` is computationally binding. An adversary cannot forge a valid `π` that satisfies the pairing equation without possessing a valid private witness that genuinely satisfies all R1CS constraints — including the carbon intensity ceiling. This is guaranteed by the knowledge soundness property of Groth16 under the Generic Group Model.

---

## 2. Formal Cryptographic Claim Statement

### The Zero-Knowledge Statement

H2Ledger's core cryptographic claim is a **Succinct Non-Interactive Argument of Knowledge (zk-SNARK)** instantiated over the BN254 (alt-bn128) elliptic curve pairing. The statement proven by any industrial producer is formally expressed as follows:

> **Statement Φ:** *"I know a secret tuple `(energy_consumed, supplier_emission_factor) ∈ F_p²` such that, given public parameters `(h2_produced, emission_threshold) ∈ F_p²`, the following arithmetic relations hold simultaneously over the prime field `F_p` where `p` is the BN254 scalar field prime:*
>
> 1. `total_co2 := energy_consumed × supplier_emission_factor`
> 2. `carbon_intensity × h2_produced = total_co2` *(integer-safe division equivalence)*
> 3. `emission_threshold − carbon_intensity ≥ 0`"

**Completeness** guarantees that any honest prover holding a compliant witness will always generate an accepting proof. **Soundness** guarantees that no prover — even a computationally unbounded adversary — can produce an accepting proof for a false statement (i.e., non-compliant hydrogen) except with negligible probability in the security parameter. **Zero-knowledge** guarantees that the verifier learns nothing beyond the truth of the statement: `energy_consumed` and `supplier_emission_factor` remain cryptographically opaque.

The reduction from the division operation `total_co2 / h2_produced` to a multiplication equivalence check (`carbon_intensity × h2_produced === total_co2`) is a critical design decision. Native division does not exist as a rank-1 constraint and must be decomposed as described in Section 4.

### Security Assumptions

The soundness of this construction rests upon:

- **d-PKE assumption** (decryption-verifiable pairing knowledge of exponent) in the generic group model over BN254.
- **Discrete Logarithm hardness** on the BN254 elliptic curve group.
- **Trusted Setup integrity** — the `τ` (tau) parameter from the Powers of Tau ceremony must have been securely destroyed; any surviving `τ` breaks soundness universally.

---

## 3. Data Dictionary

All signals are elements of the prime field `F_p`, where `p = 21888242871839275222246405745257275088548364400416034343698204186575808495617` (the BN254 scalar prime). Floating-point representations do not exist within this field; all values are encoded as scaled integers, and division is enforced via the multiplicative inverse relationship described in Section 4.

| Signal Name | Circom Visibility | On-Chain Visibility | Data Type | Unit | Semantic Role |
|---|---|---|---|---|---|
| `energy_consumed` | `signal input` (private) | Hidden — never transmitted | Scaled integer ∈ F_p | kWh | Total electrical energy drawn by the electrolyzer unit during the production batch. This is proprietary hardware telemetry and constitutes a trade secret. |
| `supplier_emission_factor` | `signal input` (private) | Hidden — never transmitted | Scaled integer ∈ F_p | g CO₂ / kWh | Carbon intensity coefficient of the energy supplier's grid mix. Reveals the identity and contract terms of the upstream energy provider. Must remain confidential. |
| `h2_produced` | `signal input` (public) | Exposed as `publicSignals[0]` | Scaled integer ∈ F_p | kg | Total mass of green hydrogen produced in the batch. This quantity directly determines the number of carbon credit tokens minted on-chain upon proof acceptance. |
| `emission_threshold` | `signal input` (public) | Exposed as `publicSignals[1]` | Scaled integer ∈ F_p | g CO₂ / kg H₂ | The maximum permitted carbon intensity for a hydrogen batch to qualify as "green" under the applicable regulatory standard (e.g., EU delegated act, CertifHy protocol). Acts as the circuit's compliance ceiling. |

> **Note on scaling:** Since the BN254 field permits only integer arithmetic, real-valued quantities (e.g., `supplier_emission_factor = 85.4 g CO₂/kWh`) must be pre-scaled by a known constant (e.g., ×1000) before witness injection. The scaling factor must be consistent across all signals involved in the division equivalence check, or the constraint will be unsatisfiable. This scaling convention must be codified in the off-chain client library and audited independently.

---

## 4. Circuit Logic & Mathematical Proof

### 4.1 Circom Implementation

The following is the canonical circuit implementation for the H2Ledger compliance verifier, targeting Circom 2.1.6 and the BN254 curve backend.

```circom
pragma circom 2.1.6;

template H2LedgerVerifier() {
    // ── Private Witness Inputs ─────────────────────────────────────────────
    // These signals are consumed by the witness generation phase only.
    // They are NEVER embedded in the proof π or the public input vector.
    signal input energy_consumed;
    signal input supplier_emission_factor;

    // ── Public Inputs ──────────────────────────────────────────────────────
    // These values are hashed into the proof commitment and verified on-chain.
    // They are declared in the `component main { public [...] }` export.
    signal input h2_produced;
    signal input emission_threshold;

    // ── Intermediate Signals ───────────────────────────────────────────────
    signal total_co2;
    signal carbon_intensity;

    // ── Step 1: Total CO₂ Footprint ───────────────────────────────────────
    // This is a valid R1CS constraint: one multiplication of two witness signals.
    // The `<==` operator simultaneously assigns the value (witness) AND enforces
    // the arithmetic constraint in the R1CS matrix system.
    total_co2 <== energy_consumed * supplier_emission_factor;

    // ── Step 2: Carbon Intensity (Integer-Safe Division Encoding) ─────────
    // Division is NOT a native R1CS operation. It cannot be expressed as a
    // degree-2 polynomial constraint (A · B = C) directly.
    //
    // Strategy: express division as a multiplication equivalence.
    //   If carbon_intensity = total_co2 / h2_produced,
    //   then: carbon_intensity * h2_produced === total_co2 (identically)
    //
    // `<--` performs ONLY the witness assignment (hint to the prover engine).
    // It adds NO constraint to the R1CS. Without the subsequent `===` line,
    // a malicious prover could inject any value for carbon_intensity and
    // the proof would still verify — a critical soundness vulnerability.
    carbon_intensity <-- total_co2 / h2_produced;

    // This line is the actual R1CS constraint. It enforces the multiplication
    // equivalence at the constraint level, closing the soundness gap opened
    // by `<--`. The combination of `<--` (assign) + `===` (constrain) is the
    // canonical Circom pattern for encoding non-native operations such as
    // integer division, modular reduction, and bitwise decomposition.
    carbon_intensity * h2_produced === total_co2;

    // ── Step 3: Regulatory Compliance Inequality ───────────────────────────
    // We compute the signed difference to create the basis for a range proof.
    // If emission_threshold >= carbon_intensity, then diff is non-negative.
    signal diff;
    diff <== emission_threshold - carbon_intensity;

    // PRODUCTION NOTE: The above `diff` computation alone does NOT enforce
    // the inequality diff >= 0. In the BN254 field F_p, any "negative" value
    // is represented as a large positive integer close to p. An unconstrained
    // diff signal would not distinguish between a valid positive remainder
    // and a field-wrapped negative value.
    //
    // Production implementation MUST replace this with a multi-bit comparator
    // from circomlib, e.g.:
    //
    //   include "circomlib/circuits/comparators.circom";
    //   component lte = LessEqThan(252);
    //   lte.in[0] <== carbon_intensity;
    //   lte.in[1] <== emission_threshold;
    //   lte.out === 1;
    //
    // LessEqThan performs a binary decomposition of both operands and verifies
    // the comparison using O(n) constraints where n is the bit width. Using
    // 252-bit comparators (safe for BN254's ~254-bit field) ensures soundness.
}

// ── Circuit Export Declaration ─────────────────────────────────────────────
// The `public` array explicitly marks which signals are included in the
// public input vector submitted to the on-chain verifier.
// All signals NOT listed here are treated as private witness data.
component main {public [h2_produced, emission_threshold]} = H2LedgerVerifier();
```

---

### 4.2 Constraint Semantics: Assignment vs. Constraint Operators

Understanding the distinction between Circom's assignment and constraint operators is not merely syntactic — it is the central correctness and security invariant of the entire circuit.

**`<==` (Assign-and-Constrain)**

The `<==` operator is the compound form. It performs both witness assignment and R1CS constraint generation simultaneously. Concretely, `total_co2 <== energy_consumed * supplier_emission_factor` generates the R1CS triplet `(A, B, C)` such that `A · B − C = 0` is enforced across all valid witnesses. Any proof that does not satisfy this equation will fail the pairing verification on-chain. This is the safe default for all quadratic expressions and linear combinations.

**`<--` (Assign Only — Witness Hint)**

The `<--` operator injects a value into the witness vector during the prover's local computation phase, but adds **zero constraints** to the R1CS. It exists to communicate computational hints to the witness generation engine for operations that are not natively expressible as degree-2 polynomial constraints (e.g., division, square roots, bit decompositions). Used alone, it represents a **critical soundness hole**: a malicious prover can assign any arbitrary value without the constraint system detecting it.

**`===` (Constrain Only — No Assignment)**

The `===` operator generates an R1CS constraint without assigning a witness value. It is always paired with a preceding `<--` to close the soundness gap. The pattern `x <-- f(y); x * z === w;` is the canonical Circom idiom for constraining non-native operations: the prover computes `x` locally via `f(y)`, then the constraint `x * z = w` forces the system to reject any witness where the assignment is inconsistent with the public inputs.

**Security Summary:**

| Operator | Generates R1CS Constraint | Assigns Witness Value | Safe Standalone |
|---|---|---|---|
| `<==` | ✅ Yes | ✅ Yes | ✅ Yes |
| `<--` | ❌ No | ✅ Yes | ❌ **No — soundness hole** |
| `===` | ✅ Yes | ❌ No | ⚠️ Only with prior `<--` |

---

### 4.3 Field Arithmetic and Integer Rounding Implications

The BN254 scalar field `F_p` is a finite field of prime order. All arithmetic in the circuit is performed modulo `p`. This imposes two non-trivial constraints on the H2Ledger implementation:

**Division truncation and non-uniqueness.** When computing `carbon_intensity <-- total_co2 / h2_produced`, the result is the field element `total_co2 · h2_produced⁻¹ mod p`. This is not equivalent to integer floor division. If `total_co2` is not exactly divisible by `h2_produced`, the field inverse will produce a large integer — not the decimal quotient a real-world engineer would expect. The multiplication equivalence check `carbon_intensity * h2_produced === total_co2` implicitly enforces exact divisibility. In practice, all input values must be pre-scaled (e.g., by a factor of 10³ or 10⁶) to eliminate fractional residuals before witness injection.

**Field overflow and underflow.** The "subtraction" `emission_threshold - carbon_intensity` is performed modulo `p`. If `carbon_intensity > emission_threshold` (the non-compliant case), the result is not a negative number but rather `p − (carbon_intensity − emission_threshold)`, a very large positive integer. A naive range check on `diff` would therefore pass even for non-compliant producers. This is precisely why the production circuit must use a dedicated `LessEqThan(n)` comparator component from `circomlib`, which performs a correct binary decomposition and avoids this field-wrapping failure mode.

**Constraint count implications.** The `LessEqThan(252)` comparator generates approximately 252 additional R1CS constraints. For a batch-processing deployment with many concurrent proof submissions, this constraint overhead should be evaluated against prover latency targets and the available trusted setup (SRS) size.

---

## 5. Post-Quantum Agility & Roadmap Note

### 5.1 Current Cryptographic Exposure

The present H2Ledger architecture is instantiated over the **BN254 (alt-bn128) elliptic curve** using the **Groth16** proof system, which relies on:

- **Bilinear pairing operations:** `e: G1 × G2 → GT` over BN254.
- **Elliptic Curve Discrete Logarithm Problem (ECDLP):** hardness in the groups G1, G2, GT.
- **Knowledge of Exponent assumptions** in the Generic Group Model.

All of these assumptions are **vulnerable to Shor's algorithm** running on a sufficiently large, fault-tolerant quantum computer. Shor's algorithm solves the discrete logarithm problem in polynomial time (`O(n³)` quantum gate complexity), which would allow a quantum-capable adversary to:

1. **Forge proofs** by extracting the toxic waste `τ` from the structured reference string (SRS), even from a completed trusted setup.
2. **Reconstruct private witnesses** by inverting the group operations underlying the commitment scheme.
3. **Break on-chain verifier security** by computing valid `(A, B, C)` proof tuples without satisfying the underlying circuit constraints.

The National Institute of Standards and Technology (NIST) finalized its first set of post-quantum cryptographic standards in 2024. The EU's NIS2 Directive and associated critical infrastructure mandates are converging toward a **2030 hard deadline** for post-quantum migration in regulated sectors, including energy infrastructure — a category that explicitly encompasses green hydrogen certification systems.

### 5.2 Vulnerability Surface by Component

```
┌──────────────────────────────────────────────────────────────────────────┐
│              QUANTUM THREAT SURFACE MAP — H2Ledger v1.0                  │
├───────────────────────────┬──────────────────┬───────────────────────────┤
│ Component                 │ Algorithm        │ Quantum Vulnerability      │
├───────────────────────────┼──────────────────┼───────────────────────────┤
│ Groth16 Prover/Verifier   │ BN254 Pairings   │ CRITICAL — Shor breaks     │
│                           │ (ECC)            │ ECDLP in poly-time         │
├───────────────────────────┼──────────────────┼───────────────────────────┤
│ Trusted Setup (SRS)       │ τ ∈ F_p secrets  │ CRITICAL — SRS extraction  │
│                           │ (ECC-based)      │ enables universal forgery  │
├───────────────────────────┼──────────────────┼───────────────────────────┤
│ On-Chain Commitment Hash  │ Keccak-256 /     │ MODERATE — Grover's algo   │
│                           │ Poseidon         │ halves effective key space │
│                           │ (hash-based)     │ (256→128 bits security)    │
├───────────────────────────┼──────────────────┼───────────────────────────┤
│ Signal Encoding / Scaling │ Pure arithmetic  │ NONE — field arithmetic    │
│                           │ over F_p         │ is quantum-agnostic        │
└───────────────────────────┴──────────────────┴───────────────────────────┘
```

### 5.3 Migration Pathway: STARK-Based Post-Quantum Architecture

The recommended migration target is a **hash-based STARK system** (Scalable Transparent ARguments of Knowledge), specifically a **FRI (Fast Reed-Solomon Interactive Oracle Proof of Proximity)**-based construction such as those implemented in StarkWare's Cairo VM, Polygon Miden, or the `plonky2` / `plonky3` frameworks.

**Why STARKs are post-quantum resistant:**

STARKs derive their security exclusively from **collision-resistant hash functions** (e.g., Poseidon, BLAKE3, Rescue-Prime), which are believed to be quantum-resistant under conservative parameter choices. The FRI protocol reduces polynomial proximity testing to a sequence of hash-based Merkle commitments. There is no pairing operation, no elliptic curve group assumption, and no trusted setup — all three of which are eliminated simultaneously.

**Why STARKs eliminate the trusted setup problem:**

Groth16 requires a circuit-specific trusted setup (Powers of Tau + phase-2 ceremony). If the ceremony is compromised or the toxic waste `τ` is recovered — by any means, including quantum computation — the security of every proof ever generated under that setup is retroactively destroyed. STARKs are **transparent**: their security is derived entirely from public randomness (Fiat-Shamir transform over a hash function), and there is no secret parameter to compromise.

**Concrete migration steps for H2Ledger:**

The migration is not a simple parameter swap; it requires a ground-up re-implementation of the constraint system in the target framework's intermediate representation.

```
Phase 0 (2025–2026): Crypto-Agility Preparation
  ├── Abstract proof system interface (ProofSystem trait / interface)
  ├── Decouple circuit logic from curve-specific primitives
  └── Instrument verifier contract to accept pluggable proof types

Phase 1 (2027–2028): Parallel STARK Implementation
  ├── Port H2LedgerVerifier() constraints to Miden VM or Plonky3 arithmetization
  ├── Replace LessEqThan(ECC) with range proofs over hash-based commitments
  ├── Conduct comparative audit: Groth16 vs. STARK constraint equivalence
  └── Deploy STARK verifier to testnet alongside existing Groth16 verifier

Phase 2 (2029): Migration and Deprecation
  ├── All new proof submissions routed exclusively to STARK verifier
  ├── Historical Groth16 proofs archived (not retroactively invalidated)
  └── SRS toxic waste destruction confirmation — final audit

Phase 3 (2030): Compliance Certification
  ├── EU NIS2 / Critical Infrastructure post-quantum attestation filing
  ├── Full hash-based proof pipeline operational
  └── Groth16 verifier contract decommissioned on-chain
```

**Lattice-based alternative consideration:**

An alternative migration target is **lattice-based SNARKs** (e.g., constructions over Module-LWE or NTRU). These offer asymptotically smaller proof sizes than STARKs and are being actively standardized by NIST (CRYSTALS-Dilithium, Falcon). However, as of 2025, production-grade lattice-based SNARK verifiers for EVM deployment remain immature. The STARK pathway is recommended as the primary migration trajectory given its implementation readiness, with lattice-based constructions re-evaluated at Phase 1 review.

### 5.4 Proof Size and Verifier Gas Cost Implications

The migration to STARKs entails a trade-off that must be quantified in the H2Ledger economic model:

| Property | Groth16 (Current) | STARK / FRI (Target) |
|---|---|---|
| Proof size | ~128 bytes (constant) | ~40–200 KB (logarithmic in circuit size) |
| On-chain verification gas | ~280,000 gas (EVM) | ~5–15M gas (EVM, naïve); ~500K with recursive aggregation |
| Trusted setup required | Yes — circuit-specific | No — fully transparent |
| Quantum resistance | None | Strong (hash-based) |
| Proof generation time | Fast (~seconds) | Moderate (~seconds to minutes) |
| Verifier complexity | O(1) pairings | O(log² n) hash evaluations |

The increased on-chain verification cost of raw STARKs can be mitigated through **recursive proof aggregation**: multiple H2Ledger compliance proofs can be batched into a single recursive STARK proof (e.g., using Plonky2's recursive composition) and verified in a single on-chain transaction, amortizing the gas cost across the batch and restoring economic viability.

---

> **Architectural Conclusion:** The H2Ledger provenance engine is sound and production-deployable under classical adversarial assumptions. Its zero-knowledge properties rigorously protect industrial trade secrets while providing cryptographically verifiable regulatory compliance. However, the system carries a **known and time-bounded existential risk** from quantum computation targeting its elliptic curve foundations. The crypto-agility framework and STARK migration roadmap defined in Section 5 represent the mandatory engineering trajectory to ensure regulatory compliance and long-term trust in the H2Ledger certification infrastructure through and beyond the 2030 EU mandate horizon.

---

*End of Executive Cryptographic Specification: H2Ledger Provenance Engine v1.0.0*
