const { buildPoseidon } = require("circomlibjs");

async function main() {
  // Initialize Poseidon
  const poseidon = await buildPoseidon();

  // Private inputs (must match values you'll use in inputs.json)
  const depositor = BigInt("123456789");      // Use BigInt for large numbers
  const amount = BigInt("1000000");           // Amount in wei
  const destinationChainId = BigInt("1");      // Chain ID
  const secret = BigInt("987654321");         // Random private number

  // Compute eventHash = Poseidon([depositor, amount, chainId, secret])
  const eventHash = poseidon([
    depositor,
    amount,
    destinationChainId,
    secret
  ]);

  // Compute nullifierHash = Poseidon([secret])
  const nullifierHash = poseidon([secret]);

  console.log("Computed Hashes:");
  console.log("eventHash:", poseidon.F.toString(eventHash));
  console.log("nullifierHash:", poseidon.F.toString(nullifierHash));
}

main().catch(console.error);