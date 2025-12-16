/**
 * MASP E2E Test - SCAFFOLDING
 * 
 * Basic test that deploys and calls each instruction.
 * Architecture and proper tests TBD.
 */

import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import fs from "fs";

const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8899";

// Instruction discriminators
const IX_SHIELD = 0;
const IX_TRANSFER = 1;
const IX_UNSHIELD = 2;

async function main() {
  console.log("=== MASP E2E Test (Scaffolding) ===\n");
  
  const connection = new Connection(RPC_URL, "confirmed");
  
  // Load or create payer keypair
  let payer;
  const keypairPath = process.env.KEYPAIR || `${process.env.HOME}/.config/solana/id.json`;
  if (fs.existsSync(keypairPath)) {
    const keypairData = JSON.parse(fs.readFileSync(keypairPath));
    payer = Keypair.fromSecretKey(new Uint8Array(keypairData));
  } else {
    payer = Keypair.generate();
    console.log("Generated new keypair, requesting airdrop...");
    const sig = await connection.requestAirdrop(payer.publicKey, 10e9);
    await connection.confirmTransaction(sig);
  }
  
  console.log(`Payer: ${payer.publicKey.toBase58()}`);
  
  // Get program ID from deploy or environment
  const programId = process.env.PROGRAM_ID 
    ? new PublicKey(process.env.PROGRAM_ID)
    : null;
    
  if (!programId) {
    console.log("\nNo PROGRAM_ID set. Deploy the program first and set PROGRAM_ID env var.");
    console.log("Example: PROGRAM_ID=<pubkey> node scripts/test_e2e.mjs");
    return;
  }
  
  console.log(`Program: ${programId.toBase58()}\n`);
  
  // Test each instruction (stub calls)
  for (const [name, discriminator] of [
    ["Shield", IX_SHIELD],
    ["Transfer", IX_TRANSFER],
    ["Unshield", IX_UNSHIELD],
  ]) {
    console.log(`Testing ${name}...`);
    
    const ix = new TransactionInstruction({
      programId,
      keys: [], // No accounts needed for stub
      data: Buffer.from([discriminator]),
    });
    
    const tx = new Transaction().add(ix);
    
    try {
      const sig = await sendAndConfirmTransaction(connection, tx, [payer]);
      console.log(`  ✓ ${name} succeeded: ${sig}\n`);
    } catch (e) {
      console.log(`  ✗ ${name} failed: ${e.message}\n`);
    }
  }
  
  console.log("=== E2E Test Complete ===");
}

main().catch(console.error);

