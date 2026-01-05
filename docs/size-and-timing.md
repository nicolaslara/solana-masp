# Size & Timing Analysis (Production Viability)

This doc summarizes **Solana transaction size constraints**, the **current on-wire layouts** in this repo, and what that implies for:

- how much space we need per shield / transfer / unshield
- how many transactions are in the critical path (latency)
- what can be parallelized vs what is sequential
- feasibility of “15 input notes → 1 output note” transfers

Sources of truth:

- Solana tx envelope limit: **1232 bytes** (packet MTU constraint; see `knowledge.md`)
- Client tx construction: `client/src/backends/solana.rs`
- Program parsing + account requirements: `programs/solana-masp/src/instructions.rs`, `programs/solana-masp/src/inputs.rs`
- Ciphertext formats: `client/src/encryption.rs`
- Proof sizes: `programs/solana-masp/src/verify.rs`

---

## Current byte sizes (ciphertexts, proofs)

### Ciphertexts (outputs-only DA, Option 1A)

From `client/src/encryption.rs`:

- `C_enc` (`EncryptedNote::to_bytes()`): `ENCRYPTED_NOTE_SIZE = 8 + 64 + 12 + 144 + 16 = 244 bytes`
- `C_out` (`OutgoingCiphertext::to_bytes()`): `C_OUT_SIZE = 12 + (32 + 144) + 16 = 204 bytes` (V2 format; V1 was 236 bytes)

**Important current inefficiency (space + hashing):**

- The client currently computes `ct_hash = H(ephemeral_key || ciphertext_bytes)`.
- But `ciphertext_bytes` is often `EncryptedNote::to_bytes()`, which already includes `ephemeral_key`.
- So the *posted bytes* / *hashed bytes* currently duplicate **64 bytes/output**.

### Proof sizes (verification backends)

From `programs/solana-masp/src/verify.rs`:

- **UltraPlonk** proof: `2144 bytes`
- **Groth16** proof: `192 bytes`

---

## Transaction shapes and instruction-data sizes (today)

### Shield (Tx B: MASP state transition)

From `client/src/backends/solana.rs::shield()` the instruction data is:

- `IX_SHIELD` (1)
- `commitment` (32)
- `asset_id` (32)
- `amount` (8)
- `ct_hash` (32)

Total: **105 bytes**.

Accounts (typical):

- payer (signer)
- tree_state PDA (writable)
- proof_buffer (read-only)
- optional: mock commitment store program + state
- optional: verifier program (CPI mode)

### Transfer (Tx B: MASP state transition)

From `client/src/backends/solana.rs::transfer()` and `programs/solana-masp/src/instructions.rs::TransferData`:

- discriminator `IX_TRANSFER` (1)
- `anchor` (32)
- `nullifiers[3]` (96)
- `output_commitments[3]` (96)
- `input_count` + `output_count` (8)
- `ct_hashes[3]` (96)
- `tx_binding` (32)

Total: **361 bytes**.

Accounts (typical, CPI verification + direct nullifier PDAs):

- authority/payer (signer)
- tree_state PDA (writable)
- proof_buffer (read-only)
- system program (read-only)
- optional: verifier program (read-only)
- **nullifier PDAs**: `input_count` writable accounts (1–3 today)
- optional: mock commitment-store program + store-state (simple-onchain-store feature)

### Unshield (Tx B: MASP state transition)

From `client/src/backends/solana.rs::unshield()` and `programs/solana-masp/src/instructions.rs::UnshieldData`:

- `IX_UNSHIELD` (1)
- `anchor` (32)
- `nullifier` (32)
- `tx_binding` (32)
- `amount` (8)
- `recipient_limbs[4]` (32)  (4×u64 LE)
- `asset_id` (32)

Total: **169 bytes**.

Accounts (typical):

- authority/payer (signer)
- tree_state PDA (writable)
- proof_buffer (read-only)
- nullifier PDA (writable)
- system program (read-only)
- optional: store program (simple-onchain-store)
- optional: verifier program (CPI mode)

---

## Proof buffer upload overhead (how many txs per operation)

We do **not** fit UltraPlonk proofs into a single Solana transaction. Instead we upload to a proof buffer and then reference that buffer from Tx B.

From `client/src/backends/solana.rs`:

- proof buffer header size: **5 bytes**
- chunk size: `MAX_CHUNK_SIZE = 900` bytes of payload per `UploadChunk` tx

### Proof-buffer payload sizes (UltraPlonk)

The proof-buffer payload is:

`public_inputs_bytes (pi_count * 32) || proof_bytes`

Current public input counts (program side):

- Shield: 4 public inputs → 128 bytes
- Transfer: 13 public inputs → 416 bytes
- Unshield: 9 public inputs → 288 bytes

So total payload sizes:

- Shield: `128 + 2144 = 2272` (+5 header in account)
- Transfer: `416 + 2144 = 2560`
- Unshield: `288 + 2144 = 2432`

With 900-byte chunks, each requires **3 upload txs**.

#### Critical-path tx count (UltraPlonk)

Assuming CPI-verifier mode where the buffer is owned by the verifier program (see `create_proof_buffer()`):

- **Tx 0**: create buffer account (system create-account)
- **Tx 1**: init buffer header
- **Tx 2–4**: upload chunks (3 txs)
- **Tx 5**: MASP Shield/Transfer/Unshield (Tx B)

So each operation is **~6 Solana transactions** in the current architecture.

### If Groth16 is used

Transfer payload becomes `416 + 192 = 608` bytes, which fits under one chunk.

That allows:

- init+upload combined (or init + one upload)
- then Tx B

So the critical path can drop from ~6 tx → **~2–3 tx** for the same operation.

---

## What can be parallelized vs what is sequential

### Off-chain (wallet)

Can be parallelized:

- trial encryption and `ct_hash` computation per output
- witness assembly per input (Merkle paths fetched in parallel)
- proving for different *independent* operations (e.g., two transfers) can run concurrently on a multi-core machine

Must be sequential inside one operation:

- `tx_binding` depends on the chosen `anchor` + nullifiers + counts, but is cheap
- proof generation depends on having all private inputs (witness) and `ct_hashes` ready

### On-chain / network (Solana)

Can be parallelized (latency hiding):

- **Tx A ciphertext posting** can be submitted in parallel with **proof-buffer uploads** (neither depends on the other).
- If you chunk ciphertext posting (multiple posting txs), those postings can also be pipelined with proof-buffer chunk uploads.

Must be sequential (hard dependencies):

- Tx B must wait until:
  - proof buffer is fully uploaded, and
  - the wallet knows the `ct_hashes` it binds to (from the bytes it posted in Tx A).

Contention limitation (throughput):

- Every MASP state transition writes the same `tree_state` PDA (writable account), so **Solana will serialize these transactions** (account lock). Even if you submit in parallel, the runtime cannot execute them concurrently due to the shared writable account.

---

## “15 inputs → 1 output” feasibility

### Interpreting the question (assume we *change* MAX_* to 15→1)

Yes — the intent here is: **raise the compile-time maxima** so a single transfer can support something like:

- `MAX_INPUTS = 15`
- `MAX_OUTPUTS = 1` (or 2 if you want explicit change output)

The feasibility question is then: *after we change those constants and rebuild the circuit/program/client, does it still fit Solana’s byte + CU limits, especially under Light’s current non-membership batching max=2?*

### Size blockers for 15 inputs (even after circuit work)

Two things scale with input count:

1. **Public inputs and proof-buffer sizing**
   - If the MASP proof keeps **explicit nullifiers** as public inputs, public input count grows with `MAX_INPUTS` and you must raise verifier limits:
     - `programs/solana-masp/src/verify.rs`: `MAX_PUBLIC_INPUTS = 16` (too small for 15-input layouts that expose nullifiers + outputs + counts + ct_hashes, etc.)
     - `programs/solana-masp/src/state.rs`: `MAX_PROOF_BUFFER_SIZE = 5 + 512 + 2144` assumes max 16 public inputs; must be increased accordingly.
   - If instead you adopt the **intent-hash / `h_nf`** model (nullifiers private, only `h_nf` public), public input growth can be kept small even for large `MAX_INPUTS`.

2. **Accounts passed to the program (uniqueness path)**
   - In the current PDA-per-nullifier model, `process_transfer()` expects **one writable nullifier PDA account per enabled input**.
     - So `MAX_INPUTS=15` implies **15 writable accounts** in the apply tx, which is a tx-size constraint and usually requires **v0 + Address Lookup Tables (ALTs)**.
   - In the production Light model, you don’t pass 15 PDAs, but you still pay for Light uniqueness checks.
     - Under the current constraint “non-membership batching max 2”, you need \(\lceil 15/2 \rceil = 8\) Light non-membership proofs for nullifier uniqueness, which can become the dominant **CU + bytes** limiter.

In practice, a 15-input Transfer Tx B will usually **not fit in a single legacy (non-v0) Solana transaction** without:

- **Address Lookup Tables (ALTs)**, and
- switching to **v0 (versioned) transactions** in the client builder.

### Recommendation: “consolidation circuit” rather than main transfer

If we want 15→1 primarily for UTXO consolidation:

- implement a dedicated “consolidate” circuit with `MAX_INPUTS=15`, `MAX_OUTPUTS=1` (or 2 to allow change), and keep the main transfer at 3→3.
- choose circuit at runtime based on coin selection.

This minimizes proof cost for the common case and isolates the “big input set” path.

---

## Nullifier set storage alternatives (PDA vs Light) and what changes in prod

### Option A: PDA-per-nullifier (local dev simplification / reference)

**On-chain shape (in this repo today):**

- Each non-zero input nullifier requires a **writable PDA account** passed to Tx B.
- Program creates the PDA (rent-exempt) and writes a `NullifierAccount`.
- `NullifierAccount::SIZE = 41 bytes` (`programs/solana-masp/src/state.rs`).

**Pros (for local dev):**

- Simple semantics: existence = spent.
- No external infra dependency (good for local bringup).
- Off-chain spent checks can be cheap: batch `getMultipleAccounts` for PDAs.

**Cons (production):**

- **Unbounded state growth**: one account per nullifier forever (not acceptable for production).
- **Account-list scaling**: N inputs ⇒ ~N extra writable accounts in Tx B.
  - This is a hard blocker for “15 inputs” unless you use v0+ALTs (and even then, it’s tight depending on other accounts).
- **Capital lock** (not a fee, but locked SOL): each created PDA must be rent-exempt:

\[
\text{locked\_lamports} =
\texttt{getMinimumBalanceForRentExemption}(41) \times (\#\text{nullifiers})
\]

Total locked SOL grows linearly with lifetime spent notes.

### Option B: Light Protocol “address tree” for nullifiers (production target)

**Core idea (from `docs/light-protocol-integration.md` / `docs/light-protocol-questions.md`):**

- Treat each nullifier as a Light compressed account **address**: `address = nullifier`.
- “Spend” = attempt to create address; duplicate spends fail (insert-once).
- Compressed accounts can set `lamports = 0` (no per-nullifier rent-exempt PDA accounts).

**Pros (size + $):**

- Avoids “one PDA per nullifier” rent growth. State is in Light’s compressed trees.
- **Tx B account list does not need to scale with number of nullifiers** in the same way PDAs do (you pass Light’s tree/program accounts, not 15 nullifier PDAs).
- Light supports **batched validity proofs** (`getValidityProof(addresses=[...])`) so on-chain verification can be amortized.
  - **Important current constraint (2025-12):** for **non-membership / uniqueness** checks (nullifier insert-once), batching is limited to **2 items per proof** (max).
  - Repo notes estimate **~100–200K CU** for verifying a batched Light proof (`docs/payment-discovery-analysis.md`), but under the 2-item limit you need multiple proofs for many inputs.

**Cons / costs shift:**

- **Infra dependency**: you typically depend on Photon/Helius (or self-hosted) to produce validity proofs.
- **Compute cost** moves from “many PDA creates + long account list” to “Light proof verification + Light CPI”.
- **Liveness risk**: Light state updates can depend on the forester/queue mechanics (documented in `knowledge.md`).

### Cost model (high-level, $)

Solana “$ cost” is dominated by:

- **Base fee**: signatures per transaction (small, but multiplied by tx count; UltraPlonk buffering is tx-heavy).
- **Priority fee**: \( \text{CU} \times \text{microLamportsPerCU} \) (dominant in congestion).
- **Capital lock**: rent-exempt lamports for accounts that must live forever (PDA approach).
- **Service cost**: external indexer/RPC provider fees (Light approach).

So, roughly:

- **PDA nullifiers**: low-ish CU for uniqueness, but high **rent lock** + poor scaling to large input counts.
- **Light nullifiers**: low **state rent lock**, good scaling for large input counts, but you pay:
  - extra **on-chain CU** for Light proof verification/CPI, and
  - **off-chain service** costs for validity proofs + operational complexity.

---

## Light model “full” sizing under the current non-membership batching limit (max 2)

This section focuses on the **production-target nullifier model**:

- nullifier uniqueness via Light “address tree” (insert-once)
- **non-membership proofs batch at most 2 nullifiers per proof** (current constraint)

### How many Light proofs do we need?

For N input nullifiers in a single MASP transfer/unshield:

\[
\text{light\_non\_membership\_proofs}(N)=\lceil N/2 \rceil
\]

Examples:

- N=1 → 1 proof
- N=2 → 1 proof
- N=3 → 2 proofs
- N=15 → 8 proofs

### Compute budget feasibility (CU)

Let:

- \(CU_{\text{masp}}\) be the MASP proof verification cost (UltraPlonk or Groth16)
- \(CU_{\text{light}}\) be the per-proof Light verification/CPI cost (batched proof for up to 2 items)

Then the rough bound for an atomic spend is:

\[
CU_{\text{total}} \approx CU_{\text{masp}} + \lceil N/2 \rceil \cdot CU_{\text{light}} + CU_{\text{overhead}} \le 1.4\text{M}
\]

Implications:

- With **UltraPlonk** on-chain verification in this repo (~1.2M CU in practice), there is only enough headroom for **~1–2 Light proofs**.
  - That effectively caps N at **~2–4 inputs** under the “2-per-proof” constraint.
  - **Conclusion:** a 15-input *atomic* consolidation is not viable if we keep UltraPlonk verification on-chain in the same transaction as Light non-membership checks.
- With **Groth16** for MASP (~81K CU), the constraint shifts to Light proofs:
  - N=15 requires 8 Light proofs; whether that fits depends on the real \(CU_{\text{light}}\) (and overhead).

### Transaction size feasibility (bytes)

Even if CU fits, 15-input spends must still fit the **1232-byte transaction envelope**.

Under the 2-item batching limit, you may need to include **8 proof payloads** for N=15.
If those payloads are not tiny, they will not fit inline.

**Practical requirement:** if we pursue large-input spends with Light under this constraint, we likely need a **proof-buffer / chunk-upload pattern** for the Light proof payloads as well (similar to how we handle UltraPlonk proof bytes today), or accept multi-transaction (non-atomic) execution.

### Production-shaped recommendation under this constraint

- Keep “payment transfer” circuits small (e.g., 2–3 inputs) so \(\lceil N/2 \rceil\) stays small.
- Treat “15→1 consolidation” as:
  - either a *rare* operation that uses **Groth16 MASP** and is carefully engineered for tx size (buffers/ALTs),
  - or a multi-step consolidation strategy (loses atomicity; needs careful UX + replay protection).

## Theoretical byte-size wins (most impactful first)

1. **Avoid duplicate `ephemeral_key` in Tx A posting + `ct_hash` hashing**
   - Today: `ct_hash = H(ephemeral_key || EncryptedNote::to_bytes())`, but `EncryptedNote::to_bytes()` already includes `ephemeral_key`.
   - Canonicalize to hash/post **exactly one copy** of `ephemeral_key`.
   - Win: **64 bytes per output** in Tx A, plus less hashing work.

2. **Prefer Groth16 for production throughput (if acceptable)**
   - Reduces proof bytes (2144 → 192) and verification CU (~1.2M → ~81K).
   - Enables removing the multi-tx proof-buffer upload path (or makes it 1 upload at most).

3. **Separate “large-input consolidation” from “payment transfers”**
   - Keeps the common transfer tx smaller and faster.
   - Large input-set txs can be rarer and can use ALTs if needed.

---

## Open follow-ups

- Decide whether we want to make v0+ALT a **first-class requirement** (needed for 15-input spends with PDA-per-nullifier).
- Decide whether we want a **15-input consolidation circuit** and keep main transfer at 3-input.
- Decide canonical “bytes posted in Tx A” format and freeze it (removes epk duplication, aligns `ct_hash` semantics).

---

## Can we verify proofs in a separate “third tx”?

Yes, **but not for free**.

Today’s model is effectively:

- Tx A: post ciphertext bytes (optional / Option 1A)
- Tx A′: upload proof bytes into a proof buffer (chunked)
- Tx B: **verify proof(s) + update MASP state** (anchor check, nullifier insert, commitment insert)

### 3‑tx model (verification separated from state transition)

You can restructure to:

- Tx A / A′: post ciphertexts + upload proof material(s)
- **Tx V (Verify-only)**:
  - verify MASP proof (and any Light proofs) *now*
  - write a compact “verified” marker on-chain (e.g., set `proof_buffer.status = Verified` and store a hash of the exact public inputs / intent)
- **Tx S (State transition-only)**:
  - re-check **anchor validity** (must still be valid at apply time)
  - enforce **nullifier uniqueness** at apply time (may fail if someone else spent in the meantime)
  - apply commitment inserts / leaf count updates
  - require and consume the “verified marker” so it can’t be replayed

### What this buys you

- **Compute budget distribution**: you can move heavy verification work out of the state transition tx to fit per-tx CU limits (useful under Light non-membership batching limits).
- Potentially simpler “big input count” paths if CU, not bytes, is the binding constraint.

### What you must add to make it safe

- **Anti-replay / anti-theft**:
  - Tx S must require the same authority (or an explicit authorization) as Tx V, otherwise anyone who sees the verified marker could front-run Tx S and “spend your proof”.
  - The verified marker must bind to **exact intent** (at minimum: anchor, nullifiers, output commitments, counts, ct_hashes, tx_binding; and ideally program_id/chain_id context).
  - The marker must be **one-time consumable** (mark “used” when Tx S succeeds).
- **Non-atomicity handling**:
  - Between Tx V and Tx S, the anchor window can move and nullifiers can be spent by competing transactions.
  - So Tx S can still fail even if Tx V succeeded; wallets need retry/refresh logic (new anchor / new proofs).

### Bottom line

- **Yes**, a verify-only “third tx” is viable and is a common technique to fit CU limits.
- But it requires explicit program design for “verified intent objects” (or “proof tickets”) to prevent replay/front-running, and it trades atomicity for schedulability.
