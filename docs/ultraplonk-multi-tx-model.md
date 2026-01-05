# UltraPlonk Multi‑TX Model (Production‑Shaped)

This document specifies a **multi‑transaction execution model** for MASP when the proving system is **UltraPlonk** and on-chain verification is expensive enough that we may need to split verification and application.

It also describes how this model **simplifies under Groth16**.

This doc is intended to be **protocol‑shaped**: the interface and safety story should remain valid even if internal implementations change (buffers vs inline bytes, different indexers, etc.).

Key constraints incorporated:

- Solana transaction envelope ~**1232 bytes** (packet-size constraint).
- UltraPlonk proof bytes ~**2144 bytes** (see `programs/solana-masp/src/verify.rs`).
- Light Protocol nullifier uniqueness uses **non-membership proofs batched at most 2 items per proof (current constraint)**.

---

## Goals

- Enable **production-safe** execution even when UltraPlonk verification + Light nullifier uniqueness cannot fit within a single tx’s compute budget.
- Ensure **safety** across tx boundaries:
  - no “mix-and-match” of nullifiers/outputs between verify and apply
  - no replay of a verified intent
  - no theft or output redirection by relayers/front-runners
- Minimize privacy harm:
  - **avoid revealing nullifiers** in “verify-only” steps
  - only reveal nullifiers in the step that actually attempts uniqueness insertion

Non-goals:

- Guarantee atomicity across multiple transactions. Multi-tx implies apply may fail; wallets must retry.

---

## Concepts

### Intent hash

An **intent hash** is a single field element (or 32-byte digest) that commits to the complete spend intent.

Properties required:

- **Binding**: changing any relevant field changes the intent hash.
- **Context bound**: includes chain/program context to prevent cross-deployment replay.
- **Public**: it is a public input to the MASP proof so verification binds to it “for free”.

We can reuse or extend the existing notion of `tx_binding`, but for this model we treat the intent hash as the primary commitment object.

### Private nullifiers in the MASP proof

To avoid revealing nullifiers during verify-only, the MASP proof should:

- take the per-input nullifiers as **private inputs**
- compute `h_nf = H(padded_nullifiers)` inside the circuit
- bind the public intent hash to `h_nf` (not to explicit nullifier values)

This ensures a verify-only tx reveals **only** the committed digest, not the nullifiers themselves.

### Verified intent ticket (on-chain)

A **VerifiedIntentTicket** is an on-chain marker that records “a proof for intent_hash was verified”.

It must be:

- **one-time consumable** (to prevent replay)
- **context-bound** (to this program + cluster)
- optionally **permissioned** (require a specific signer to consume) — not required for soundness if the intent fully commits outputs, but useful for relayer economics

---

## Transaction sequence (UltraPlonk)

There are up to **four** logical phases. Some can run in parallel.

### Tx A — Ciphertext posting (Option 1A, outputs-only)

Purpose:

- publish output ciphertext bytes to the ledger for data availability (DA)

Inputs:

- ciphertext posting bytes per output (canonical format must be frozen)
- (optionally) output indexing metadata for indexers

Outputs / linkage:

- Wallet computes `ct_hash[j] = H(ciphertext_bytes[j])` locally.
- `ct_hashes[]` are committed by the MASP intent hash and later enforced by wallets.

Notes on current sizes (from current repo implementation):

- `C_enc` (recipient ciphertext) is **244 bytes** (`client/src/encryption.rs`: `ENCRYPTED_NOTE_SIZE`).
- Current implementation duplicates `ephemeral_key` in the hashed/posting blob; removing that is a straightforward size win (~64B/output).

### Tx P — Proof material upload (buffers; chunked)

Purpose:

- make proof bytes available to the verifier program without exceeding tx envelope limits

Inputs:

- MASP proof bytes (UltraPlonk: ~2144B)
- MASP public input bytes for verification

Mechanism:

- create a proof buffer account
- upload bytes in chunks (current chunk size in client is 900B payload)

Outputs / linkage:

- a `proof_buffer` account address referenced by later txs

Notes on current sizes:

- Current public input counts (current transfer layout) include explicit nullifiers.
- Under the “private nullifiers” model, the number of public inputs can decrease (see “Size simplifications” below).

### Tx V — Verify-only (“VerifyIntent”)

Purpose:

- verify the MASP proof for a specific `intent_hash` and write a consumable ticket

Inputs:

- `proof_buffer` containing:
  - the MASP public inputs (including `intent_hash`)
  - the UltraPlonk proof bytes
- (optional) verifier program account (CPI mode)

Program actions:

1. Parse public inputs from `proof_buffer`.
2. Verify UltraPlonk proof.
3. Compute `intent_hash` (or read it as a public input) and create `VerifiedIntentTicket(intent_hash, expiry, …)`.
4. Mark buffer as verified/frozen (optional hardening).

Outputs / linkage:

- a `VerifiedIntentTicket` (PDA keyed by `intent_hash` or a unique nonce + `intent_hash`)

Privacy:

- nullifiers are **not revealed** here if the MASP proof commits only to `h_nf` (digest) rather than explicit nullifiers.

### Tx S — Apply-only (“ApplyIntent”)

Purpose:

- reveal the concrete nullifiers and apply the state transition (uniqueness + commitment inserts)

Inputs:

- `VerifiedIntentTicket`
- revealed `nullifiers[]` (padded to max inputs)
- any public outputs needed to apply (or reconstructed from ticket / proof inputs), including:
  - output commitments
  - `ct_hashes[]` (if not already committed in the intent)
  - counts
  - anchor
- Light non-membership proof(s) for nullifier uniqueness (current constraint: batch max 2 per proof)

Program actions (must be deterministic):

1. Recompute `h_nf = H(padded_nullifiers)` from the revealed nullifiers.
2. Recompute `intent_hash` (or verify that `intent_hash` inside ticket commits to `h_nf`).
3. Re-check **anchor validity** at apply time (root history).
4. Enforce **nullifier uniqueness** at apply time:
   - with PDAs (reference model) or
   - with Light (production): verify required non-membership proof(s) and insert addresses.
5. Insert output commitments / update commitment accumulator state.
6. Consume the ticket (close or mark “used”).

Failure modes (expected):

- anchor became stale → retry with fresh anchor and new proofs
- nullifier already spent → must choose different inputs and re-prove

Parallelism:

- Tx A (ciphertext posting) and Tx P (proof upload) can run in parallel.
- Tx V depends on Tx P completing.
- Tx S depends on Tx V completing and (if using Light) on obtaining Light non-membership proof(s).

---

## Safety argument (what makes it safe)

### Preventing “swap” between verify and apply

Tx S is safe if it enforces:

- the revealed `nullifiers[]` match the commitment inside `intent_hash` (via `h_nf`)
- the applied outputs (`output_commitments[]`, `ct_hashes[]`, counts, etc.) are also committed by `intent_hash`

Then no relayer/front-runner can:

- replace nullifiers
- redirect outputs
- change ciphertext binding hashes

### Preventing replay

The `VerifiedIntentTicket` must be one-time consumable. Consuming it on successful apply prevents replay even if the same intent could theoretically be re-submitted.

(Nullifier uniqueness also prevents replay, but ticket consumption is the correct explicit replay control for a multi-tx protocol.)

### Authority / relayers

From a **soundness** perspective, a special “authority” signer is not required if:

- the MASP proof + `intent_hash` fully commit to outputs and nullifiers (via `h_nf`), and
- Apply enforces that commitment.

You may still introduce authority for:

- relayer fee guarantees (ensure fee recipient is committed in outputs)
- who is allowed to consume a ticket (optional)

---

## Size simplifications (how inputs could become smaller/simpler)

This model naturally enables simplifications relative to the current “explicit nullifiers are public inputs” layout:

1. **Do not expose nullifiers as MASP public inputs**
   - Replace explicit `nullifiers[]` in the MASP public input list with `h_nf`.
   - This reduces MASP proof public inputs and avoids revealing nullifiers in Tx V.

2. **Keep `ct_hashes[]` as committed values (public)**
   - If the MASP proof commits to `ct_hashes[]`, Apply doesn’t need ciphertext bytes, only the hashes.
   - Wallets still verify `ct_hash == H(ciphertext_bytes)` off-chain when accepting outputs.

3. **Avoid duplicated ephemeral key bytes in ciphertext posting**
   - Canonicalize the posted bytes so the `ephemeral_key` is not included twice (current repo has duplication in the hashed blob).

4. **If using Groth16 for MASP**
   - proofs are smaller (192B), often eliminating proof buffers entirely.

---

## How this changes under Groth16

Groth16 changes both **bytes** and **compute**, which often collapses the multi-tx protocol:

- MASP proof size ~**192 bytes** (vs 2144)
- MASP verification CU is dramatically smaller than UltraPlonk (order-of-magnitude; exact CU depends on implementation)

Practical consequences:

- In many cases you can do **Verify + Apply in a single transaction**, restoring atomicity.
- If Light non-membership batching (max 2) still forces multiple proofs, you may still need multiple instructions or multiple txs, but MASP verification is no longer the dominant constraint.

If you keep the same “intent hash + reveal nullifiers at apply” architecture:

- the safety story remains identical
- the operational flow becomes simpler (fewer txs, fewer buffers)


