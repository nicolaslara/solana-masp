# MASP Protocol (Reference Implementation Spec)

This document defines the **high-level MASP protocol** implemented by this repo. It is intentionally **implementation-oriented** (describes what the client/chain/indexer/circuits must do), while remaining **production-shaped** (so mocks can be swapped out without changing user flows).

This repo’s authoritative protocol definition and soundness/privacy argument is:

- `docs/protocol-soundness.md` (**primary / normative**)

For the detailed “MUST prove” statements, see `docs/circuit-security-requirements.md`.

---

## Roles and Trust Model

- **Client / Wallet**
  - Holds keys, constructs notes, builds transactions, generates ZK proofs (off-chain).
  - Discovers incoming notes by scanning ciphertexts (or via OOB tx_sig) and verifying plaintext ↔ commitment consistency.
- **Chain (Solana program + SPL token programs)**
  - Enforces state transitions: append commitments, record nullifiers, validate anchors, move tokens.
  - Verifies ZK proofs (in production: on-chain verifier).
- **Indexer (external observer)**
  - Serves encrypted outputs and membership witnesses (Merkle path or Light validity proof).
  - In production the indexer is **not** updated by the chain; it observes ledger data.

---

## Core Data Types

### Note plaintext

A note is a shielded “UTXO-like” object:

- `asset_id: Field` — derived from token mint: `asset_id = H(DOM_ASSET, token_address)`
- `amount: u64` — range checked in-circuit
- `recipient: Field` — diversified address field (e.g. `pk_d.x`)
- `nullifier_nonce: Field` — unique per note, committed in note
- `note_randomness: Field` — hides note contents in commitment

### Commitment (cm)

A commitment is the on-chain leaf representing a note:

```text
cm = H(DOM_NOTE_COMMIT, asset_id, amount, recipient, nullifier_nonce, note_randomness)
```

### Nullifier (nf)

The nullifier is revealed when spending a note and prevents double-spends:

```text
nf = H(DOM_NULLIFIER, nk, nullifier_nonce)
```

Only the note owner can produce the correct `nf` because only they can produce/know the correct `nk`.

### Anchor (root)

An anchor is a commitment-tree root. Transactions bind to an anchor to prove membership against a specific state snapshot.

---

## Operations

### Shield (Deposit)

**Goal:** move value from transparent SPL token balance into the shielded pool.

- **Client does:**
  - Create note plaintext.
  - Compute commitment `cm`.
  - Encrypt note ciphertext(s) for scanning/recovery.
  - Produce a **shield proof** showing `cm` matches note fields (and other required statements).
- **Chain checks:**
  - Transfers `amount` of `token_address` into the pool account.
  - (Optional) verifies shield proof with `vk_shield` (see note below).
  - Appends `cm` to the commitment set.
- **Indexer provides:**
  - Ciphertexts + commitment association for later scanning.

**Do we “need” a shield circuit?**

We keep a `shield` circuit in this repo because it helps lock:

- the note format and commitment preimage layout
- amount range checks and asset binding semantics

However, unlike transfer/unshield, **shield does not prevent theft** if omitted: a malformed commitment mainly causes
sender/recipient griefing (unspendable notes), and the client already verifies plaintext ↔ commitment after decryption.

**Decision (reference implementation):**

- Keep the `shield` circuit and its ABI (so we can enable it later).
- For the earliest on-chain POC we may treat shield proof verification as optional and rely on client-side integrity checks,
  while transfer/unshield remain proof-gated.

### Transfer (Shielded spend → shielded outputs)

**Goal:** spend one input note and create 1–3 output notes (recipient, change, fee).

- **Client does:**
  - Select spend note.
  - Get membership witness from indexer.
  - Compute nullifier `nf`.
  - Construct output notes (recipient/change/fee).
  - Compute output commitments.
  - Generate transfer proof.
  - Submit transaction containing proof + outputs + ciphertexts.
- **Chain checks:**
  - Anchor is valid (in root history).
  - Nullifier is unused.
  - Verifies transfer proof with `vk_transfer` against the public inputs.
  - Records nullifier and appends output commitments.

### Unshield (Withdraw)

**Goal:** spend a shielded note and release value to a transparent recipient.

- **Client does:**
  - Select spend note with exact amount.
  - Get membership witness, compute nullifier.
  - Generate unshield proof binding the public `(asset_id, amount, recipient)` to the spent note.
  - Submit transaction containing proof and the public withdrawal parameters.
- **Chain checks:**
  - Anchor is valid.
  - Nullifier is unused.
  - Verifies unshield proof with `vk_unshield`.
  - Records nullifier.
  - Transfers SPL tokens out of the pool to the public recipient.

---

## Membership Verification (Merkle Path vs Light Validity Proof)

There are two ways to prove that an input commitment exists in the commitment set:

- **Merkle path (explicit siblings + indices)**
  - Pro: simple conceptually; can be verified locally/off-chain.
  - Con: path is large; and if we were to verify it inside the spend circuit, it increases constraints.
  - Used here for the **mock** backend: `MockChain` verifies `MembershipWitness::MerklePath` locally.

- **Light Protocol validity proof (Groth16)**
  - Pro: constant-size witness; verified on-chain against a Light-backed state root.
  - Con: requires Light infrastructure + verifier.
  - Planned production model: verify `MembershipWitness::LightValidityProof` **on-chain**.

**Decision (reference implementation):** membership is verified **outside** the MASP spend circuits (transfer/unshield).
The transfer/unshield circuits still take `input_commitment` as a **public input** and prove:

- the spender knows the note preimage such that `H(note_fields) == input_commitment`
- the nullifier is derived correctly from ownership key material
- output commitments / balance / binding statements

This ensures the membership proof and spend proof are tied to the *same* leaf.

**Important nuance:** the spend circuits still accept `anchor` as a public input because:

- the *transaction binding* commits to it, so proofs are tied to the intended state snapshot
- it makes it explicit which anchor the external membership proof must be verified against

---

## Balance Enforcement (In-Circuit vs On-Chain Homomorphic Checks)

There are two common patterns to enforce value conservation:

### A) Pure in-circuit balance (recommended baseline)

The spend circuit proves balance directly over private amounts:

- Single-asset: `v_in == v_out + v_change (+ v_fee)`
- Multi-asset: α-tag random linear combination (hides asset types while enforcing conservation)

**Pros:** simplest on-chain logic (verify one proof), minimal extra cryptographic objects.

### B) Value commitments + on-chain group equation (optional optimization)

Each note carries a *value commitment* (e.g. Pedersen-style) `C_v = rG + vH`.
The chain can check:

- `Σ C_in - Σ C_out - C_public == 0` (group addition)

However, this only works safely if the spend circuit also proves:

- each `C_v` is correctly bound to the note’s amount
- amount range proofs (e.g. < 2^64)
- asset-type correctness (single-asset equality or α-tag construction)

**Pros:** can make some balance checks cheaper on-chain (especially with batching).
**Cons:** adds extra objects to the protocol + additional curve ops on-chain, and still requires in-circuit bindings/range proofs.

**Decision guideline:**

- Use **A** as the baseline (fewer moving parts; easiest to audit and implement first).
- Consider **B** later if on-chain compute becomes a bottleneck and we have a clear batching story.

---

## What Makes It Safe (Responsibility Split)

This protocol is safe when these layers *compose* correctly:

- **Circuit (ZK) ensures correctness of *private* statements**
  - “I know the note preimage”
  - “This note is a member of the tree for the given anchor”
  - “The nullifier is derived correctly from ownership key material”
  - “Value is conserved / asset rules hold”
  - “Outputs are well formed”
  - “Unshield binds public withdrawal fields to the note”
- **Chain ensures correctness of *public* state transitions**
  - Nullifier uniqueness (double-spend prevention)
  - Anchor validity (witness freshness policy / root history)
  - Proof verification with the right VK per circuit
  - Token movements (shield/unshield)
- **Client ensures correctness of *note discovery and local state***
  - Ciphertext decrypts to a note whose commitment matches the on-chain commitment
  - Spentness checks before accepting or spending a note

If any layer omits its responsibilities, the system can become unsafe (e.g. theft, inflation, double spends) or unreliable (e.g. fund loss/griefing).

---

## Reference Implementation: What Mocks Must Model

This repo’s mocks are considered correct when they respect the same boundaries:

- `MockChain` must behave like a chain: validate anchors, enforce nullifier uniqueness, and call the verifier.
- `MockIndexer` must behave like an indexer: serve outputs and witnesses, and may model indexing latency.
- `MockSpendProver` / `MockProofVerifier` may short-circuit cryptography, but they must preserve:
  - the public-input wiring per circuit
  - the “right verification key per circuit” semantics
  - failure modes where appropriate (negative tests)

---

## Action Shape (1→3 Today) and Scaling to N→M

Right now we model a single **Action** as:

- **1 input note**
- **up to 3 outputs**: recipient, change, fee

This is a reasonable baseline because it matches how wallets typically construct payments:

- Most payments spend one note and create one recipient output + (optional) change + (optional) fee.

### Do we want more inputs / N→M?

Yes, but we generally get N→M by composing multiple fixed-size actions rather than making the circuit itself fully variable:

- **Multiple actions per transaction** (recommended scaling path):
  - A transaction carries `K` actions (each action has its own spend proof + nullifier + outputs).
  - This gives you **N inputs and M outputs** overall without needing dynamic circuit sizes.

### Can it be an array / flexible?

In Noir, array sizes are compile-time constants. So “fully variable N and M” isn’t a great fit directly inside one circuit.
Two common production patterns are:

- **Fixed max with padding**: choose `MAX_INPUTS`, `MAX_OUTPUTS`, pad unused slots with zeros and add constraints to treat them as inactive.
- **Composable actions**: keep a small “action circuit” and repeat it per action; later consider aggregation if needed.

**Decision (for now):** keep the **single-action circuit** (1→3 outputs) and scale to N→M via **multiple actions** in the transaction format.

### Joining notes (multi-input)

Wallets sometimes need to **merge notes** (e.g. spend 2 notes to pay 1 amount). There are two common design options:

- **Multiple actions per transaction** (Orchard-style): each action is 1 input → 1 output, repeated `K` times.
  - Great for batching independent spends.
  - Does **not** directly enable “merge 2 inputs into 1 output” within the same transaction unless you introduce chaining.

- **Multi-input spend circuit (fixed max with padding)**: choose `MAX_INPUTS` and represent unused inputs as dummy notes.
  - This directly supports “join notes” in one proof.
  - Costs more constraints and increases public input surface.

**Decision (next milestone):** implement a **multi-input transfer** as a fixed-max circuit with padding (start with `MAX_INPUTS=2`)
so we can support joining notes, while keeping the single-input action as the simplest baseline.
