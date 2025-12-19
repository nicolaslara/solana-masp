# MASP Protocol Soundness & Privacy (Authoritative Spec)

This is the **primary normative protocol document** for this repository.

It defines:

- The MASP **state model** (commitments + nullifiers)
- The **public vs private** data layout and privacy expectations
- The **required checks** for each operation (Shield / Transfer / Unshield)
- The division of responsibility across **Client / Chain / Indexer / Circuits**
- How Light Protocol proofs compose with MASP proofs (anchors/roots + batching)

Related docs:

- `docs/circuit-security-requirements.md` (detailed circuit statement checklist)
- `docs/protocol.md` (high-level overview; should not contradict this document)
- `client/tests/user_flows.rs` (wallet flows that the protocol must support)

---

## Threat model and assumptions

### Cryptographic assumptions

- Poseidon/Poseidon2 is collision resistant for our domain-separated uses.
- The proving system is sound: false statements cannot be proven except with negligible probability.
- Output encryption is AEAD-secure (confidentiality + integrity).

### System assumptions

- The chain enforces consensus rules for state transitions and rejects invalid transactions.
- Indexers are **observers** of ledger data (not authoritative), and may be adversarial.
- Wallets must validate decrypted data before treating it as spendable.

---

## Core invariants (soundness)

The protocol is sound if the following are guaranteed:

- **No inflation**: shielded value cannot be created from nothing.
- **No double-spend**: each note can be spent at most once.
- **No unauthorized spend**: only the intended recipient (SpendingKey holder) can spend.
- **Correct boundary accounting**:
  - Shield: pool credits correspond to actual token deposits.
  - Unshield: pool debits correspond to actual token withdrawals.

---

## State model (commitment tree + nullifier set)

### Commitment set (notes)

- Each shielded note corresponds to a **commitment** \(cm\).
- Commitments are stored in an **append-only commitment Merkle tree** (an accumulator) maintained by the MASP program.
- The program publishes / stores a rolling set of recent **anchors** (tree roots) that can be used as spend contexts.

**Important privacy constraint:** spends must **not** require referencing the specific commitment object/leaf on-chain (e.g., as a content-addressed account keyed by the commitment). Otherwise observers can link spends/unshields back to the original shield path by following explicit commitment references, breaking the shielded-pool unlinkability goal.

### Nullifier set (spentness)

- Each spent note reveals a **nullifier** \(nf\).
- Nullifiers are stored in a set that enforces **insert-once** semantics (e.g., a Light address tree in production, or another deterministic set structure).
- Spending a note inserts its nullifier; duplicates are rejected.

---

## Public vs private data

### Public (on-chain / in transaction data)

- Output commitments created (by hash / commitment)
- Nullifier(s) revealed
- Anchor (commitment tree root / root context) used for membership
- Encrypted **output** ciphertext payloads (see “Ciphertexts: DA and binding” for how these are published)
- Shield boundary: token mint/address and amount
- Unshield boundary: token mint/address, amount, and public recipient

### Private (witness/proof)

- Note plaintext fields (asset_id, amount, recipient/address, nullifier_nonce, note_randomness, …)
- SpendingKey-derived secrets (authorization material)
- Output note plaintexts
- Any randomness used for commitments, encryption, and proof binding

---

## Ciphertexts: data availability (DA) and binding to proofs

Ciphertexts are required for **outputs only** (note discovery). They are **not** required for inputs.

**Normative rule (privacy):** the protocol must **never** publish or store ciphertexts for inputs/spends.
Doing so is redundant (spends are already validated by proof + nullifiers) and can create avoidable
linkability surface (e.g., any stable “input ciphertext reference” risks re-introducing a commitment↔spend trail).

### Why outputs need ciphertexts, and inputs do not

- **Outputs**: wallets discover received notes by scanning ciphertexts and attempting trial decryption; once decrypted,
  the wallet must verify the plaintext is consistent with the corresponding public commitment.
- **Inputs**: spends are validated by:
  - revealed nullifier(s) (spentness/double-spend prevention), and
  - a proof that binds to the input commitment preimage + membership under an anchor.
  No input ciphertext is needed for soundness or wallet recovery, and publishing input ciphertexts is actively discouraged.

### Two distinct “match the proof” properties

We distinguish:

1. **Binding (integrity / anti-swap):** the published ciphertext bytes correspond to the output notes proven in the
   MASP state transition (“Tx B” below).
2. **Decryptability (recipient success):** the receiver can decrypt and recover the note plaintext needed to spend.

**Important (Zcash-style model):** unless we put key agreement + encryption correctness *inside the circuit*, third parties
cannot validate decryptability. Ciphertext correctness is not consensus-critical; malformed ciphertext can “burn” funds
(griefing). Wallets must treat decryptability as a receive-side correctness/UX property, not a consensus guarantee.

### DA + binding under Solana constraints (normative baseline)

Solana programs cannot introspect other transactions’ instruction data at execution time, and the transaction envelope is
tight. Therefore the baseline protocol uses a **two-step publish + state transition** design:

- **Tx A (ciphertext posting tx(s))**: publish ciphertext bytes for outputs (possibly chunked across multiple txs).
  - This provides **ledger-history DA** (archive-retrievable bytes) without permanent state growth.
- **Tx B (MASP state transition tx)**: includes proof + nullifiers + commitments and binds to the ciphertext bytes via hashes.

This is the **baseline** because it works under current Solana limits and avoids permanent ciphertext accounts.

### Binding construction: Option 1A (weak binding, recommended baseline)

For each output `j`, Tx B includes (directly as public inputs, or indirectly inside `tx_binding`) a ciphertext hash:

```text
ct_hash[j] = H(DOM_CIPHERTEXT, ciphertext_bytes[j])
```

**What is enforced by the proof vs the wallet (1A):**

- **Proof / circuit / verification MUST enforce binding:** the proof verification for Tx B MUST bind to the exact
  `ct_hash[j]` values for the enabled output slots (either because `ct_hash` are explicit public inputs, or because they
  are included in a `tx_binding` value that the circuit recomputes).
- **Wallet MUST enforce decryptability + acceptance rules:** the wallet computes `H(DOM_CIPHERTEXT, ciphertext_bytes)` over
  the fetched bytes and checks it equals the bound `ct_hash`, then attempts decryption and validates plaintext↔commitment.
  Decryptability is **not** consensus-critical in 1A.

Wallet/indexer verification rule:

1. Fetch ciphertext bytes `C[j]` from Tx A (or redundancy backends).
2. Compute `ct_hash[j] = H(DOM_CIPHERTEXT, C[j])`.
3. Verify `ct_hash[j]` matches what Tx B bound to for output `j`.
4. Attempt decryption (receiver-only); on success, verify plaintext↔commitment consistency (`H(note_plaintext)==cm[j]`).

Failure handling:

- If `ct_hash` matches but decryption fails: treat as sender griefing/burn (ciphertext not consensus-critical).
- If ciphertext bytes are missing: treat as DA failure; try redundancy; otherwise the output is not discoverable.

### Operational accelerators

- **Bundling** (e.g., Jito bundles) can make “Tx A(s) + Tx B” land atomically in practice on some leaders, improving UX.
  This is not a consensus primitive; the protocol must remain correct without it.
- **Off-chain redundancy** (mirrors/IPFS/etc.) can improve availability, but must be “best-effort” and never the only DA story.

### Future hardening: Option 1B “verifiable encryption”

A future hardening milestone may move from “weak binding” to “decryptability binding” by having the circuit enforce that
`ct_hash` is derived from correct encryption of the output plaintext to the receiver key. This is optional and gated by
measured circuit cost and cryptographic review.

Design space and detailed discussion:

- `docs/design-decisions/ciphertext-da-and-binding.md`

---

## What each party learns (privacy model)

This section describes the intended privacy properties of the protocol and what information is necessarily revealed.

| Party | Learns | Must not learn (except via metadata correlations) |
|---|---|---|
| **Chain / observers** | commitments, nullifiers, anchor/root context, ciphertext blobs, unshield public boundary fields, shield boundary fields | note plaintexts (amounts/recipients/assets inside pool), mapping from ciphertext→recipient |
| **Indexer** | same public ledger data; can see what ciphertexts a wallet fetches/scans; can see which membership/non-membership items the wallet requests proofs for | which ciphertexts decrypt successfully; note plaintexts |
| **Wallet** | its decrypted notes; its own secrets; public ledger data needed for validity | other users’ plaintexts |

Privacy caveats (protocol-level):

- Witness/proof requests can leak intent. This is mitigated by PIR/decoys, metadata hiding, or self-hosted indexers.

---

## Core objects and derivations

### Note plaintext (current)

- `asset_id: Field`
- `amount: u64`
- `recipient: Field` (current; see Spend Authorization section for required binding)
- `diversifier_index: u64` (committed; must match the diversifier used for encryption/decryption)
- `nullifier_nonce: Field`
- `note_randomness: Field`

### Nullifier nonce (`nullifier_nonce`)

`nullifier_nonce` is part of the note plaintext and is later used to derive the note’s nullifier when the note is spent.

This protocol uses two rules depending on how the note is created:

- **Shield-created notes (deposit)**: `nullifier_nonce` is **sampled randomly** by the note creator (the depositor wallet) using a CSPRNG.
  - We cannot “prove randomness” in-circuit; instead we rely on correct wallet RNG.
  - Collisions are assumed negligible; `note_randomness` also ensures commitment uniqueness even for identical notes.
- **Spend-created output notes (transfer/unshield outputs)**: `nullifier_nonce` is **deterministically derived** by the spending wallet:

\[
out\_i.nullifier\_nonce = H(DOM\_NULLIFIER\_NONCE, input\_commitment, output\_index)
\]

The spend circuit MUST enforce this derivation for outputs so the spender cannot choose adversarial nonces.

### Commitment

\[
cm = H(DOM\_NOTE\_COMMIT, asset\_id, amount, recipient, diversifier\_index, nullifier\_nonce, note\_randomness)
\]

### Nullifier

The nullifier must be derivable **only** by the spender (SpendingKey holder) for notes addressed to them, and must be bound to the note:

\[
nf = H(DOM\_NULLIFIER, \text{spend\_auth\_material}, nullifier\_nonce)
\]

**Important:** `spend_auth_material` MUST NOT be computable from a watch-only viewing key.

---

## Spend authorization (no explicit signature; ZK-native ownership)

We do **not** rely on an external signature verified by consensus. Instead, the **MASP spend proof** must prove:

1. **Preimage knowledge**: the prover knows a note plaintext that hashes to the input commitment.
2. **Ownership binding**: the note’s recipient/address is bound to SpendingKey-derived secret(s), and the prover knows those secret(s).
3. **Nullifier correctness**: the revealed nullifier is correctly derived from that SpendingKey-derived secret(s) and the note nonce.

This is what makes “FullViewingKey can view but cannot spend” true.

### Why “knowledge of some secret” is not enough

If a circuit only checked `nf == H(secret, nullifier_nonce)`, any attacker could choose their own `secret` and “authorize” spending.

Therefore, the protocol **requires** that the secret used in nullifier derivation is **the one corresponding to the recipient/address** encoded in the note.

### Consequence for note/address format

The note must carry enough address information for the circuit to prove that binding (not merely “an x-coordinate” that cannot be validated).

---

## Anchors / roots (commitment tree)

An “anchor” is the **root** of the commitment set against which membership is being proven.

The chain must maintain a set of recent valid anchors (roots) for the commitment tree.

### Does the MASP spend circuit need `anchor` as a public input?

Yes (directly or indirectly). The protocol requires that a spend proof is bound to a specific commitment-tree root context. There are two acceptable designs:

- **Explicit root binding**: include `anchor_root` as a public input to the MASP spend circuit.
- **Implicit root binding**: include `anchor_root` inside a transaction binding hash that the MASP circuit checks.

Either way, “anchors” remain a protocol-level concept: they are the binding point that prevents replay/mix-and-match across different commitment-set states.

---

## Light proof types (avoid terminology confusion)

If Light is used (e.g., for the nullifier set), it exposes more than one “proof-like” artifact:

- **Per-item proof material** (Merkle path / root context) can be fetched in batch, e.g. via
  [`getMultipleCompressedAccountProofs`](https://www.helius.dev/docs/api-reference/zk-compression/getmultiplecompressedaccountproofs).

- A single **Validity Proof** (Groth16) can cover multiple inputs/outputs in one proof (Light API calls this `getValidityProof`):
  [`getValidityProof`](https://www.helius.dev/docs/api-reference/zk-compression/getvalidityproof).

On-chain, the intended Light flow is: verify a **single validity proof** that covers the batch, rather than verifying many Merkle paths individually.

This section does **not** apply to the commitment tree membership model described above (which uses Merkle paths inside the MASP circuit + anchor validity on-chain), only to nullifiers.

---

## Operations and required checks

### Shield (deposit)

**Goal**: deposit transparent tokens and append a new commitment (note) into the MASP commitment tree.

#### Required checks (Shield)

- **(S1) Transparent boundary correctness (chain)**:
  - `(token_address, amount)` is actually transferred into the pool.
- **(S2) Commitment integrity (circuit and wallet integrity)**:
  - `cm == H(DOM_NOTE_COMMIT, asset_id, amount, recipient, nullifier_nonce, note_randomness)`.
- **(S3) Asset binding (circuit + chain)**:
  - `asset_id` corresponds to `token_address` used in the transparent transfer.
- **(S4) Amount range (circuit, via type system)**:
  - `amount < 2^64`.
  - In Noir circuits, this is enforced automatically by using `u64` types for all amount parameters.
- **(S5) Output ciphertext hash binding (proof-level binding; outputs-only)**:
  - If the protocol uses Tx A/Tx B posting (Option 1A), the shield state-transition transaction MUST bind to the output
    ciphertext bytes via `ct_hash = H(DOM_CIPHERTEXT, ciphertext_bytes)` (as an explicit public input or via an intent hash
    the circuit checks).
  - The circuit does **not** prove decryptability in 1A; it only binds the intended ciphertext hash value(s).

#### Responsibility split (Shield)

- **Circuit must prove**: (S2), (S3), (S4)
- **Chain must enforce**: (S1) and append `cm` into the commitment tree (and publish/update the current root)
- **Wallet must enforce**: ciphertext integrity and (if using scanning) plaintext↔commitment consistency before accepting notes

### Transfer (shielded → shielded) — single proof, flexible inputs/outputs

**Goal**: prove valid spends of one or more existing commitments, create new output commitments, and insert nullifiers — all in a single proof.

#### Transaction shape (N inputs → M outputs)

There is only **one** transfer type in this protocol: a single proof that supports flexible **N inputs → M outputs** within fixed compile-time maxima.

- **`MAX_INPUTS = 3`** (recommended for main transfer)
- **`MAX_OUTPUTS = 3`** (payment + change + fee)

The circuit accepts **exactly** `MAX_INPUTS` input slots and `MAX_OUTPUTS` output slots, with boolean `enabled` flags marking the active subset. Disabled slots are padded with zeros and do not affect balances or validity.

**Public inputs (canonical layout):**

1. `anchor_root : Field` — shared anchor for all inputs
2. `nullifiers[MAX_INPUTS] : [Field; MAX_INPUTS]` — padded with 0 for disabled inputs
3. `output_commitments[MAX_OUTPUTS] : [Field; MAX_OUTPUTS]` — padded with 0 for disabled outputs
4. `input_count : u32` (encoded as Field)
5. `output_count : u32` (encoded as Field)
6. `tx_binding : Field`

The proof MUST bind to the exact ordering of nullifiers and commitments. Reordering MUST invalidate the proof.

**Ciphertext hashes (outputs-only, Option 1A baseline):**

If ciphertexts are posted out-of-band via Tx A, then Tx B MUST also bind to the per-output ciphertext hash values
`ct_hashes[MAX_OUTPUTS]` for enabled output slots. This can be done by:

- adding `ct_hashes` as explicit public inputs (verification binds them “for free”), or
- including `ct_hashes` inside `tx_binding` and having the circuit recompute `tx_binding` accordingly.

**Output semantics (recommended wallet layout):**

- Output 0: **payment** to recipient
- Output 1: **change** back to sender (disabled if no change)
- Output 2: **fee note** to relayer/operator (disabled if no fee)

#### Required checks (Transfer)

- **(T1) Membership (MASP circuit + chain anchor validity)**:
  - For each **enabled** input `i`, the prover supplies a Merkle path witness and the circuit checks membership under the shared `anchor_root`.
  - The chain checks that `anchor_root` is a valid recent root for the commitment tree.
- **(T2) Spend authorization / ownership (MASP circuit)**:
  - For each **enabled** input `i`, only the SpendingKey holder for that note's recipient/address can produce a valid spend proof.
- **(T2b) Transaction binding hash (MASP circuit)**:
  - `tx_binding` is a public input computed as:

    ```text
    tx_binding = H(DOM_TX_BINDING, anchor_root, input_count, output_count, h_nf)
    ```

    where `h_nf = H(nullifiers[0..MAX_INPUTS])`.
  - Output commitments are already explicit public inputs and are therefore already bound by proof verification; we intentionally do not include them in `tx_binding` so output nonces can be derived from `tx_binding` without circular dependency.
- **(T2c) Output ciphertext hash binding (proof-level binding; outputs-only)**:
  - For each **enabled** output `j`, Tx B MUST bind to `ct_hash[j] = H(DOM_CIPHERTEXT, ciphertext_bytes[j])` (either as an
    explicit public input or by inclusion in `tx_binding` that the circuit checks).
  - For **disabled** outputs, the corresponding `ct_hash[j]` MUST be zero (or another fixed padding rule), to avoid
    “hidden” ciphertexts in unused slots.
  - This is an **integrity/anti-swap** binding. Decryptability is not proven in 1A.
- **(T3) Input preimage knowledge (MASP circuit)**:
  - For each **enabled** input `i`: `input_commitment_i == H(note_fields_i...)`.
- **(T4) Nullifier correctness (MASP circuit)**:
  - For each **enabled** input `i`: `nullifier_i == H(DOM_NULLIFIER, spend_auth_material_i, note_nullifier_nonce_i)`.
  - For **disabled** inputs: `public_nullifiers[i] == 0`.
- **(T5) Output well-formedness (MASP circuit)**:
  - For each **enabled** output `j`: `output_commitment_j == H(output_note_plaintext_j...)`.
  - For **disabled** outputs: `public_output_commitments[j] == 0`.
- **(T6) Output nonce derivation (MASP circuit)**:
  - Output note `nullifier_nonce` values are derived deterministically from `tx_binding`:

    ```text
    out_j.nullifier_nonce = H(DOM_NULLIFIER_NONCE, tx_binding, j)
    ```

  - This is REQUIRED because there may be multiple inputs.
- **(T7) Value conservation + asset rules (MASP circuit)**:
  - **Current semantics (hard-sound): single-asset per transfer.**
  - All **enabled** inputs and outputs MUST share the same `asset_id`.
  - Value conservation is enforced as an **integer equality**:

    ```text
    Σ(enabled_input_amounts) == Σ(enabled_output_amounts)
    ```

  - Multi-asset-in-one-transfer is intentionally deferred to a later milestone (see `tasks.md` Milestone 5).
- **(T7b) Count correctness + slot gating (MASP circuit)**:
  - `1 ≤ input_count ≤ MAX_INPUTS`
  - `1 ≤ output_count ≤ MAX_OUTPUTS`
  - `input_count == Σ(input_enabled[i])`
  - `output_count == Σ(output_enabled[j])`
  - All per-slot constraints are gated by enable flags.
- **(T8) Nullifier uniqueness (chain, Light address tree)**:
  - Inserting each non-zero nullifier succeeds exactly once.
- **(T9) Root/anchor binding (composition)**:
  - All enabled inputs prove membership against the same `anchor_root` (shared anchor).

#### Responsibility split (Transfer)

- **Chain must enforce**:
  - Anchor validity for `anchor_root`
  - Nullifier insert-once semantics for all non-zero nullifiers
  - Append/record all non-zero output commitments
  - Verify the proof against the canonical public input layout
- **Circuit must prove**:
  - Membership for each enabled input under `anchor_root`
  - Correct binding to authoritative commitment data for each input
  - Ownership authorization + correct nullifier derivation
  - Output commitment correctness + deterministic output nonces
  - Integer value conservation (single-asset)
  - Correct gating/counts and zero-padding constraints
  - Correct `tx_binding` computation
- **Wallet must enforce**:
  - Output ciphertext integrity + plaintext↔commitment consistency
  - Coin selection strategy (prefer fewer inputs; use consolidation circuit for many inputs)

#### Why this is sufficient (Transfer)

- (T1)+(T3) ensure each spend refers to a real note in the committed set (no "phantom notes").
- (T2)+(T4) ensure only the intended owner can derive the correct nullifier and satisfy the authorization constraints.
- (T8) prevents replay/double-spend even if an attacker reuses the same proof inputs.
- (T5)+(T7) prevent creating value or malformed outputs.
- (T2b) prevents relayers/indexers from swapping or splicing outputs/nullifiers across transactions.
- (T7b) ensures disabled slots cannot affect soundness.

### Unshield (shielded → transparent)

**Goal**: spend a commitment and withdraw to a public recipient.

#### Required checks (Unshield)

- Same as Transfer for (T1)–(T4) and (T8)–(T9), plus:
- **(U1) Public withdrawal amount/asset binding (MASP circuit)**:
  - the public `(asset_id, amount)` matches the spent note’s plaintext fields.
- **(U2) Public recipient binding (MASP circuit)**:
  - the public `recipient` is bound to the proof intent via the public `tx_binding` and/or explicit public inputs, so it cannot be swapped/malleated by an intermediary.
  - ⚠️ **Recipient encoding rule:**
    - It is **NOT SAFE** to encode a 32-byte recipient (e.g., Solana pubkey) as a single `Field` using `Fr::from_be_bytes_mod_order`.
    - Reason: BN254 scalar field has prime modulus \(p < 2^{254}\), so reduction mod \(p\) is a **many-to-one** mapping from 256-bit strings → field elements; distinct recipients can collide.
    - This creates a malleability/collision class: the proof can be valid for multiple distinct 32-byte recipients that map to the same `Field`.
    - **Instead**, represent the recipient as **4×u64 limbs** (little-endian) as public inputs:
      - `public_recipient_limbs: [u64; 4]`
    - The chain/program MUST recompute these limbs from the actual 32-byte recipient in the instruction data and reject if they do not match.
- **(U3) Transparent withdrawal (chain)**:
  - the chain executes the actual token transfer to the public recipient.

#### Why this is sufficient (Unshield)

- (U1) prevents “withdraw more than the note value” or “withdraw wrong asset”.
- (U2) prevents “swap the recipient address after the user proves” (malleability of withdrawal destination).
- (U3) ensures the transparent boundary is actually applied by consensus.

#### Responsibility split (Unshield)

- **Chain must enforce**:
  - anchor validity for the spent commitment(s) (as in Transfer)
  - Nullifier uniqueness via Light address tree insert-once semantics (as in Transfer)
  - Proof verification of the MASP unshield proof against the correct verification key
  - The actual SPL/token transfer to the public recipient
- **Circuit must prove**:
  - input commitment preimage knowledge
  - SpendingKey-only ownership authorization binding
  - nullifier correctness
  - public withdrawal amount/asset binding matches the spent note
  - public recipient is bound to the proof intent (via the public `tx_binding`)
- **Wallet/indexer must support**:
  - providing ciphertexts and Merkle path witnesses needed to build the MASP proof

---

## Wallet correctness requirements (receive / recover)

These are not “consensus soundness”, but are required for safety and UX:

- **Ciphertext AEAD integrity**: tampered ciphertext must fail to decrypt.
- **Recipient match**: decrypted note must correspond to one of the wallet’s addresses.
- **Diversifier consistency**: encrypted outputs include a public `diversifier_index`, and wallets must enforce it matches the decrypted note plaintext.
- **Ciphertext hash binding (outputs-only)**: when the protocol publishes `ct_hash` for an output, wallets MUST verify `ct_hash == H(DOM_CIPHERTEXT, ciphertext_bytes)` before attempting to accept the output.
- **Commitment binding**: `H(note_plaintext) == output_commitment` before accepting a note.
- **Spentness filtering**: do not treat notes as spendable if their nullifier is already present.

---

## Batching (Light)

### Batched membership proof material (RPC fetch)

For off-chain tooling, you can fetch multiple account proof materials in one call:

- [`getMultipleCompressedAccountProofs`](https://www.helius.dev/docs/api-reference/zk-compression/getmultiplecompressedaccountproofs)

### Batched on-chain validity (single Groth16)

For on-chain verification, the intended batching primitive is the validity proof:

- [`getValidityProof`](https://www.helius.dev/docs/api-reference/zk-compression/getvalidityproof)

This is the mechanism by which one proof can cover multiple checks within Light’s supported batch shapes (e.g., address-tree insert-once / non-membership style checks for the nullifier set).

---

## Enforcement matrix (summary)

This table summarizes which layer is responsible for each class of check in the **normative protocol**:

| Check class | Enforced by | Notes |
|---|---|---|
| Membership of input commitments | MASP circuit + chain anchor validity | Merkle paths are proven in-circuit; chain checks anchor is a valid recent root |
| Nullifier uniqueness | Chain (via Light address tree insert-once) | duplicates must fail deterministically |
| Preimage knowledge and spend authorization | MASP circuit (proof) | ZK-native; must exclude watch-only spending |
| Output well-formedness and value conservation | MASP circuit (proof) | includes range checks |
| Token transfers at boundary | Chain (SPL programs) | required for shield/unshield soundness |
| Ciphertext↔commitment acceptance | Wallet | wallet must not accept malformed notes |

## Implementation status (reference implementation)

This section tracks deviations between the current code and the normative protocol above.

- **Commitment set**: reference implementation uses an in-memory Merkle tree. Production design is an on-chain commitment accumulator (append-only tree with anchor history), not a content-addressed Light state tree.
- **Nullifier set**: reference implementation uses an in-memory set; production target may use Light (address tree insert-once) or another bounded on-chain structure.
- **Spend authorization**: enforced by the reference prover semantics; real circuits must implement equivalent constraints.
- **Transaction binding hash**: enforced by the reference prover semantics with a concrete layout; may be extended to include ciphertext hashes / additional intent fields.

### Mock implementation mapping (S1–U3)

This subsection maps each required check to its current enforcement location in the mock reference implementation.
If something is “NOT IMPLEMENTED”, it is a required protocol check that the mock currently does not model.

#### Shield (S1–S4)

- **(S1) Transparent boundary correctness (chain)**: **NOT IMPLEMENTED** in mocks (no SPL transfers yet).
- **(S2) Commitment integrity**:
  - `client/src/proofs.rs`: `MockSpendProver` for `ProofPublicInputs::Shield` checks `Note::commitment() == new_commitment`.
  - `client/src/mock.rs`: `MockChain::shield()` verifies the (mock) proof via `ProofVerifier`.
- **(S3) Asset binding**:
  - `client/src/mock.rs`: `MockChain::shield()` computes `public_asset_id = compute_asset_id(token_address)` for the proof public inputs.
  - `client/src/proofs.rs`: `MockSpendProver` checks `pi.public_asset_id == private_inputs.note_asset_id`.
- **(S4) Amount range**:
  - Enforced by Noir's `u64` type system in real circuits: all amount parameters (`public_amount`, `note_amount`, output values) are typed as `u64`, which automatically generates range constraints.
  - In Rust mocks, amounts are already `u64`, so no explicit check is needed.

#### Transfer (T1–T9) — single transfer (N inputs → M outputs)

- **(T1) Membership**:
  - `client/src/mock.rs`: `MockChain::transfer()` checks `is_valid_anchor(anchor)`.
  - `client/src/proofs.rs`: `mock_check_transfer()` iterates over enabled inputs and verifies each Merkle path against the shared `anchor`.
- **(T2) Spend authorization / ownership (SpendingKey-only)**:
  - `client/src/proofs.rs`: `mock_check_spend_authorization()` enforces that the prover knows `spending_key` such that:
    - `fvk(spending_key).nk_field == private.nk`, and
    - `fvk(spending_key).diversified_address(note_diversifier_index).to_field == private.note_recipient`
  - Authorization is checked for each enabled input note.
- **(T2b) Transaction binding hash (anti-malleability / intent binding)**:
  - `client/src/tx_binding.rs`: defines `tx_binding_transfer(...)` (binding for the single transfer type).
  - `client/src/proofs.rs`: `mock_check_transfer()` enforces `public.tx_binding == tx_binding_transfer(...)`.
  - The binding includes a hash of the full padded nullifier array plus counts.
- **(T3) Input preimage knowledge**:
  - `client/src/proofs.rs`: `mock_check_transfer()` recomputes each enabled input commitment from note fields.
- **(T4) Nullifier correctness**:
  - `client/src/proofs.rs`: For each enabled input, checks `compute_nullifier(nk, note_nullifier_nonce) == public.nullifiers[i]`.
  - For disabled inputs, checks `public.nullifiers[i] == 0`.
- **(T5) Output well-formedness**:
  - `client/src/proofs.rs`: For each enabled output, checks `note.commitment() == public.output_commitments[j]`.
  - For disabled outputs, checks `public.output_commitments[j] == 0`.
- **(T6) Output nonce derivation**:
  - `client/src/proofs.rs`: checks `out_j.nullifier_nonce == H(DOM_NULLIFIER_NONCE, tx_binding, j)`.
- **(T7) Value conservation + asset rules**:
  - `client/src/proofs.rs`: `mock_check_transfer()` enforces single-asset semantics:
    - All enabled inputs/outputs must have the same `asset_id`.
    - Value conservation: `Σ(enabled_input.amount) == Σ(enabled_output.amount)` (checked in integers).
- **(T7b) Count correctness + slot gating**:
  - `client/src/proofs.rs`: Validates `input_count` and `output_count` match the number of enabled slots.
  - Constraints are gated by enable flags.
- **(T8) Nullifier uniqueness**:
  - `client/src/mock.rs`: `MockChain::insert_nullifier()` rejects duplicates for each non-zero nullifier.
- **(T9) Root/anchor binding (composition)**:
  - All enabled inputs prove membership against the same shared `anchor`.

#### Unshield (U1–U3)

- **(U1) Public withdrawal amount/asset binding**:
  - `client/src/proofs.rs`: `mock_check_unshield()` enforces `public_amount == note_amount` and `public_asset_id == note_asset_id`.
- **(U2) Public recipient binding**: implemented in mocks (and is the standard ZK meaning of public inputs).
  - `client/src/proofs.rs`: `MockProofVerifier` binds proof bytes to **all** public inputs, including `public_recipient`.
  - `client/src/proofs.rs`: `mock_check_unshield()` also enforces `tx_binding == H(DOM_TX_BINDING, ...)` (current layout).
    - This is a minimal, concrete intent-binding layout over the fields we already have today; future iterations can extend it to cover ciphertext hashes / additional intent fields.
- **(U3) Transparent withdrawal (chain)**: **NOT IMPLEMENTED** in mocks (no SPL transfers yet).
