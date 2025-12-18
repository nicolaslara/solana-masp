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
- Encrypted output ciphertext payloads (calldata / instruction data)
- Shield boundary: token mint/address and amount
- Unshield boundary: token mint/address, amount, and public recipient

### Private (witness/proof)

- Note plaintext fields (asset_id, amount, recipient/address, nullifier_nonce, note_randomness, …)
- SpendingKey-derived secrets (authorization material)
- Output note plaintexts
- Any randomness used for commitments, encryption, and proof binding

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

### Note plaintext (v0)

- `asset_id: Field`
- `amount: u64`
- `recipient: Field` (v0; see Spend Authorization section for required binding)
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
- **(S4) Amount range (circuit)**:
  - `amount < 2^64`.

#### Responsibility split (Shield)

- **Circuit must prove**: (S2), (S3), (S4)
- **Chain must enforce**: (S1) and append `cm` into the commitment tree (and publish/update the current root)
- **Wallet must enforce**: ciphertext integrity and (if using scanning) plaintext↔commitment consistency before accepting notes

### Transfer (shielded → shielded)

**Goal**: prove a valid spend of an existing commitment, create new commitments, and insert a nullifier.

#### Required checks (Transfer)

- **(T1) Membership (MASP circuit + chain anchor validity)**:
  - the prover supplies a Merkle path witness and the MASP circuit checks that the (private) input commitment is a member under the public `anchor_root`.
  - the chain checks that `anchor_root` is a valid recent root for the commitment tree.
- **(T2) Spend authorization / ownership (MASP circuit)**:
  - only the SpendingKey holder for the note’s recipient/address can produce a valid spend proof (see “Spend authorization” section).
- **(T2b) Transaction binding hash (MASP circuit)**:
  - `tx_binding` is a public input and must equal a well-defined hash of the transaction intent.
  - The current protocol layout used by this repository is defined in `client/src/tx_binding.rs` (`tx_binding_transfer(...)`).
- **(T3) Input preimage knowledge (MASP circuit)**:
  - `input_commitment == H(note_fields...)`.
- **(T4) Nullifier correctness (MASP circuit)**:
  - `nullifier == H(DOM_NULLIFIER, spend_auth_material, note_nullifier_nonce)` with `spend_auth_material` bound to ownership.
- **(T5) Output well-formedness (MASP circuit)**:
  - each output commitment matches its output note plaintext.
- **(T6) Output nonce derivation (MASP circuit)**:
  - output note `nullifier_nonce` values are derived exactly as specified in “Nullifier nonce (`nullifier_nonce`)”.
- **(T7) Value conservation + asset rules (MASP circuit)**:
  - conservation holds (single-asset now; multi-asset via α-tags later).
- **(T8) Nullifier uniqueness (chain, Light address tree)**:
  - inserting the nullifier succeeds exactly once.
- **(T9) Root/anchor binding (composition)**:
  - the MASP spend proof is bound to the same anchor/root context used for membership (explicitly or via a binding hash).

#### Responsibility split (Transfer)

- **Chain must enforce**: anchor validity for (T1), (T8), and verify the MASP proof against its public inputs
- **Circuit must prove**: membership/path validity for (T1), (T2)–(T7) and bind to the same root context as the anchor (T9)
- **Wallet/indexer must support**: providing ciphertexts and membership/non-membership inputs needed to build Merkle path witnesses and MASP proofs

#### Why this is sufficient (Transfer)

- (T1)+(T3) ensure the spend refers to a real note in the committed set (no “phantom notes”).
- (T2)+(T4) ensure only the intended owner can derive the correct nullifier and satisfy the authorization constraints.
- (T8) prevents replay/double-spend even if an attacker reuses the same proof inputs.
- (T5)+(T7) prevent creating value or malformed outputs.

### Unshield (shielded → transparent)

**Goal**: spend a commitment and withdraw to a public recipient.

#### Required checks (Unshield)

- Same as Transfer for (T1)–(T4) and (T8)–(T9), plus:
- **(U1) Public withdrawal amount/asset binding (MASP circuit)**:
  - the public `(asset_id, amount)` matches the spent note’s plaintext fields.
- **(U2) Public recipient binding (MASP circuit)**:
  - the public `recipient` is bound to the proof intent via the public `tx_binding`, so it cannot be swapped/malleated by an intermediary.
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
  - `client/src/proofs.rs`: `mock_assert_amount_is_u64()` is called by `MockSpendProver` for Shield/Transfer/Unshield checks.
    - This is a documented no-op in Rust (amounts are already `u64`), but preserves the fact that **real circuits must enforce range checks** as constraints.

#### Transfer (T1–T9)

- **(T1) Membership**:
  - `client/src/mock.rs`: `MockChain::transfer()` checks:
    - `is_valid_anchor(anchor)`
    - `membership_witness.root() == anchor`
    - `membership_witness.verify_local(input_commitment)`
  - `client/src/proofs.rs`: `mock_check_transfer()` also checks witness root == anchor and verifies Merkle path locally.
- **(T2) Spend authorization / ownership (SpendingKey-only)**:
  - `client/src/proofs.rs`: `mock_check_spend_authorization()` enforces that the prover knows `spending_key` such that:
    - `fvk(spending_key).nk_field == private.nk`, and
    - `fvk(spending_key).diversified_address(note_diversifier_index).to_field == private.note_recipient`
  - `client/src/client.rs`: the client supplies `spending_key` and `note_diversifier_index` (as part of the note plaintext fields) in `SpendPrivateInputs` for spend proofs.
- **(T2b) Transaction binding hash (anti-malleability / intent binding)**:
  - `client/src/tx_binding.rs`: defines `tx_binding_transfer(...)`.
  - `client/src/client.rs`: computes `tx_binding` when building `SpendPublicInputs` for transfers.
  - `client/src/mock.rs`: recomputes `tx_binding` from the request when verifying transfer proofs.
  - `client/src/proofs.rs`: `mock_check_transfer()` enforces `public.tx_binding == H(DOM_TX_BINDING, ...)`.
- **(T3) Input preimage knowledge**:
  - `client/src/proofs.rs`: `mock_check_transfer()` recomputes input note and checks `commitment == public.input_commitment`.
- **(T4) Nullifier correctness**:
  - `client/src/proofs.rs`: `mock_check_transfer()` checks `compute_nullifier(private.nk, note_nullifier_nonce) == public.nullifier`.
- **(T5) Output well-formedness**:
  - `client/src/proofs.rs`: `mock_check_transfer()` checks each output note commitment matches each public output commitment.
- **(T6) Output nonce derivation**:
  - `client/src/proofs.rs`: `mock_check_transfer()` checks `out_i.nullifier_nonce == Note::derive_nullifier_nonce(input_commitment, output_index)`.
- **(T7) Value conservation + asset rules**:
  - `client/src/proofs.rs`: `mock_check_transfer()` enforces single-asset and `sum(outputs.amount) == input.amount`.
- **(T8) Nullifier uniqueness**:
  - `client/src/mock.rs`: `MockChain::insert_nullifier()` rejects duplicates (in-memory set).
- **(T9) Root/anchor binding (composition)**:
  - `client/src/mock.rs`: `MockChain::transfer()` binds witness root to request anchor.
  - `client/src/proofs.rs`: `mock_check_transfer()` binds witness root to public anchor.

#### Unshield (U1–U3)

- **(U1) Public withdrawal amount/asset binding**:
  - `client/src/proofs.rs`: `mock_check_unshield()` enforces `public_amount == note_amount` and `public_asset_id == note_asset_id`.
- **(U2) Public recipient binding**: implemented in mocks (and is the standard ZK meaning of public inputs).
  - `client/src/proofs.rs`: `MockProofVerifier` binds proof bytes to **all** public inputs, including `public_recipient`.
  - `client/src/proofs.rs`: `mock_check_unshield()` also enforces `tx_binding == H(DOM_TX_BINDING, ...)` (v0 layout).
    - This is a minimal, concrete intent-binding layout over the fields we already have today; future iterations can extend it to cover ciphertext hashes / additional intent fields.
- **(U3) Transparent withdrawal (chain)**: **NOT IMPLEMENTED** in mocks (no SPL transfers yet).
