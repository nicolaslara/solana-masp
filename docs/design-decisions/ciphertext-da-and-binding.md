Below is a **drop-in replacement** for the design-decision doc, updated for **Jito bundling**, “possible future tx-size increases”, **off-chain redundancy**, and a more realistic **Candidate 2 (1B) feasibility/cost/safety** appendix.

---

# Ciphertext Data Availability (DA) & Binding to Proofs (Solana MASP)

**Status:** Proposed → **Recommended** (see “Decision”)
**Last updated:** 2025-12-19
**Owner:** MASP team
**Scope:** Design decision (non-normative). Soundness/privacy remains governed by `docs/protocol-soundness.md`.

## 1. Problem statement

We must publish **output note ciphertexts** so wallets can discover received notes and later spend them.

We want ciphertexts to be:

* **Discoverable:** wallets can find outputs during sync.
* **Durable (DA):** retrievable from Solana history / standard RPC that proxies archive nodes.
* **Integrity-protected:** wallets can verify fetched bytes are the intended bytes.
* **Bound to the transfer intent / proof:** ciphertexts can’t be swapped without detection.

### 1.1 Two distinct “match the proof” properties

1. **Binding (integrity / anti-swap):** the published ciphertext bytes correspond to the output notes proven in Tx B.
2. **Decryptability (recipient success):** the receiver can decrypt and recover the note plaintext needed to spend.

**Important:** without putting key agreement + encryption correctness *inside the circuit*, **third parties can’t validate decryptability**. This is the Zcash Sapling/Orchard model: ciphertext correctness is not consensus-critical; malformed ciphertext can “burn” funds (griefing).

## 2. What needs ciphertexts?

* **Outputs need ciphertexts** (note discovery).
* **Inputs do not**: spends rely on nullifiers + proof (+ root/anchor context), not input ciphertexts.

## 3. Solana constraints (current reality)

* **Transaction size limit:** transactions are still limited to **1232 bytes total** (signatures + message + instruction data). v0 + ALTs reduce account-key overhead but **do not remove** the 1232-byte envelope limit. ([Solana][1])
* **Potential size increases:** Solana has discussed/testing “transaction size increase” since QUIC, but it’s **not a guaranteed near-term invariant**; we should not design a production privacy protocol that depends on it. ([Solana][2])
* **Jito bundles:** bundles can execute up to **5 transactions sequentially and atomically (all-or-nothing)** on Jito-enabled validators. This improves multi-tx liveness/UX but is **not a consensus primitive** (non-Jito leaders don’t provide this behavior). ([Jito Labs Documentation][3])
* **Accounts as storage:** accounts are durable *current state*, but:

  * storing ciphertexts permanently implies **rent/state growth**,
  * “store then close” makes data **not reliably retrievable via standard history APIs** (provider-dependent whether closed data is served).

## 4. Design space (options)

### Option 0 — Inline ciphertexts in the MASP state transition (single tx)

**What:** put ciphertext bytes directly into the transfer/shield instruction.

**Pros**

* Best “ledger DA” story (history fetch).
* Simplest wallet/indexer model.
* No rent/state growth.

**Cons**

* **Usually infeasible** for standard flows (e.g., 1-in/3-out with ~400–600B per ciphertext).
* Proof + accounts + metadata competes for the same 1232B envelope.

**Binding**

* Strong, “by construction” (ciphertext bytes are in the same tx).

**Verdict:** **Not viable** beyond toy/minimal outputs.

---

### Option 1 — “Ciphertext posting tx(s)” + hash binding in the MASP tx (ledger DA, no rent)

**What:** split into:

* **Tx A:** publish ciphertext bytes (one or more transactions, chunked).
* **Tx B:** MASP state transition (proof + nullifiers + commitments) that **binds** to those bytes via `ct_hash`.

**Pros**

* Ciphertexts live in **ledger history** (archive-retrievable).
* Removes ciphertext bytes from the tight budget of Tx B.
* No permanent state growth.

**Cons**

* Multi-tx UX: both must land.
* Programs **cannot read another tx’s calldata**, so binding is enforced by **wallet/indexer rules**, not by consensus (unless we add a temporary account bridge; see Option 2).

#### Option 1A — Weak binding (recommended baseline)

**Tx B contains:** `ct_hash = H(ciphertext_bytes)` (per output or aggregated root).

* **Guarantees:** anti-swap / integrity (wallet can verify bytes match what Tx B committed to).
* **Does not prevent:** sender committing to garbage ciphertext (still Zcash-style griefing/burn).

#### Option 1B — Strong binding (“verifiable encryption”) (future hardening)

**Tx B proof enforces:** `ct_hash` is derived from **correct encryption** of the output plaintext to the receiver key.

* **Guarantees:** if bytes match `ct_hash`, ciphertext is **decryptable** (assuming crypto is correct).
* **Still can’t enforce on-chain:** that Tx A exists unless we add an execution-time bridge (Option 2) or rely on bundling for atomic landing.

**Verdict:** Option 1A is the production baseline; 1B is optional hardening if/when costs + crypto choices are acceptable.

---

### Option 2 — Temporary “ciphertext buffer” account (PDA) + consume/close (execution-time linkage)

**What:** use a PDA/account as a bridge so Tx B can read bytes (because programs can read accounts, not prior tx calldata).

Two common shapes:

**2A. Buffer-only (wallet binding)**

* Tx A writes ciphertext bytes into a PDA and includes `ct_hash` in Tx B.
* Tx B *does not* re-hash (too expensive unless using SHA/Keccak syscalls + matching circuit hash).
* PDA is closed after.

This mostly helps **data transport**, not integrity, unless Tx B verifies the hash.

**2B. Consensus-level anti-swap (requires hash alignment)**

* Tx B reads ciphertext bytes from PDA, computes `H` on-chain, and checks it equals `ct_hash` provided.
* To make this feasible on Solana, `H` must be **SHA256/Keccak** (syscalls), and the circuit must also bind using the same hash function (or a hash-to-hash bridge).

**Pros**

* Gives Tx B something it can actually validate (accounts).
* With **Jito bundling**, (Tx A write) + (Tx B consume/close) can be atomic in practice for Jito leaders. ([Jito Labs Documentation][3])

**Cons**

* Requires extra accounts in the transaction (tx size pressure; mitigated by ALTs).
* Requires temporary rent-exempt lamports (returned on close, but still operational friction).
* If you want consensus-level hash checks, you likely must standardize on SHA/Keccak for `ct_hash` (or pay to compute Poseidon on-chain, which you probably don’t want).

**Verdict:** good **engineering tool** if you want “Tx B validated that bytes existed at execution time”, but it complicates the system and doesn’t inherently solve decryptability.

---

### Option 3 — Off-chain ciphertext store (IPFS / server / user backups) + on-chain hash

**What:** publish `ct_hash` on-chain; store ciphertext bytes in:

* your own replicated service (with backups),
* IPFS (pinning),
* Arweave, etc.

**Pros**

* Zero Solana size pressure.
* Very flexible (large ciphertexts, multiple outputs).

**Cons**

* DA becomes **operational**, not ledger-native.
* Wallet “sync from chain alone” is no longer true.

**Verdict:** useful as **redundancy**, risky as the only DA.

---

### Option 4 — Permanent on-chain ciphertext accounts

**What:** store ciphertext bytes in long-lived accounts.

**Pros**

* Simple retrieval from state.
* No multi-tx “missing ciphertext tx” failure.

**Cons**

* Permanent state growth + rent burden.
* DoS/bloat pressure (and it’s exactly the wrong direction for a privacy pool on Solana).

**Verdict:** **not recommended**.

---

## 5. Binding + DA requirements (what we can and can’t enforce)

### 5.1 “Tx B can’t read Tx A calldata”

Correct: Solana programs can’t introspect other transactions’ instruction data. So **Option 1A/1B binding is not consensus-enforced**; it’s enforced by **wallet/indexer verification** (and by UX conventions like bundling). The only way for Tx B to verify bytes at execution time is to reference an **account** (Option 2).

### 5.2 What changes with Jito bundling?

Bundling *does not* increase the per-transaction 1232B envelope, but it **does**:

* make multi-tx publish+transfer flows land **atomically in practice** (up to 5 tx), ([Jito Labs Documentation][3])
* reduce “Tx B landed but Tx A didn’t” UX failures (for Jito leaders).

We should treat bundling as an **availability/UX accelerator**, not a security primitive.

### 5.3 What if Solana increases tx size to ~4k?

If Solana later increases the envelope, Option 0 becomes more attractive. But since current canonical docs still state 1232B, we design for today and treat any increase as upside. ([Solana][1])

---

## 6. Privacy: is storing `ct_hash` on-chain safe?

**Short answer:** yes, if `ct_hash` is a hash of **ciphertext bytes** (including nonce/ephemeral key), it is **pseudorandom-looking** to observers.

Important nuance:

* Publishing `ct_hash` *does* create a public linkage between Tx B and whatever ciphertext bytes match it. That linkage is **intended** (it’s how wallets bind bytes ↔ outputs).
* `ct_hash` is **not equivalent** to publishing plaintext or note metadata. It should not reveal the note commitment preimage or the receiver unless your ciphertext format itself leaks structure (don’t do deterministic or low-entropy ciphertexts).

---

## 7. Decision

### 7.1 Implement now: **Option 1A (ledger DA via Tx A) + weak binding via `ct_hash` in Tx B**

**Why**

* Works under the current 1232B limit.
* No permanent state growth.
* Ciphertexts are ledger-historical artifacts (archive retrievable).
* Keeps protocol surface area compatible with future hardening (1B).

**Operational recommendations**

* Support **chunked Tx A** (multiple posts) for large multi-output transfers.
* Prefer **Jito bundling** for atomic landing when available; gracefully degrade when not. ([Jito Labs Documentation][3])
* Add **optional off-chain redundancy** (Option 3) as “best-effort mirrors” (not required for correctness).

### 7.2 Plan (optional hardening): **Option 1B** if/when crypto + cost are acceptable

See Appendix A.

### 7.3 Do not do

* Permanent ciphertext accounts (Option 4).
* Clawback/expiry semantics (explicitly out of scope).

---

## 8. Wallet/indexer verification rules (Option 1A baseline)

For each output `j` in Tx B:

1. Fetch ciphertext bytes `C[j]` from Tx A (or from redundancy backends).
2. Compute `ct_hash[j] = H(DOM_CIPHERTEXT, C[j])`.
3. Verify `ct_hash[j]` matches what Tx B bound to (either as explicit public inputs or inside `tx_binding`).
4. Attempt decryption (receiver-only); on success, verify plaintext ↔ commitment consistency (`cm[j]` matches the plaintext commitment rule).

Failure handling:

* If `ct_hash` matches but decryption fails: treat as sender griefing/burn (baseline assumption).
* If ciphertext missing: treat as DA failure; try redundancy; else the output is not discoverable.

---

# Appendix A — Candidate 2 / Option 1B feasibility, cost model, and crypto safety

This appendix is about **future-proofing**: what it would take to make ciphertext decryptability proof-enforced, and what it likely costs.

## A1. What 1B must prove

Per output `j`, the circuit must bind:

* output plaintext `P[j]` (already witness),
* receiver encryption public key `pk_enc[j]` (from address),
* sender ephemeral secret `esk[j]` (witness),
* sender ephemeral public key `epk[j]` (public, or derivable),
* ciphertext bytes `C[j]` (or a digest thereof),
* and output `ct_hash[j]`.

The circuit enforces that:

* `epk[j] = esk[j] * G` (fixed-base),
* shared secret `ss[j] = esk[j] * pk_enc[j]` (variable-base),
* keys derived via a KDF,
* encryption+auth relation holds, yielding ciphertext/tag and then `ct_hash[j]`.

## A2. What Noir/BN254 can realistically support in-circuit (today)

Noir provides **black box functions** for several crypto primitives, meaning the backend can implement specialized constraints for them (and can fall back to less efficient implementations if not). ([Noir][4])

Relevant for 1B:

* **Embedded curve ops** over the configured field (for BN254: BabyJubJub / Grumpkin), including fixed-base scalar mul and MSM. ([Noir][5])
* **AES128**, **SHA256**, **Blake2s**, **Blake3**, and bitwise **XOR** (plus RANGE). ([Noir][4])

This is the key update versus earlier assumptions: **we are not forced to hand-roll curve gadgets or bit-level AES** if we target a backend that implements these blackboxes efficiently.

## A3. Two viable 1B constructions

### A3.1 “Standard-primitive” construction (recommended *if* we do 1B)

Goal: avoid “custom Poseidon AEAD” while still being circuit-feasible.

One concrete design:

**KEM (in-circuit)**

* Curve: embedded curve (BabyJubJub/Grumpkin as supported). ([Noir][5])
* Prove `epk = fixed_base_scalar_mul(esk)`.
* Prove `ss = scalar_mul(pk_enc, esk)` via `multi_scalar_mul` (N=1) or equivalent.

**KDF (in-circuit)**

* HKDF-SHA256, or KDF based on SHA256/Blake2s/Blake3 blackboxes. ([Noir][4])

**DEM (in-circuit)**

* AES-CTR using AES128 blackbox + XOR (CTR is easy in-circuit if AES is blackboxed). ([Noir][4])
* Integrity via Encrypt-then-MAC using HMAC-SHA256 (built from SHA256 blackbox). ([Noir][4])

This yields a “standard building blocks” scheme (AES + HMAC-SHA256) without requiring AES-GCM/ChaCha20-Poly1305 correctness.

Security notes:

* AES-CTR requires **unique nonce/counter per key**.
* EtM with HMAC-SHA256 is a well-understood path to IND-CCA style guarantees (assuming careful AAD + nonce management).
* This is still “our own AEAD composition”, but it’s composed from conservative primitives (unlike a Poseidon-based bespoke cipher).

### A3.2 “ZK-native” construction (Poseidon2 stream + MAC)

This minimizes circuit cost because it stays field-native, but it is **custom symmetric crypto** and should not ship without serious cryptographic review.

If we ever do this, treat it as a research artifact with an explicit security argument and review—not a casual optimization.

## A4. Cost model (parameterized, because backend/gates matter)

Let:

* `m = #outputs`
* `L = plaintext bytes per output` (after serialization; before padding)
* `B = ceil(L / 16)` AES blocks (CTR)
* `S = byte-length hashed by HMAC` (AAD + ciphertext + metadata, padded to SHA256 blocks)

### A4.1 Incremental circuit work per output (standard-primitive path)

**Curve ops**

* 1× fixed-base scalar mul (`epk`)
* 1× variable-base scalar mul (`ss`)

In Noir, these can be blackbox calls (backend-dependent cost). ([Noir][5])

**KDF**

* HKDF uses 2× HMAC plus expansion; in practice for small key material, expect a small constant number of SHA256 blackbox invocations.

**Encryption**

* AES128 encrypt `B` blocks (for CTR keystream), plus XOR `L` bytes.

**MAC**

* HMAC-SHA256 over `S` bytes: roughly proportional to number of SHA256 compression blocks required.

So the *shape* is:

`ΔCost_per_output ≈ C_ecdh + C_kdf + B*C_aes + L*C_xor + C_hmac(S)`

### A4.2 What this means for proving vs verification costs

* **Proof verification** for common SNARKs is *roughly constant* w.r.t. circuit size; the pain is mostly **proving time/memory** and circuit engineering risk.
* So 1B is primarily a **prover budget** question (and whether we can keep the circuit within an acceptable constraint count).

### A4.3 How we get real numbers (the only honest way)

We should treat any “constraint count” estimate as provisional until we measure it with our exact backend.

Noir provides:

* `nargo info` to view circuit size,
* `--print-acir` to inspect opcodes,
* backend tooling (e.g., barretenberg `bb ... gates`) to see gate count. ([Noir][6])

**Action item for future-proofing:** keep a tiny `circuits/crypto_costs/` harness that compiles:

* 1× and 2× embedded scalar mul,
* AES-CTR over 1, 2, 4 blocks,
* HMAC-SHA256 over representative message sizes,
  and record `nargo info` deltas in this doc whenever Noir/backend versions change.

## A5. The “ct_hash privacy” question under 1B

Storing `ct_hash` remains safe for privacy **as long as**:

* ciphertext includes sufficient randomness (nonce + epk),
* `ct_hash` commits to the full ciphertext/tag (so it looks random),
* we do not encode identifying metadata in clear inside the ciphertext format.

The real privacy risk is not `ct_hash` itself; it’s **any deterministic or structured ciphertext format** that enables cross-output correlation.

---

# Appendix B — Practical recommendation summary (one paragraph)

**Ship now with Option 1A:** ciphertexts in separate Tx A(s) + `ct_hash` binding in Tx B; use **Jito bundles** opportunistically to make publish+transfer atomic when available; add **off-chain mirrors** as redundancy only. Candidate 1B is technically feasible in Noir **if** we align on embedded-curve ECDH and an in-circuit encryption/MAC built from Noir blackboxes, but we should treat it as a future hardening milestone gated by measured `nargo info` budgets and a clear cryptographic review story. ([Noir][5])

---

If you want, I’ll also give you **concrete field/byte layouts** for the “standard-primitive 1B” ciphertext (AAD contents, nonce rules, and exactly what gets hashed into `ct_hash`) so the protocol surface is frozen in a way that keeps 1A → 1B upgradeable without breaking wallet formats.

[1]: https://solana.com/docs/core/transactions?utm_source=chatgpt.com "Transactions"
[2]: https://solana.com/news/solana-network-upgrades?utm_source=chatgpt.com "Solana Network Upgrades"
[3]: https://docs.jito.wtf/lowlatencytxnsend/ "⚡ Low Latency Transaction Send — Jito Labs Documentation - High Performance Solana Infrastructure"
[4]: https://noir-lang.org/docs/noir/standard_library/black_box_fns "Black Box Functions | Noir Documentation"
[5]: https://noir-lang.org/docs/dev/noir/standard_library/cryptographic_primitives/embedded_curve_ops "Scalar multiplication | Noir Documentation"
[6]: https://noir-lang.org/docs/explainers/explainer-writing-noir?utm_source=chatgpt.com "Thinking in Circuits | Noir Documentation"
