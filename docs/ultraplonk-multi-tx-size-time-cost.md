# UltraPlonk Multi‑TX Model: Size / Time / Cost Analysis

This document analyzes the **size**, **latency (time)**, and **cost** of the multi‑tx model described in `docs/ultraplonk-multi-tx-model.md`.

It is written for production feasibility discussions (not as an exact simulator).

Constraints referenced:

- Solana tx envelope ~**1232 bytes**
- UltraPlonk proof size ~**2144 bytes**
- Current client chunk upload payload size: **900 bytes** (leaving overhead)
- Light non-membership batching limit: **max 2 items per proof**

---

## 0) Variables, formulas, and models compared

This doc compares the following **execution models**:

- **Model U‑1 (UltraPlonk, single apply tx)**: upload proof buffer (chunked) → one “apply” tx that verifies UltraPlonk and applies state changes.
- **Model U‑2 (UltraPlonk, verify/apply split)**: upload proof buffer (chunked) → `Tx V` (verify-only) → `Tx S` (apply-only).
- **Model G‑1 (Groth16, single tx)**: one tx can usually verify MASP proof + apply state changes (no proof-buffer chunking needed).
- **Model G‑2 (Groth16, split only if Light dominates)**: if Light non-membership proof payloads / CU do not fit, you may still need multi-step apply, but MASP verification is no longer the bottleneck.

### Symbols

- \(N\): number of input notes (input nullifiers are enforced at apply time).
- \(M\): number of outputs.
- \(C_{\text{enc}}\): bytes per output ciphertext posted for recipients (today: 244B).
- \(C_{\text{out}}\): bytes per output sender-recovery ciphertext (today: 204B; optional).
- \(P_{\text{masp}}\): MASP proof size in bytes.
  - UltraPlonk: \(P_{\text{masp}}=2144\)
  - Groth16: \(P_{\text{masp}}=192\)
- \(PI_{\text{masp}}\): MASP public input count (each is 32 bytes).
- \(CHUNK\): proof upload payload bytes per tx (today: 900B).
- \(L(N)\): number of Light non-membership proofs required under “max 2 per proof”:

\[
L(N)=\lceil N/2 \rceil
\]

- \(B_{\text{light}}\): bytes per Light non-membership proof payload (implementation-dependent).
- \(CU_{\text{masp}}\): compute units to verify the MASP proof.
- \(CU_{\text{light}}\): compute units to verify+apply one Light non-membership proof (batched up to 2 items).

### Core byte formulas

**Ciphertext posting bytes (Tx A):**

\[
Bytes_{\text{ct}} \approx M \cdot (C_{\text{enc}} + \mathbb{1}_{\text{useCout}}\cdot C_{\text{out}})\quad(+\ \text{small framing})
\]

**MASP proof-buffer payload bytes (Tx P):**

\[
Bytes_{\text{masp\_buffer}} = 32 \cdot PI_{\text{masp}} + P_{\text{masp}}
\]

**# upload tx for MASP proof buffer:**

\[
Tx_{\text{upload}} = \left\lceil \frac{Bytes_{\text{masp\_buffer}}}{CHUNK} \right\rceil
\]

**Light proof payload bytes (apply path):**

\[
Bytes_{\text{light}} \approx L(N)\cdot B_{\text{light}}
\]

### Core CU feasibility bound (single atomic apply tx)

If you try to do MASP verification + Light uniqueness in a single Solana transaction:

\[
CU_{\text{total}} \approx CU_{\text{masp}} + L(N)\cdot CU_{\text{light}} + CU_{\text{overhead}} \le 1.4\text{M}
\]

This is why UltraPlonk (large \(CU_{\text{masp}}\)) tends to push you to a verify/apply split when Light is required.

## 1) Current byte sizes in this repo (baseline facts)

### Ciphertexts (Tx A)

From `client/src/encryption.rs`:

- `C_enc` bytes: **244B** (`ENCRYPTED_NOTE_SIZE`)
- `C_out` bytes: **204B** (`C_OUT_SIZE`, V2)

Current implementation detail to fix for space:

- `ct_hash` is currently computed over a blob that includes `ephemeral_key` twice when `ciphertext_bytes = EncryptedNote::to_bytes()`.
- Removing that duplication saves **~64B per output** in the posted/hashes bytes.

### MASP instruction-data sizes (Tx B today; independent of proof bytes)

From current `client/src/backends/solana.rs` layouts:

- Shield instruction data: **105B**
- Transfer instruction data (MAX_INPUTS=3, MAX_OUTPUTS=3): **361B**
- Unshield instruction data: **169B**

These are *not* the main limiting factor for UltraPlonk. The proof bytes are.

---

## 2) UltraPlonk multi‑tx count and critical path (time)

The multi‑tx model separates:

- proof data availability (buffers) from
- proof verification from
- state transition application

### Proof buffer payload size

The proof buffer must contain:

- `pi_count * 32` bytes of public inputs
- `2144` bytes of UltraPlonk proof

Current PI counts in program logic (today):

- Shield: 4 PIs → 128B
- Transfer: 13 PIs → 416B
- Unshield: 9 PIs → 288B

Total proof-buffer payloads (today):

- Shield: 2272B
- Transfer: 2560B
- Unshield: 2432B

At 900B per upload tx, each requires **3 upload txs**.

### Transaction count per operation (UltraPlonk)

Assuming:

- Tx A ciphertext posting exists (Option 1A), and
- proof bytes use a buffer upload, and
- verification and application are split as `Tx V` and `Tx S`.

Then a single transfer’s rough tx count is:

- Tx A: ciphertext posting (1, possibly more if outputs are large/many)
- Tx P0: create proof buffer account (1)  *(some implementations fold this into init; current CPI verifier flow uses explicit create)*
- Tx P1: init proof buffer (1)
- Tx P2–P4: upload chunks (3)
- Tx V: verify-only (1)
- Tx S: apply-only (1)

Total: **~8 tx** in the critical path for a transfer.

Parallelism:

- Tx A can run in parallel with Tx P* uploads (no dependency).
- Tx V depends on buffer completion; Tx S depends on Tx V and Light proofs.

### Where time comes from

Latency is dominated by:

- number of sequential tx confirmations (round trips)
- proof generation time (off-chain)
- Light proof fetch/generation time (off-chain)

UltraPlonk multi-tx is therefore **round-trip heavy** relative to Groth16.

---

## 3) Light non-membership batching limit and its impact

Under the constraint “non-membership batching max 2”:

\[
\text{non\_membership\_proofs}(N)=\lceil N/2 \rceil
\]

So for N inputs:

- N=3 → 2 non-membership proofs
- N=15 → 8 non-membership proofs

Impacts:

- **Compute**: apply tx must pay for verifying \(\lceil N/2 \rceil\) Light proofs (or CPIs that verify them).
- **Bytes**: apply tx must transport those proof payloads (likely too large to fit inline if N is large).
  - For large N, you likely need **buffering for Light proof payloads** (or accept multiple apply txs, losing atomicity).

Operational implication:

- Under UltraPlonk, large N is difficult because:
  - Tx S is already compute/size constrained, and
  - Light proofs scale as \(\lceil N/2 \rceil\).

This strongly suggests:

- keep “payment transfers” to small input counts (2–3), and
- treat large-input consolidation as a separate path and likely a different proof system (see Groth16 section).

---

## 3.1) Worked examples (N=3 vs N=15)

Using \(L(N)=\lceil N/2 \rceil\):

- **N=3** inputs → \(L(3)=2\) Light non-membership proofs
- **N=15** inputs → \(L(15)=8\) Light non-membership proofs

Two practical consequences:

- **Bytes**: unless \(B_{\text{light}}\) is tiny, carrying \(8 \cdot B_{\text{light}}\) proof payload inline is unlikely to fit under the 1232B envelope → you need buffering or multi-step apply.
- **Compute**: apply-time CU scales linearly with \(L(N)\), so large N quickly becomes Light-dominated even if MASP verification is cheap (Groth16).

---

## 4) Cost model ($): what you pay for

Total cost is a sum of several distinct contributors:

### 4.1 Base fees (signatures per tx)

UltraPlonk multi-tx increases base fees because it uses many txs per operation.

You can reduce base fees by:

- reducing the number of txs (Groth16, or fewer buffers)
- using bundling/atomic scheduling where possible (still multiple txs, but less user-perceived latency)

### 4.2 Priority fees (compute-unit pricing)

Priority fees scale with:

\[
\text{priority fee} \approx CU_{\text{used}} \times \mu\text{lamports/CU}
\]

UltraPlonk pushes compute into the verify tx (Tx V).
Light pushes compute into the apply tx (Tx S), scaling with \(\lceil N/2 \rceil\).

### 4.3 Capital lock / rent (only in PDA nullifier model; local dev simplification)

If nullifiers are stored as PDAs (the repo’s local/dev simplification), you pay an accumulating rent-exempt capital lock:

\[
\text{locked\_lamports} =
\texttt{getMinimumBalanceForRentExemption}(\text{NullifierAccount::SIZE}=41) \times (\#\text{nullifiers})
\]

Light avoids this per-nullifier rent growth (compressed accounts can be lamports=0).

### 4.4 Off-chain service costs (Light / indexers)

With Light, you also pay for:

- proof generation service (Photon/Helius or self-hosting)
- RPC bandwidth / API pricing (provider dependent)

---

## 5) How this changes under Groth16

Groth16 changes the multi-tx cost profile dramatically:

- proof bytes: **192B** (vs 2144B)
- on-chain verification CU: much smaller than UltraPlonk

Consequences:

- you can often remove the proof-buffer upload phase entirely (or make it a single tx in the worst case)
- you can often combine verify+apply into **one tx**, restoring atomicity and cutting round trips

However, Light non-membership “max 2 per proof” can still force multiple proofs for large N.

So for large-input consolidation (e.g., 15→1):

- Groth16 makes MASP verification cheap enough that the remaining constraint is Light’s per-proof limits and payload sizing.
- If Light proof payloads cannot fit, you may still need buffering or multi-step application (non-atomic).

---

## 6) Summary: size / time / cost by model

This is the “at a glance” comparison of the main models. “Tx count” is the **critical path** for a transfer.

| Model | Critical-path txs (transfer) | Size (bytes) hot spots | Time hot spots | Cost hot spots |
|---|---:|---|---|---|
| **U‑1 UltraPlonk single apply tx** | \(Tx_A + (1\text{ create}+1\text{ init}+Tx_{\text{upload}}) + 1\text{ apply}\) | proof-buffer bytes \((32\cdot PI_{\text{masp}}+2144)\); apply tx must also carry Light proof payloads if used | many confirmations; UltraPlonk proving + buffer uploads | priority fee on near-limit CU tx; many base fees |
| **U‑2 UltraPlonk split (Tx V + Tx S)** | \(Tx_A + (1+1+Tx_{\text{upload}}) + 1\text{ verify} + 1\text{ apply}\) | same proof-buffer bytes; apply tx carries Light payloads | extra verify confirmation; Light proof fetch + apply | base fee for extra tx; priority fee split; Light service cost |
| **G‑1 Groth16 single tx** | typically \(Tx_A + 1\text{ tx}\) | Light proof payloads dominate; MASP proof bytes usually fit inline (192B) | Light proof fetch/generation; fewer confirmations | dominated by Light (service + priority fee if many proofs) |
| **G‑2 Groth16 multi-step (Light-dominated)** | \(Tx_A + k\cdot \text{apply steps}\) | Light payloads force buffering or multiple apply steps | multiple apply confirmations | multiple base fees + Light service cost |

Notes:

- \(Tx_A\) can be >1 tx if ciphertext posting bytes exceed the envelope.
- With today’s public input counts in this repo, UltraPlonk transfer buffer payload is **2560B** → \(Tx_{\text{upload}}=\lceil 2560/900\rceil=3\).
- Under the “intent hash / private nullifiers” architecture, \(PI_{\text{masp}}\) can stay small even as `MAX_INPUTS` increases (reducing upload bytes and avoiding nullifier reveal in verify-only).

---

## 7) Biggest size/time/cost wins (ranked)

1. **Private nullifiers + intent-hash commitment**
   - prevents “verify-only nullifier reveal”
   - reduces MASP public input surface and makes multi-tx safer/cleaner

2. **Groth16 MASP proofs for production**
   - collapses tx count (removes chunked proof buffers)
   - massively reduces on-chain CU for MASP verification

3. **Fix ciphertext posting canonical bytes**
   - remove duplicated ephemeral key in the hashed/posting blob (~64B/output)

4. **Keep N small in the common transfer path**
   - under Light batch max=2, large N quickly becomes proof-heavy on apply
   - use a separate consolidation path if needed


