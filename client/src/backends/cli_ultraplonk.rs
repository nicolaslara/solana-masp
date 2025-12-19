//! CLI-based UltraPlonk prover using nargo + bb.
//!
//! This prover shells out to the installed `nargo` and `bb` CLI tools.
//! No dep conflicts, works with the workspace, uses the standard toolchain.
//!
//! ## Directory Management
//!
//! Each proof operation creates a timestamped directory:
//! ```text
//! client/target/masp_proofs/
//!   transfer-1702841234567/
//!     Prover.toml
//!     witness.gz
//!     proof.bin
//!     vk_bb.bin
//! ```
//!
//! Directories are cleaned up on success. Set `MASP_KEEP_PROOF_ARTIFACTS=1` to keep them.
//!
//! ## Environment Variables
//!
//! - `MASP_BB_PATH`: Path to `bb` binary (default: `~/.bb/bb` if exists, else `bb` in PATH)
//! - `MASP_NARGO_PATH`: Path to `nargo` binary (default: `nargo` in PATH)
//! - `MASP_KEEP_PROOF_ARTIFACTS`: Set to `1` to keep proof directories after success
//!
//! ## Cleanup
//!
//! Old proof directories can be cleaned with `CliProofManager::cleanup_old()`.

use crate::traits::{
    ProofBytes, ProofPublicInputs, ProofSystemError, ShieldPublicInputs, SpendPrivateInputs,
    SpendProver, SpendPublicInputs, UnshieldPublicInputs,
};
use ark_ff::{BigInteger, PrimeField};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// Circuit types supported by the MASP system
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitType {
    Shield,
    Transfer,
    Unshield,
}

impl CircuitType {
    pub fn name(&self) -> &'static str {
        match self {
            CircuitType::Shield => "shield",
            CircuitType::Transfer => "transfer",
            CircuitType::Unshield => "unshield",
        }
    }

    pub fn circuit_dir(&self, repo_root: &Path) -> PathBuf {
        repo_root.join("circuits").join("masp").join(self.name())
    }

    pub fn artifact_name(&self) -> String {
        format!("masp_{}.json", self.name())
    }
}

/// Convert Fr to decimal string for Noir/bb
fn fr_to_dec(fr: crate::types::Fr) -> String {
    let bigint = fr.into_bigint();
    let bytes = bigint.to_bytes_be();
    num_bigint::BigUint::from_bytes_be(&bytes).to_string()
}

fn fr_vec_to_toml_array(vals: &[crate::types::Fr]) -> String {
    // Noir prover TOML commonly uses strings for field elements.
    // Emit: ["123", "456", ...]
    let inner = vals
        .iter()
        .map(|v| format!("\"{}\"", fr_to_dec(*v)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{inner}]")
}

fn bool_vec_to_toml_array(vals: &[bool]) -> String {
    // Emit: [true, false, ...]
    let inner = vals
        .iter()
        .map(|b| {
            if *b {
                "true".to_string()
            } else {
                "false".to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{inner}]")
}

/// Manages proof artifact directories
pub struct CliProofManager {
    base_dir: PathBuf,
}

impl CliProofManager {
    pub fn new() -> Self {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        Self {
            base_dir: base.join("target").join("masp_proofs"),
        }
    }

    /// Create a new timestamped directory for a proof operation
    ///
    /// Uses timestamp + thread ID to avoid race conditions in parallel tests.
    pub fn create_proof_dir(&self, circuit: CircuitType) -> std::io::Result<PathBuf> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        // Include thread ID to avoid race conditions in parallel tests
        let thread_id = format!("{:?}", std::thread::current().id());
        // Extract just the number from "ThreadId(N)"
        let thread_num = thread_id
            .trim_start_matches("ThreadId(")
            .trim_end_matches(')')
            .to_string();
        let dir = self
            .base_dir
            .join(format!("{}-{}-{}", circuit.name(), timestamp, thread_num));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    /// Remove a proof directory (call on success)
    pub fn cleanup_dir(dir: &Path) -> std::io::Result<()> {
        if std::env::var("MASP_KEEP_PROOF_ARTIFACTS").is_ok() {
            eprintln!("Keeping proof artifacts at {}", dir.display());
            return Ok(());
        }
        std::fs::remove_dir_all(dir)
    }

    /// Remove proof directories older than `max_age_secs`
    pub fn cleanup_old(&self, max_age_secs: u64) -> std::io::Result<usize> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        let mut removed = 0;
        if let Ok(entries) = std::fs::read_dir(&self.base_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name_str = name.to_string_lossy();
                // Parse timestamp from directory name (e.g., "transfer-1702841234567")
                if let Some(ts_str) = name_str.rsplit('-').next() {
                    if let Ok(ts) = ts_str.parse::<u64>() {
                        let age_ms = now.saturating_sub(ts);
                        if age_ms > max_age_secs * 1000
                            && std::fs::remove_dir_all(entry.path()).is_ok()
                        {
                            removed += 1;
                        }
                    }
                }
            }
        }
        Ok(removed)
    }

    /// Get the base directory for proof artifacts
    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }
}

impl Default for CliProofManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Get the path to the `bb` binary.
///
/// Priority:
/// 1. `MASP_BB_PATH` environment variable
/// 2. `~/.bb/bb` (default bbup installation)
/// 3. `bb` in PATH
fn get_bb_path() -> PathBuf {
    if let Ok(path) = std::env::var("MASP_BB_PATH") {
        return PathBuf::from(path);
    }

    // Check default bbup location
    if let Some(home) = std::env::var_os("HOME") {
        let default_bb = PathBuf::from(home).join(".bb").join("bb");
        if default_bb.exists() {
            return default_bb;
        }
    }

    // Fall back to PATH
    PathBuf::from("bb")
}

/// Get the path to the `nargo` binary.
///
/// Priority:
/// 1. `MASP_NARGO_PATH` environment variable
/// 2. `nargo` in PATH
fn get_nargo_path() -> PathBuf {
    if let Ok(path) = std::env::var("MASP_NARGO_PATH") {
        return PathBuf::from(path);
    }
    PathBuf::from("nargo")
}

/// CLI-based UltraPlonk prover using nargo + bb
pub struct CliUltraPlonkProver {
    repo_root: PathBuf,
    manager: CliProofManager,
    bb_path: PathBuf,
    nargo_path: PathBuf,
}

impl CliUltraPlonkProver {
    pub fn new() -> Self {
        let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let repo_root = base.join(".."); // client/../ = solana-masp/
        Self {
            repo_root,
            manager: CliProofManager::new(),
            bb_path: get_bb_path(),
            nargo_path: get_nargo_path(),
        }
    }

    fn circuit_dir(&self, circuit_type: CircuitType) -> PathBuf {
        circuit_type.circuit_dir(&self.repo_root)
    }

    fn circuit_json(&self, circuit_type: CircuitType) -> PathBuf {
        self.circuit_dir(circuit_type)
            .join("target")
            .join(circuit_type.artifact_name())
    }

    /// Ensure the canonical VK exists. bb write_vk is non-deterministic, so we must
    /// generate it once and reuse it. Uses file locking to prevent race conditions.
    fn ensure_canonical_vk(
        &self,
        circuit_json: &Path,
        vk_path: &Path,
    ) -> Result<(), ProofSystemError> {
        // Wait for VK to be readable (not just exist) to handle filesystem sync issues
        fn wait_for_readable(path: &Path, max_ms: u64) -> bool {
            let start = std::time::Instant::now();
            while start.elapsed().as_millis() < max_ms as u128 {
                if std::fs::metadata(path)
                    .map(|m| m.len() > 0)
                    .unwrap_or(false)
                {
                    return true;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            false
        }

        // Determine if we need to (re)generate the VK.
        // `bb write_vk` is non-deterministic, so we must generate *once per circuit artifact*,
        // but we MUST regenerate if the circuit changed.
        let vk_is_present = std::fs::metadata(vk_path)
            .map(|m| m.len() > 0)
            .unwrap_or(false);
        let circuit_mtime = std::fs::metadata(circuit_json)
            .and_then(|m| m.modified())
            .ok();
        let vk_mtime = std::fs::metadata(vk_path).and_then(|m| m.modified()).ok();

        let needs_regen = if !vk_is_present {
            true
        } else {
            match (circuit_mtime, vk_mtime) {
                (Some(c), Some(v)) => c > v,
                _ => true, // If we can't determine, regenerate to be safe.
            }
        };

        // Quick path: VK exists and is newer than the circuit.
        if !needs_regen {
            return Ok(());
        }

        // Use lock file to ensure only one process generates the VK
        let lock_path = vk_path.with_extension("lock");

        // Try to acquire lock
        let mut attempts = 0;
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(_lock_file) => {
                    // We have the lock - re-check freshness (someone else may have generated).
                    let vk_is_present = std::fs::metadata(vk_path)
                        .map(|m| m.len() > 0)
                        .unwrap_or(false);
                    let circuit_mtime = std::fs::metadata(circuit_json)
                        .and_then(|m| m.modified())
                        .ok();
                    let vk_mtime = std::fs::metadata(vk_path).and_then(|m| m.modified()).ok();

                    let needs_regen = if !vk_is_present {
                        true
                    } else {
                        match (circuit_mtime, vk_mtime) {
                            (Some(c), Some(v)) => c > v,
                            _ => true,
                        }
                    };

                    if needs_regen {
                        let temp_path = vk_path.with_extension("tmp");
                        Self::run_cmd(
                            Command::new(&self.bb_path)
                                .arg("OLD_API")
                                .arg("write_vk")
                                .arg("-b")
                                .arg(circuit_json)
                                .arg("-o")
                                .arg(&temp_path),
                            &format!("bb write_vk ({})", self.bb_path.display()),
                        )?;
                        // Atomic rename
                        std::fs::rename(&temp_path, vk_path).map_err(|e| {
                            ProofSystemError::ProvingFailed(format!("rename vk: {e}"))
                        })?;
                    }
                    // Release lock
                    let _ = std::fs::remove_file(&lock_path);
                    return Ok(());
                }
                Err(_) => {
                    // Another process has the lock - wait for VK to be readable
                    attempts += 1;
                    if attempts > 100 {
                        // Stale lock - force remove and retry
                        let _ = std::fs::remove_file(&lock_path);
                    }
                    // Wait for VK to appear and be readable
                    if wait_for_readable(vk_path, 100) {
                        return Ok(());
                    }
                }
            }
        }
    }

    fn build_transfer_prover_toml(
        &self,
        public: &SpendPublicInputs,
        private: &SpendPrivateInputs,
    ) -> Result<String, ProofSystemError> {
        let num_outputs = public.output_commitments.len();
        if num_outputs == 0 || num_outputs > 3 {
            return Err(ProofSystemError::InvalidPublicInputs);
        }

        // Pad output commitments to 3 (use 0 for unused slots)
        let zero = crate::types::Fr::from(0u64);
        let out0 = public.output_commitments.first().copied().unwrap_or(zero);
        let out1 = public.output_commitments.get(1).copied().unwrap_or(zero);
        let out2 = public.output_commitments.get(2).copied().unwrap_or(zero);

        // For stage-0, we just use dummy values for output note details
        // In production, these would come from the actual output notes
        let out0_value = private.note_amount; // recipient gets the value
        let out1_value = 0u64; // change value (TODO: pass from client)
        let out2_value = 0u64; // fee value (TODO: pass from client)

        // Private-only: spent commitment (not a public input in the privacy-preserving model)
        let input_commitment = crate::note::Note::with_values(
            private.note_asset_id,
            private.note_amount,
            private.note_recipient,
            private.note_diversifier_index,
            private.note_nullifier_nonce,
            private.note_randomness,
        )
        .commitment();

        let (siblings, path_indices, root) = match &private.membership_witness {
            crate::proofs::MembershipWitness::MerklePath {
                siblings,
                path_indices,
                root,
            } => (siblings, path_indices, root),
            crate::proofs::MembershipWitness::LightValidityProof { .. } => {
                return Err(ProofSystemError::NotImplemented(
                    "ultraplonk(cli) does not support LightValidityProof membership witness"
                        .to_string(),
                ));
            }
        };

        if *root != public.anchor {
            return Err(ProofSystemError::InvalidPublicInputs);
        }

        let siblings_toml = fr_vec_to_toml_array(siblings);
        let path_indices_toml = bool_vec_to_toml_array(path_indices);

        Ok(format!(
            r#"# Auto-generated by CliUltraPlonkProver
anchor = "{anchor}"
input_commitment = "{input_commitment}"
siblings = {siblings}
path_indices = {path_indices}
nullifier = "{nullifier}"
output_commitment_0 = "{out0}"
output_commitment_1 = "{out1}"
output_commitment_2 = "{out2}"
tx_binding = "{tx_binding}"

note_asset_id = "{note_asset_id}"
note_amount = "{note_amount}"
note_recipient = "{note_recipient}"
note_diversifier_index = "{note_diversifier_index}"
note_nullifier_nonce = "{note_nullifier_nonce}"
note_randomness = "{note_randomness}"
nk = "{nk}"
ask = "{ask}"

out0_value = "{out0_value}"
out1_value = "{out1_value}"
out2_value = "{out2_value}"
"#,
            anchor = fr_to_dec(public.anchor),
            input_commitment = fr_to_dec(input_commitment),
            siblings = siblings_toml,
            path_indices = path_indices_toml,
            nullifier = fr_to_dec(public.nullifier),
            out0 = fr_to_dec(out0),
            out1 = fr_to_dec(out1),
            out2 = fr_to_dec(out2),
            tx_binding = fr_to_dec(public.tx_binding),
            note_asset_id = fr_to_dec(private.note_asset_id),
            note_amount = private.note_amount,
            note_recipient = fr_to_dec(private.note_recipient),
            note_diversifier_index = private.note_diversifier_index,
            note_nullifier_nonce = fr_to_dec(private.note_nullifier_nonce),
            note_randomness = fr_to_dec(private.note_randomness),
            nk = fr_to_dec(private.nk),
            // Derive ask from spending_key for the Noir circuit
            ask = fr_to_dec(crate::keys::SpendingKey::from_field(private.spending_key).ask()),
            out0_value = out0_value,
            out1_value = out1_value,
            out2_value = out2_value,
        ))
    }

    fn build_unshield_prover_toml(
        &self,
        public: &UnshieldPublicInputs,
        private: &SpendPrivateInputs,
    ) -> Result<String, ProofSystemError> {
        // Private-only: spent commitment (not a public input in the privacy-preserving model)
        let input_commitment = crate::note::Note::with_values(
            private.note_asset_id,
            private.note_amount,
            private.note_recipient,
            private.note_diversifier_index,
            private.note_nullifier_nonce,
            private.note_randomness,
        )
        .commitment();

        let (siblings, path_indices, root) = match &private.membership_witness {
            crate::proofs::MembershipWitness::MerklePath {
                siblings,
                path_indices,
                root,
            } => (siblings, path_indices, root),
            crate::proofs::MembershipWitness::LightValidityProof { .. } => {
                return Err(ProofSystemError::NotImplemented(
                    "ultraplonk(cli) does not support LightValidityProof membership witness"
                        .to_string(),
                ));
            }
        };

        if *root != public.anchor {
            return Err(ProofSystemError::InvalidPublicInputs);
        }

        let siblings_toml = fr_vec_to_toml_array(siblings);
        let path_indices_toml = bool_vec_to_toml_array(path_indices);

        Ok(format!(
            r#"# Auto-generated by CliUltraPlonkProver
anchor = "{anchor}"
input_commitment = "{input_commitment}"
siblings = {siblings}
path_indices = {path_indices}
nullifier = "{nullifier}"
tx_binding = "{tx_binding}"
public_amount = "{public_amount}"
public_recipient = "{public_recipient}"
public_asset_id = "{public_asset_id}"

note_asset_id = "{note_asset_id}"
note_amount = "{note_amount}"
note_recipient = "{note_recipient}"
note_diversifier_index = "{note_diversifier_index}"
note_nullifier_nonce = "{note_nullifier_nonce}"
note_randomness = "{note_randomness}"
nk = "{nk}"
ask = "{ask}"
"#,
            anchor = fr_to_dec(public.anchor),
            input_commitment = fr_to_dec(input_commitment),
            siblings = siblings_toml,
            path_indices = path_indices_toml,
            nullifier = fr_to_dec(public.nullifier),
            tx_binding = fr_to_dec(public.tx_binding),
            public_amount = public.public_amount,
            public_recipient = fr_to_dec(public.public_recipient),
            public_asset_id = fr_to_dec(public.public_asset_id),
            note_asset_id = fr_to_dec(private.note_asset_id),
            note_amount = private.note_amount,
            note_recipient = fr_to_dec(private.note_recipient),
            note_diversifier_index = private.note_diversifier_index,
            note_nullifier_nonce = fr_to_dec(private.note_nullifier_nonce),
            note_randomness = fr_to_dec(private.note_randomness),
            nk = fr_to_dec(private.nk),
            // Derive ask from spending_key for the Noir circuit
            ask = fr_to_dec(crate::keys::SpendingKey::from_field(private.spending_key).ask()),
        ))
    }

    fn build_shield_prover_toml(
        &self,
        public: &ShieldPublicInputs,
        private: &SpendPrivateInputs,
    ) -> Result<String, ProofSystemError> {
        Ok(format!(
            r#"# Auto-generated by CliUltraPlonkProver
new_commitment = "{new_commitment}"
public_asset_id = "{public_asset_id}"
public_amount = "{public_amount}"

recipient = "{recipient}"
diversifier_index = "{diversifier_index}"
nullifier_nonce = "{nullifier_nonce}"
note_randomness = "{note_randomness}"
"#,
            new_commitment = fr_to_dec(public.new_commitment),
            public_asset_id = fr_to_dec(public.public_asset_id),
            public_amount = public.public_amount,
            recipient = fr_to_dec(private.note_recipient),
            diversifier_index = private.note_diversifier_index,
            nullifier_nonce = fr_to_dec(private.note_nullifier_nonce),
            note_randomness = fr_to_dec(private.note_randomness),
        ))
    }

    /// Ensure the circuit JSON is present and up-to-date with respect to sources.
    fn ensure_circuit_compiled(&self, circuit_type: CircuitType) -> Result<(), ProofSystemError> {
        let circuit_dir = self.circuit_dir(circuit_type);
        let circuit_json = self.circuit_json(circuit_type);

        // Fast path: if json exists and is newer than sources, we're good.
        fn newest_mtime(paths: &[PathBuf]) -> Option<std::time::SystemTime> {
            paths
                .iter()
                .filter_map(|p| std::fs::metadata(p).and_then(|m| m.modified()).ok())
                .max()
        }

        // Collect relevant source files for this circuit and the shared masp_common dependency.
        let mut sources: Vec<PathBuf> = Vec::new();
        sources.push(circuit_dir.join("Nargo.toml"));
        if let Ok(entries) = std::fs::read_dir(circuit_dir.join("src")) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|s| s.to_str()) == Some("nr") {
                    sources.push(p);
                }
            }
        }
        let common_dir = self.repo_root.join("circuits").join("masp").join("common");
        sources.push(common_dir.join("Nargo.toml"));
        if let Ok(entries) = std::fs::read_dir(common_dir.join("src")) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|s| s.to_str()) == Some("nr") {
                    sources.push(p);
                }
            }
        }

        let src_mtime = newest_mtime(&sources);
        let json_mtime = std::fs::metadata(&circuit_json)
            .and_then(|m| m.modified())
            .ok();

        let needs_compile = match (src_mtime, json_mtime) {
            (Some(src), Some(json)) => src > json,
            (Some(_), None) => true,
            _ => !circuit_json.exists(),
        };

        if !needs_compile {
            return Ok(());
        }

        // Simple lock to avoid parallel test races compiling the same circuit.
        let lock_path = circuit_dir.join("target").join(".compile.lock");
        std::fs::create_dir_all(circuit_dir.join("target"))
            .map_err(|e| ProofSystemError::ProvingFailed(format!("create target dir: {e}")))?;

        let mut attempts = 0;
        loop {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(_lock_file) => {
                    // We own the lock; compile.
                    let _ = Self::run_cmd(
                        Command::new(&self.nargo_path)
                            .current_dir(&circuit_dir)
                            .arg("compile"),
                        &format!("nargo compile ({})", self.nargo_path.display()),
                    );
                    let _ = std::fs::remove_file(&lock_path);
                    break;
                }
                Err(_) => {
                    // Someone else compiling; wait for circuit_json to appear/update.
                    attempts += 1;
                    if circuit_json.exists() {
                        // If it exists, assume it'll be updated soon; sleep a bit.
                        std::thread::sleep(std::time::Duration::from_millis(50));
                        if attempts > 200 {
                            // Stale lock - force remove and retry.
                            let _ = std::fs::remove_file(&lock_path);
                            attempts = 0;
                        }
                        continue;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            }
        }

        if !circuit_json.exists() {
            return Err(ProofSystemError::ProvingFailed(format!(
                "circuit json missing after compile: {}",
                circuit_json.display()
            )));
        }
        Ok(())
    }

    fn circuit_type_for(public_inputs: &ProofPublicInputs) -> CircuitType {
        match public_inputs {
            ProofPublicInputs::Shield(_) => CircuitType::Shield,
            ProofPublicInputs::Transfer(_) => CircuitType::Transfer,
            ProofPublicInputs::Unshield(_) => CircuitType::Unshield,
        }
    }

    fn build_prover_toml(
        &self,
        public_inputs: &ProofPublicInputs,
        private_inputs: &SpendPrivateInputs,
    ) -> Result<String, ProofSystemError> {
        match public_inputs {
            ProofPublicInputs::Shield(p) => self.build_shield_prover_toml(p, private_inputs),
            ProofPublicInputs::Transfer(p) => self.build_transfer_prover_toml(p, private_inputs),
            ProofPublicInputs::Unshield(p) => self.build_unshield_prover_toml(p, private_inputs),
        }
    }

    fn proof_prover_name(&self, proof_dir: &Path) -> String {
        // nargo expects a "prover name" which corresponds to a TOML file in the package root:
        // `--prover-name Foo` => reads `Foo.toml`.
        let suffix = proof_dir
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| "proof".to_string());
        format!("Prover_{suffix}")
    }

    /// Run a command and return output, with better error messages
    fn run_cmd(cmd: &mut Command, description: &str) -> Result<Vec<u8>, ProofSystemError> {
        let output = cmd.output().map_err(|e| {
            ProofSystemError::ProvingFailed(format!("{description}: spawn failed: {e}"))
        })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stdout = String::from_utf8_lossy(&output.stdout);
            return Err(ProofSystemError::ProvingFailed(format!(
                "{description} failed (exit {:?}):\nstderr: {}\nstdout: {}",
                output.status.code(),
                stderr,
                stdout
            )));
        }

        Ok(output.stdout)
    }
}

impl Default for CliUltraPlonkProver {
    fn default() -> Self {
        Self::new()
    }
}

impl SpendProver for CliUltraPlonkProver {
    fn prove(
        &self,
        public_inputs: &ProofPublicInputs,
        private_inputs: &SpendPrivateInputs,
    ) -> Result<ProofBytes, ProofSystemError> {
        let circuit_type = Self::circuit_type_for(public_inputs);
        let circuit_dir = self.circuit_dir(circuit_type);

        // 1. Ensure circuit is compiled (and recompile if sources changed)
        self.ensure_circuit_compiled(circuit_type)?;

        // 2. Check circuit is compiled
        let circuit_json = self.circuit_json(circuit_type);
        if !circuit_json.exists() {
            return Err(ProofSystemError::NotImplemented(format!(
                "Circuit not compiled. Run: cd {} && nargo compile",
                circuit_dir.display()
            )));
        }

        // 3. Create proof directory
        let proof_dir = self
            .manager
            .create_proof_dir(circuit_type)
            .map_err(|e| ProofSystemError::ProvingFailed(format!("create proof dir: {e}")))?;

        // Calculate prover name outside closure for cleanup
        let prover_name = self.proof_prover_name(&proof_dir);
        let prover_toml_circuit = circuit_dir.join(format!("{prover_name}.toml"));

        let result = (|| {
            // 4. Write a per-proof prover TOML.
            // nargo execute looks for `<PROVER_NAME>.toml` in the package root, so we must
            // write it there. We also write a copy to proof_dir for archival/debugging.
            let prover_toml_proof = proof_dir.join(format!("{prover_name}.toml"));
            let toml_content = self.build_prover_toml(public_inputs, private_inputs)?;

            // Write to proof_dir first (for archival)
            std::fs::write(&prover_toml_proof, &toml_content).map_err(|e| {
                ProofSystemError::ProvingFailed(format!(
                    "write {}: {e}",
                    prover_toml_proof.display()
                ))
            })?;

            // Copy to circuit_dir (where nargo expects it)
            std::fs::copy(&prover_toml_proof, &prover_toml_circuit).map_err(|e| {
                ProofSystemError::ProvingFailed(format!(
                    "copy {} to {}: {e}",
                    prover_toml_proof.display(),
                    prover_toml_circuit.display()
                ))
            })?;

            // 5. Run nargo execute to generate witness
            // Use a unique witness name per proof directory to avoid race conditions
            let witness_name = format!(
                "witness_{}",
                proof_dir.file_name().unwrap().to_string_lossy()
            );
            Self::run_cmd(
                Command::new(&self.nargo_path)
                    .current_dir(&circuit_dir)
                    .arg("execute")
                    .arg(&witness_name)
                    .arg("--prover-name")
                    .arg(&prover_name),
                &format!("nargo execute ({})", self.nargo_path.display()),
            )?;

            // Witness is at circuit_dir/target/<witness_name>.gz
            let witness_path = circuit_dir
                .join("target")
                .join(format!("{witness_name}.gz"));
            if !witness_path.exists() {
                return Err(ProofSystemError::ProvingFailed(format!(
                    "witness not generated at {}",
                    witness_path.display()
                )));
            }

            // 6. Generate proof with bb
            let proof_path = proof_dir.join("proof.bin");

            // VK MUST be generated once and reused - bb write_vk is non-deterministic!
            // Use the circuit's target directory as the canonical VK location.
            let canonical_vk = circuit_dir.join("target").join("vk_bb.bin");
            self.ensure_canonical_vk(&circuit_json, &canonical_vk)?;
            let vk_path = &canonical_vk;

            // Then generate proof
            Self::run_cmd(
                Command::new(&self.bb_path)
                    .arg("OLD_API")
                    .arg("prove")
                    .arg("-b")
                    .arg(&circuit_json)
                    .arg("-w")
                    .arg(&witness_path)
                    .arg("-o")
                    .arg(&proof_path),
                &format!("bb prove ({})", self.bb_path.display()),
            )?;

            // 7. Read proof (has public inputs prepended)
            let proof_with_pi = std::fs::read(&proof_path)
                .map_err(|e| ProofSystemError::ProvingFailed(format!("read proof: {e}")))?;

            // 8. Read VK to get num_inputs for stripping public input prefix
            let vk_bytes = std::fs::read(vk_path)
                .map_err(|e| ProofSystemError::ProvingFailed(format!("read vk: {e}")))?;

            // VK layout: [4: version][4: circuit_size][4: num_inputs][4: num_commitments][...]
            if vk_bytes.len() < 12 {
                return Err(ProofSystemError::ProvingFailed("VK too short".to_string()));
            }
            let num_inputs =
                u32::from_be_bytes([vk_bytes[8], vk_bytes[9], vk_bytes[10], vk_bytes[11]]);
            let pi_len = (num_inputs as usize) * 32;

            if proof_with_pi.len() <= pi_len {
                return Err(ProofSystemError::ProvingFailed(format!(
                    "proof too short: {} bytes, expected > {} (num_inputs={})",
                    proof_with_pi.len(),
                    pi_len,
                    num_inputs
                )));
            }

            // Return proof body (without PI prefix)
            let proof_body = &proof_with_pi[pi_len..];

            // Cleanup witness file (it's in circuit_dir/target/, not proof_dir)
            let _ = std::fs::remove_file(&witness_path);
            // Cleanup prover toml from circuit_dir (proof_dir copy remains for debugging)
            let _ = std::fs::remove_file(&prover_toml_circuit);

            Ok(ProofBytes::new(proof_body.to_vec()))
        })();

        // Always cleanup prover toml from circuit_dir, even on error
        let _ = std::fs::remove_file(&prover_toml_circuit);

        // Cleanup proof directory on success
        if result.is_ok() {
            let _ = CliProofManager::cleanup_dir(&proof_dir);
        } else {
            eprintln!(
                "Proof generation failed. Artifacts kept at: {}",
                proof_dir.display()
            );
        }

        result
    }

    fn system_name(&self) -> &'static str {
        "ultraplonk(cli)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_manager_create_and_cleanup() {
        let manager = CliProofManager::new();
        let dir = manager.create_proof_dir(CircuitType::Transfer).unwrap();
        assert!(dir.exists());

        // Write a dummy file
        std::fs::write(dir.join("test.txt"), "hello").unwrap();

        // Cleanup
        CliProofManager::cleanup_dir(&dir).unwrap();
        assert!(!dir.exists());
    }

    #[test]
    fn test_circuit_type_paths() {
        let repo_root = PathBuf::from("/tmp/test");
        assert_eq!(
            CircuitType::Transfer.circuit_dir(&repo_root),
            PathBuf::from("/tmp/test/circuits/masp/transfer")
        );
        assert_eq!(CircuitType::Transfer.artifact_name(), "masp_transfer.json");
    }
}
