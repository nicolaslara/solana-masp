//! Backend configuration
//!
//! Configure backends via environment variables or programmatically.

use std::env;
use std::fmt;

// ============================================================================
// Chain Backend
// ============================================================================

/// Chain backend selection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainBackend {
    /// In-memory mock (default for testing)
    Mock,
    /// Local Surfpool (http://127.0.0.1:8899)
    Surfpool,
    /// Solana devnet
    Devnet,
    /// Solana testnet
    Testnet,
    /// Solana mainnet-beta
    Mainnet,
    /// Custom RPC URL
    Custom(String),
}

impl ChainBackend {
    /// Get the RPC URL for this backend
    pub fn rpc_url(&self) -> Option<&str> {
        match self {
            ChainBackend::Mock => None,
            ChainBackend::Surfpool => Some("http://127.0.0.1:8899"),
            ChainBackend::Devnet => Some("https://api.devnet.solana.com"),
            ChainBackend::Testnet => Some("https://api.testnet.solana.com"),
            ChainBackend::Mainnet => Some("https://api.mainnet-beta.solana.com"),
            ChainBackend::Custom(url) => Some(url),
        }
    }

    /// Parse from environment variable or string
    pub fn from_env_or_default() -> Self {
        match env::var("MASP_CHAIN").as_deref() {
            Ok("mock") | Ok("") | Err(_) => ChainBackend::Mock, // Empty string = Mock
            Ok("surfpool") => ChainBackend::Surfpool,
            Ok("devnet") => ChainBackend::Devnet,
            Ok("testnet") => ChainBackend::Testnet,
            Ok("mainnet") => ChainBackend::Mainnet,
            Ok(url) => ChainBackend::Custom(url.to_string()),
        }
    }
}

impl fmt::Display for ChainBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainBackend::Mock => write!(f, "mock"),
            ChainBackend::Surfpool => write!(f, "surfpool ({})", self.rpc_url().unwrap()),
            ChainBackend::Devnet => write!(f, "devnet"),
            ChainBackend::Testnet => write!(f, "testnet"),
            ChainBackend::Mainnet => write!(f, "mainnet"),
            ChainBackend::Custom(url) => write!(f, "custom ({})", url),
        }
    }
}

// ============================================================================
// Indexer Backend
// ============================================================================

/// Indexer backend selection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexerBackend {
    /// In-memory mock (default for testing)
    Mock,
    /// Light Protocol via Helius RPC
    Light,
}

impl IndexerBackend {
    /// Parse from environment variable
    pub fn from_env_or_default() -> Self {
        match env::var("MASP_INDEXER").as_deref() {
            Ok("light") => IndexerBackend::Light,
            Ok("mock") | Err(_) => IndexerBackend::Mock,
            Ok(other) => {
                eprintln!("Unknown indexer backend '{}', using mock", other);
                IndexerBackend::Mock
            }
        }
    }
}

impl fmt::Display for IndexerBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IndexerBackend::Mock => write!(f, "mock"),
            IndexerBackend::Light => write!(f, "light-protocol (helius)"),
        }
    }
}

// ============================================================================
// Encryption Backend
// ============================================================================

/// Encryption backend selection
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncryptionBackend {
    /// ChaCha20-Poly1305 AEAD (default, production)
    ///
    /// Properties:
    /// - 256-bit key, 96-bit nonce
    /// - Authenticated encryption (integrity + confidentiality)
    /// - Fast in software (no AES-NI required)
    /// - Used in TLS 1.3, WireGuard, Noise Protocol
    /// - Standard IETF RFC 8439
    ChaCha,

    /// Mock encryption (fast testing, NOT SECURE)
    ///
    /// Uses XOR with deterministic "key" - only for tests!
    Mock,
    // Future options:
    // - AesGcm: AES-256-GCM (hardware acceleration on modern CPUs)
    // - XChaCha: Extended nonce ChaCha20-Poly1305 (192-bit nonce)
    // - Aegis: AEGIS-256 (very fast with AES-NI, used in some modern systems)
}

impl EncryptionBackend {
    /// Parse from environment variable
    pub fn from_env_or_default() -> Self {
        match env::var("MASP_ENCRYPTION").as_deref() {
            Ok("mock") => EncryptionBackend::Mock,
            Ok("chacha") | Err(_) => EncryptionBackend::ChaCha,
            Ok(other) => {
                eprintln!("Unknown encryption backend '{}', using chacha", other);
                EncryptionBackend::ChaCha
            }
        }
    }
}

impl fmt::Display for EncryptionBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncryptionBackend::ChaCha => write!(f, "chacha20-poly1305"),
            EncryptionBackend::Mock => write!(f, "mock (INSECURE)"),
        }
    }
}

// ============================================================================
// Proof System Backend
// ============================================================================

/// Proof system backend selection (spend proving + verification)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofSystemBackend {
    /// Mock prover/verifier (default)
    Mock,
    /// UltraPlonk (Noir + bb)
    UltraPlonk,
    /// Groth16 (Noir + groth16)
    Groth16,
}

impl ProofSystemBackend {
    pub fn from_env_or_default() -> Self {
        match env::var("MASP_PROOF_SYSTEM").as_deref() {
            Ok("ultraplonk") => ProofSystemBackend::UltraPlonk,
            Ok("groth16") => ProofSystemBackend::Groth16,
            Ok("mock") | Err(_) => ProofSystemBackend::Mock,
            Ok(other) => {
                eprintln!("Unknown proof system '{}', using mock", other);
                ProofSystemBackend::Mock
            }
        }
    }
}

impl fmt::Display for ProofSystemBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofSystemBackend::Mock => write!(f, "mock"),
            ProofSystemBackend::UltraPlonk => write!(f, "ultraplonk"),
            ProofSystemBackend::Groth16 => write!(f, "groth16"),
        }
    }
}

// ============================================================================
// Proof Verification Mode
// ============================================================================

/// Where spend proof verification is performed.
///
/// - Local: off-chain verification (fast iteration)
/// - OnChain: verification via Solana program instruction / CPI
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofVerificationMode {
    Local,
    OnChain,
}

impl ProofVerificationMode {
    pub fn from_env_or_default(chain: &ChainBackend) -> Self {
        match env::var("MASP_PROOF_VERIFY").as_deref() {
            Ok("local") => ProofVerificationMode::Local,
            Ok("onchain") => ProofVerificationMode::OnChain,
            Ok(other) => {
                eprintln!("Unknown MASP_PROOF_VERIFY '{}', using default", other);
                Self::default_for_chain(chain)
            }
            Err(_) => Self::default_for_chain(chain),
        }
    }

    fn default_for_chain(chain: &ChainBackend) -> Self {
        match chain {
            ChainBackend::Mock => ProofVerificationMode::Local,
            _ => ProofVerificationMode::OnChain,
        }
    }
}

impl fmt::Display for ProofVerificationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofVerificationMode::Local => write!(f, "local"),
            ProofVerificationMode::OnChain => write!(f, "onchain"),
        }
    }
}

// ============================================================================
// Combined Configuration
// ============================================================================

/// Complete backend configuration
#[derive(Debug, Clone)]
pub struct BackendConfig {
    pub chain: ChainBackend,
    pub indexer: IndexerBackend,
    pub encryption: EncryptionBackend,
    pub proof_system: ProofSystemBackend,
    pub proof_verify: ProofVerificationMode,
}

impl BackendConfig {
    /// Create configuration from environment variables
    pub fn from_env() -> Self {
        let chain = ChainBackend::from_env_or_default();
        Self {
            proof_verify: ProofVerificationMode::from_env_or_default(&chain),
            chain,
            indexer: IndexerBackend::from_env_or_default(),
            encryption: EncryptionBackend::from_env_or_default(),
            proof_system: ProofSystemBackend::from_env_or_default(),
        }
    }

    /// Create default mock configuration
    pub fn mock() -> Self {
        Self {
            chain: ChainBackend::Mock,
            indexer: IndexerBackend::Mock,
            encryption: EncryptionBackend::ChaCha,
            proof_system: ProofSystemBackend::Mock,
            proof_verify: ProofVerificationMode::Local,
        }
    }

    /// Create Surfpool configuration (local testing with real Solana)
    pub fn surfpool() -> Self {
        Self {
            chain: ChainBackend::Surfpool,
            indexer: IndexerBackend::Mock, // No Light Protocol locally
            encryption: EncryptionBackend::ChaCha,
            proof_system: ProofSystemBackend::Mock,
            proof_verify: ProofVerificationMode::OnChain,
        }
    }

    /// Create devnet configuration
    pub fn devnet() -> Self {
        Self {
            chain: ChainBackend::Devnet,
            indexer: IndexerBackend::Light,
            encryption: EncryptionBackend::ChaCha,
            proof_system: ProofSystemBackend::Mock,
            proof_verify: ProofVerificationMode::OnChain,
        }
    }

    /// Print configuration (useful for debugging)
    pub fn print_config(&self) {
        println!("╔══════════════════════════════════════╗");
        println!("║       MASP Backend Configuration     ║");
        println!("╠══════════════════════════════════════╣");
        println!("║ Chain:      {:<24} ║", self.chain);
        println!("║ Indexer:    {:<24} ║", self.indexer);
        println!("║ Encryption: {:<24} ║", self.encryption);
        println!("║ Proof:      {:<24} ║", self.proof_system);
        println!("║ Verify:     {:<24} ║", self.proof_verify);
        println!("╚══════════════════════════════════════╝");
    }
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self::mock()
    }
}

impl fmt::Display for BackendConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "chain={}, indexer={}, encryption={}",
            self.chain, self.indexer, self.encryption
        )
    }
}
