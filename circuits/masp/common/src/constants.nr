// Circuit constants shared across all MASP circuits
//
// These define compile-time bounds for the circuit shapes.

/// Maximum number of inputs per transfer (compile-time constant).
pub global MAX_INPUTS: u32 = 3;

/// Maximum number of outputs per transfer (compile-time constant).
pub global MAX_OUTPUTS: u32 = 3;

/// Merkle tree depth for commitment accumulator.
pub global MERKLE_DEPTH: u32 = 32;
