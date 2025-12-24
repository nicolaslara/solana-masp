//! Build script for MASP program
//!
//! Note: UltraPlonk verification keys are embedded in the masp-verifier program,
//! not in this program. Verification is done via CPI to masp-verifier.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
