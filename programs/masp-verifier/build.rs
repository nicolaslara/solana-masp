//! Build script for MASP UltraPlonk verifier
//!
//! Embeds verification keys for all 3 MASP circuits:
//! - Shield
//! - Transfer  
//! - Unshield

use std::env;
use std::fs;
use std::path::Path;

const VK_SIZE: usize = 1632; // Solidity format without G2_X

fn main() {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let out_dir = env::var("OUT_DIR").unwrap();
    
    // MASP circuit VK paths (from circuit compilation)
    let circuits = ["shield", "transfer", "unshield"];
    
    for circuit in &circuits {
        let vk_path = Path::new(&manifest_dir)
            .join("..")
            .join("..")
            .join("circuits")
            .join("masp")
            .join(circuit)
            .join("target")
            .join("vk_onchain.bin");
        
        let dest_path = Path::new(&out_dir).join(format!("vk_{}.bin", circuit));
        
        if vk_path.exists() {
            let vk_bytes = fs::read(&vk_path).expect(&format!("Failed to read {} VK", circuit));
            
            if vk_bytes.len() != VK_SIZE {
                panic!(
                    "{} VK should be {} bytes, got {} bytes.\n\
                     Regenerate with: cargo test -p masp-client masp_ultraplonk_pipeline",
                    circuit, VK_SIZE, vk_bytes.len()
                );
            }
            
            fs::write(&dest_path, &vk_bytes).expect(&format!("Failed to write {} VK", circuit));
            println!("cargo:warning=Embedded real VK for {} ({} bytes)", circuit, VK_SIZE);
        } else {
            // Generate stub VK for compilation (will fail at runtime)
            println!("cargo:warning=⚠️ {} VK not found, using stub. Run circuit compilation first!", circuit);
            let stub = vec![0u8; VK_SIZE];
            fs::write(&dest_path, &stub).expect(&format!("Failed to write stub {} VK", circuit));
        }
        
        println!("cargo:rerun-if-changed={}", vk_path.display());
    }
    
    println!("cargo:rerun-if-changed=build.rs");
}
