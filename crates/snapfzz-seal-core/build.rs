use sha2::{Digest, Sha256};
use std::io::Write;

fn derive_marker(build_id: &str, label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(build_id.as_bytes());
    hasher.update(label);
    hasher.update(b"deterministic_marker_v1");
    hasher.finalize().into()
}

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR must be set by Cargo");
    let dest_path = std::path::Path::new(&out_dir).join("generated_markers.rs");

    let build_id =
        std::env::var("BUILD_ID").unwrap_or_else(|_| chrono::Utc::now().timestamp().to_string());

    let mut file = std::fs::File::create(&dest_path).expect("must create generated marker file");

    for i in 0..5 {
        let marker = derive_marker(&build_id, format!("secret_marker_{i}").as_bytes());
        writeln!(
            file,
            "pub const SECRET_MARKER_{}: [u8; 32] = {:?};",
            i, marker
        )
        .expect("must write secret marker");
    }

    let tamper = derive_marker(&build_id, b"tamper_marker");
    writeln!(file, "pub const TAMPER_MARKER: [u8; 32] = {:?};", tamper)
        .expect("must write tamper marker");

    let sentinel = derive_marker(&build_id, b"payload_sentinel");
    writeln!(
        file,
        "pub const PAYLOAD_SENTINEL: [u8; 32] = {:?};",
        sentinel
    )
    .expect("must write payload sentinel");

    writeln!(file, "pub const DECOY_MARKERS: [[u8; 32]; 50] = [")
        .expect("must start decoy marker array");
    for i in 0..50 {
        let marker = derive_marker(&build_id, format!("decoy_marker_{i}").as_bytes());
        writeln!(file, "    {:?},", marker).expect("must write decoy marker");
    }
    writeln!(file, "]; ").expect("must close decoy marker array");

    writeln!(
        file,
        "pub const POSITION_HINT_SALT: [u8; 32] = {:?};",
        derive_marker(&build_id, b"position_hint_salt")
    )
    .expect("must write position hint salt");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=BUILD_ID");
    println!("cargo:rustc-env=BUILD_ID={}", build_id);
}
