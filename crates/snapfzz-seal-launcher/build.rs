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
    let dest_path = std::path::Path::new(&out_dir).join("launcher_markers.rs");

    let build_id = std::env::var("BUILD_ID").unwrap_or_else(|_| {
        format!(
            "{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs()
        )
    });

    let mut file = std::fs::File::create(&dest_path).expect("must create launcher marker file");

    for i in 0..5 {
        let marker = derive_marker(&build_id, format!("secret_marker_{i}").as_bytes());
        let mut arr = [0u8; 64];
        arr[..32].copy_from_slice(&marker);
        writeln!(
            file,
            "#[used] #[unsafe(no_mangle)] #[unsafe(link_section = \"__DATA,__data\")] pub static SECRET_SHARE_{}: [u8; 64] = {:?};",
            i, arr
        )
        .expect("must write secret share marker");
    }

    let tamper = derive_marker(&build_id, b"tamper_marker");
    let mut tamper_arr = [0u8; 64];
    tamper_arr[..32].copy_from_slice(&tamper);
    writeln!(
        file,
        "#[used] #[unsafe(no_mangle)] #[unsafe(link_section = \"__DATA,__data\")] pub static TAMPER_HASH: [u8; 64] = {:?};",
        tamper_arr
    )
    .expect("must write tamper marker");

    let sentinel = derive_marker(&build_id, b"payload_sentinel");
    writeln!(
        file,
        "#[used] #[unsafe(no_mangle)] #[unsafe(link_section = \"__DATA,__data\")] pub static PAYLOAD_SENTINEL: [u8; 32] = {:?};",
        sentinel
    )
    .expect("must write payload sentinel");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=BUILD_ID");
}
