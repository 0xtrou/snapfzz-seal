use sha2::{Digest, Sha256};
use std::io::Write;

const EMBEDDED_MARKER_SIZE: usize = 32;
const EMBEDDED_SLOT_SIZE: usize = 32;

fn derive_marker(build_id: &str, label: &[u8]) -> [u8; EMBEDDED_MARKER_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(build_id.as_bytes());
    hasher.update(label);
    hasher.update(b"deterministic_marker_v1");
    hasher.finalize().into()
}

fn format_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| byte.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

fn main() {
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR must be set by Cargo");
    let dest_path = std::path::Path::new(&out_dir).join("launcher_markers.rs");

    let profile = std::env::var("PROFILE").unwrap_or_default();
    let build_id = match std::env::var("BUILD_ID") {
        Ok(id) => id,
        Err(_) => {
            if profile == "release" {
                panic!(
                    "BUILD_ID environment variable must be set for release builds. Set it to a unique build identifier (e.g. git SHA)."
                );
            }
            "dev".to_string()
        }
    };

    let mut file = std::fs::File::create(&dest_path).expect("must create launcher marker file");

    #[cfg(target_os = "linux")]
    let link_section = ".data.snapfzz_markers";
    #[cfg(target_os = "macos")]
    let link_section = "__DATA,__snapfzz_mrk";

    writeln!(
        file,
        "
#[derive(Copy, Clone)]
#[repr(C)]
pub struct MarkerSlot {{
    pub marker: [u8; {EMBEDDED_MARKER_SIZE}],
    pub slot: [u8; {EMBEDDED_SLOT_SIZE}],
}}

#[derive(Copy, Clone)]
#[repr(C)]
pub struct LauncherMarkers {{
    pub secret_share_0: MarkerSlot,
    pub secret_share_1: MarkerSlot,
    pub secret_share_2: MarkerSlot,
    pub secret_share_3: MarkerSlot,
    pub secret_share_4: MarkerSlot,
    pub tamper_hash: MarkerSlot,
    pub payload_sentinel: [u8; {EMBEDDED_MARKER_SIZE}],
}}

const _: [(); 64] = [(); core::mem::size_of::<MarkerSlot>()];
const _: [(); 416] = [(); core::mem::size_of::<LauncherMarkers>()];"
    )
    .expect("must write marker types");

    writeln!(file, "#[used]").expect("must write used attribute");
    writeln!(file, "#[unsafe(no_mangle)]").expect("must write no_mangle attribute");
    writeln!(file, "#[unsafe(link_section = \"{}\")]", link_section)
        .expect("must write link_section");
    writeln!(
        file,
        "pub static LAUNCHER_MARKERS: LauncherMarkers = LauncherMarkers {{"
    )
    .expect("must write static start");

    for i in 0..5 {
        let marker = derive_marker(&build_id, format!("secret_marker_{i}").as_bytes());
        writeln!(
            file,
            "    secret_share_{i}: MarkerSlot {{ marker: [{}], slot: [0; {EMBEDDED_SLOT_SIZE}] }},",
            format_bytes(&marker)
        )
        .expect("must write secret share marker");
    }

    let tamper = derive_marker(&build_id, b"tamper_marker");
    writeln!(
        file,
        "    tamper_hash: MarkerSlot {{ marker: [{}], slot: [0; {EMBEDDED_SLOT_SIZE}] }},",
        format_bytes(&tamper)
    )
    .expect("must write tamper marker");

    let sentinel = derive_marker(&build_id, b"payload_sentinel");
    writeln!(file, "    payload_sentinel: [{}],", format_bytes(&sentinel))
        .expect("must write payload sentinel");

    writeln!(file, "}};").expect("must write static end");

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=BUILD_ID");
    println!("cargo:rerun-if-env-changed=SNAPFZZ_SEAL_ROOT_PUBKEY_HEX");

    if let Ok(pubkey_hex) = std::env::var("SNAPFZZ_SEAL_ROOT_PUBKEY_HEX") {
        println!("cargo:rustc-env=SNAPFZZ_SEAL_ROOT_PUBKEY_HEX={pubkey_hex}");
    }
}
