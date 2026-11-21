use std::env;
use std::process::ExitCode;

use meshvault_crypto::{DEFAULT_CHUNK_SIZE, HEADER_FORMAT_VERSION};

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("version") | Some("--version") | Some("-V") => {
            println!(
                "meshvault {} (format v{}, chunk_size={} bytes)",
                env!("CARGO_PKG_VERSION"),
                HEADER_FORMAT_VERSION,
                DEFAULT_CHUNK_SIZE
            );
            ExitCode::SUCCESS
        }
        Some("info") => {
            let payload = serde_json::json!({
                "product": "MeshVault",
                "format_version": HEADER_FORMAT_VERSION,
                "chunk_size_bytes": DEFAULT_CHUNK_SIZE,
                "cipher": "XChaCha20-Poly1305",
                "kdf": "Argon2id",
                "invariant": "zero-plaintext-on-disk"
            });
            println!("{payload}");
            ExitCode::SUCCESS
        }
        _ => {
            println!("MeshVault CLI (Stage 1 skeleton). Subcommands: version, info");
            ExitCode::SUCCESS
        }
    }
}
