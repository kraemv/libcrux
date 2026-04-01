use base64ct::{Base64, Encoding};
use rand::rand_core::{OsRng, TryRngCore};
use std::sync::LazyLock;
use zerocopy::*;

use crate::Error;
use libcrux_agent::key_store::*;
use libcrux_agent::messages::*;
use libcrux_agent::signatures::*;

use std::env;
use std::fmt::Write as fmtWrite;
use std::io::Write;
use std::{fs, path::PathBuf};

static KEY_STORE: LazyLock<KeyStore> =
    LazyLock::new(|| KeyStore::from_disk().expect("Failed to load agent"));

fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub(crate) fn handle_request(request: &IPCSetupRequest) -> Result<IPCSetupResponse, Error> {
    match request.get_type().get_type() {
        SetupMessageKind::AgentInit => Ok(IPCSetupResponse::from(&InitResult::from(init_agent()))),
        SetupMessageKind::EcDsaP256Key => {
            let key = EcDsaP256SetupRequest::try_ref_from_bytes(request.get_payload())
                .map_err(|_| Error::MalformedRequest)?;
            import_ecdsa_p256_key(key.try_into()?).map(|res| IPCSetupResponse::from(&res))
        }
        SetupMessageKind::Ed25519Key => {
            let key = Ed25519SetupRequest::try_ref_from_bytes(request.get_payload())
                .map_err(|_| Error::MalformedRequest)?;
            import_ed25519_key(key.into()).map(|res| IPCSetupResponse::from(&res))
        }
    }
}

fn agent_paths(id: &[u8]) -> (PathBuf, PathBuf, PathBuf, String) {
    let agent_path = PathBuf::from(format!("{}/agent", env!("HOME")));
    let root_file = agent_path.join("root_file");
    let hex_id = encode_hex(id);
    let key_subdir = format!("{:02x}/", id[0]);
    let key_path = agent_path.join(&key_subdir);
    let key_file = key_path.join(&hex_id);
    (root_file, key_path, key_file, hex_id)
}

fn init_agent() -> Result<(), Error> {
    // Build directory and root file paths and create directory
    let agent_path = PathBuf::from(format!("{}/agent", env!("HOME")));
    let root_file = agent_path.join("root_file");
    fs::create_dir_all(agent_path).map_err(|_| Error::IO)?;

    // Draw a random root key and encode it in b64 for the root file
    let mut root_key = [0u8; 32];
    let mut b64_encoded_key = [0u8; 44];
    OsRng.try_fill_bytes(&mut root_key).map_err(|_| Error::IO)?;
    Base64::encode(&root_key, &mut b64_encoded_key).map_err(|_| Error::Encoding)?;

    // Write the key to the root file
    fs::write(root_file, b64_encoded_key).map_err(|_| Error::IO)?;
    Ok(())
}

fn register_key(id: &[u8; 32], key_bytes: &[u8], key_label: &[u8]) -> Result<(), Error> {
    let (root_file, key_path, key_file, _) = agent_paths(id);

    let mut enc_id = [0u8; 44];
    Base64::encode(id, &mut enc_id).map_err(|_| Error::Encoding)?;

    let entry = [b"\n", key_label, b" ", enc_id.as_slice()].concat();

    fs::create_dir_all(&key_path).map_err(|_| Error::IO)?;
    fs::write(key_file, key_bytes).map_err(|_| Error::IO)?;

    let mut agent_file = fs::OpenOptions::new()
        .append(true)
        .open(root_file)
        .map_err(|_| Error::IO)?;
    agent_file.write_all(&entry).map_err(|_| Error::IO)?;

    Ok(())
}

fn import_ecdsa_p256_key(key: EcDsaP256PrivateKey) -> Result<EcDsaP256SetupResponse, Error> {
    let key_bytes = *key.as_bytes();
    let (id, pk) = KEY_STORE.add_ecdsa_p256_key(key)?;
    register_key(&id, &key_bytes, b"ECDSA_NISTP256_SHA256")?;
    Ok(EcDsaP256SetupResponse::new(id, pk))
}

fn import_ed25519_key(key: Ed25519PrivateKey) -> Result<Ed25519SetupResponse, Error> {
    let key_bytes = *key.as_bytes();
    let (id, pk) = KEY_STORE.add_ed25519_key(key)?;
    register_key(&id, &key_bytes, b"ED25519")?;
    Ok(Ed25519SetupResponse::new(id, pk))
}
