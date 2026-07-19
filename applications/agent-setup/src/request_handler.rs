use libcrux_agent::ID;
use rand::rngs::SysRng;
use rand::TryRng;
use std::sync::LazyLock;
use zerocopy::*;

use crate::Error;
use libcrux_agent::key_store::*;
use libcrux_agent::messages::*;
use libcrux_agent::signatures::*;
use libcrux_agent::signing_messages::*;

use std::env;
use std::io::Write;
use std::{fs, path::PathBuf};

static KEY_STORE: LazyLock<LongTermKeyStore> =
    LazyLock::new(|| KeyStore::from_disk().expect("Failed to load agent"));

pub(crate) fn handle_request(request: &IPCSetupRequest) -> Result<IPCSetupResponse, Error> {
    match request.get_header().get_type() {
        SetupMessageKind::AgentInit => Ok(IPCSetupResponse::from(&InitResult::from(init_agent()))),
        SetupMessageKind::EcDsaP256Key => {
            let key = SetupRequest::<EcDsaP256SHA256>::try_ref_from_bytes(request.get_payload())?;
            import_ecdsa_p256_key(key.get_private_key()?).map(|res| IPCSetupResponse::from(&res))
        }
        SetupMessageKind::Ed25519Key => {
            let key = SetupRequest::<Ed25519>::try_ref_from_bytes(request.get_payload())?;
            import_ed25519_key(key.get_private_key()).map(|res| IPCSetupResponse::from(&res))
        }
        SetupMessageKind::Error => Err(Error::IO),
    }
}

fn agent_paths(id: &ID) -> (PathBuf, PathBuf, PathBuf, String) {
    let agent_path = PathBuf::from(format!("{}/agent", env!("HOME")));
    let root_file = agent_path.join("root_file");
    let hex_id = hex::encode(id.as_ref());
    let key_subdir = format!("{:02x}/", id.as_ref()[0]);
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
    SysRng
        .try_fill_bytes(&mut root_key)
        .map_err(|_| Error::IO)?;
    let root_key = hex::encode(root_key);

    // Write the key to the root file
    fs::write(root_file, root_key.as_bytes()).map_err(|_| Error::IO)?;
    Ok(())
}

fn register_key(id: &ID, key_bytes: &[u8], key_label: &[u8]) -> Result<(), Error> {
    let (root_file, key_path, key_file, enc_id) = agent_paths(id);

    let entry = [b"\n", key_label, b" ", enc_id.as_bytes()].concat();

    fs::create_dir_all(&key_path).map_err(|_| Error::IO)?;
    fs::write(key_file, key_bytes).map_err(|_| Error::IO)?;

    let mut agent_file = fs::OpenOptions::new()
        .append(true)
        .open(root_file)
        .map_err(|_| Error::IO)?;
    agent_file.write_all(&entry).map_err(|_| Error::IO)?;

    Ok(())
}

fn import_ecdsa_p256_key(
    key: EcDsaP256PrivateKey<SHA256>,
) -> Result<SetupResponse<EcDsaP256PublicKey<SHA256>>, Error> {
    let key_bytes = *key.as_bytes();
    let (id, pk) = KEY_STORE.ecdsa_p256_add_key(key)?;
    register_key(&id, &key_bytes, b"ECDSA_NISTP256_SHA256")?;
    Ok(SetupResponse::<EcDsaP256PublicKey<SHA256>>::new(id, pk))
}

fn import_ed25519_key(key: Ed25519PrivateKey) -> Result<SetupResponse<Ed25519PublicKey>, Error> {
    let key_bytes = *key.as_bytes();
    let (id, pk) = KEY_STORE.ed25519_add_key(key)?;
    register_key(&id, &key_bytes, b"ED25519")?;
    Ok(SetupResponse::<Ed25519PublicKey>::new(id, pk))
}
