use base64ct::{Base64, Encoding};
use rand::rand_core::{OsRng, TryRngCore};
use std::sync::{LazyLock};
use zerocopy::*;

use agent_lib::messages::*;
use agent_lib::key_store::*;
use agent_lib::signatures::*;
use crate::Error;

use std::{fs, path::Path};
use std::env;
use std::fmt::Write as fmtWrite;
use std::io::Write;

static KEY_STORE: LazyLock<KeyStore> = LazyLock::new(|| KeyStore::from_disk().expect("Failed to load agent"));

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
            let key = EcDsaP256SetupRequest::try_ref_from_bytes(request.get_payload()).map_err(|_| Error::MalformedRequest)?;
            import_ecdsa_p256_key(key.try_into()?)
                .map(|res| IPCSetupResponse::from(&res))
        }
        SetupMessageKind::Ed25519Key => {
            let key = Ed25519SetupRequest::try_ref_from_bytes(request.get_payload()).map_err(|_| Error::MalformedRequest)?;
            import_ed25519_key(key.into())
                .map(|res| IPCSetupResponse::from(&res))
        }
    }
}

fn init_agent() -> Result<(), Error> {
    // Build directory and root file paths and create directory
    let agent_path = format!("{}/agent", env!("HOME"));
    let agent_path = Path::new(&agent_path);
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

fn import_ecdsa_p256_key(key: EcDsaP256PrivateKey) -> Result<EcDsaP256SetupResponse, Error> {
    let agent_path = format!("{}/agent", env!("HOME"));
    let agent_path = Path::new(&agent_path);
    let key_bytes = *key.as_bytes();
    
    let (id, pk) = KEY_STORE.add_ecdsa_p256_key(key)?;
    let hex_id = encode_hex(&id);
    let mut enc_id: [u8; 44] = [0; 44];
    Base64::encode(&id, &mut enc_id).map_err(|_| Error::Encoding)?;

    let mut key_path = String::with_capacity(3);
    write!(&mut key_path, "{:02x}/", id[0]).unwrap();
    let key_path = agent_path.join(key_path);
    let root_file = agent_path.join("root_file");
    let key_file = key_path.join(&hex_id);

    let entry = [b"\nECDSA_NISTP256_SHA256 ".as_slice(), enc_id.as_slice()].concat();
    
    let mut agent_file = fs::OpenOptions::new().append(true).open(root_file).map_err(|_| Error::IO)?;

    fs::create_dir_all(&key_path).map_err(|_| Error::IO)?;
    fs::write(key_file, key_bytes).map_err(|_| Error::IO)?;
    agent_file.write(&entry).map_err(|_| Error::IO)?;
    
    Ok(EcDsaP256SetupResponse::new(id, pk))
}

fn import_ed25519_key(key: Ed25519PrivateKey) -> Result<Ed25519SetupResponse, Error> {
    let agent_path = format!("{}/agent", env!("HOME"));
    let agent_path = Path::new(&agent_path);
    let key_bytes = *key.as_bytes();
    
    let (id, pk) = KEY_STORE.add_ed25519_key(key)?;
    let hex_id = encode_hex(&id);
    let mut enc_id: [u8; 44] = [0; 44];
    Base64::encode(&id, &mut enc_id).map_err(|_| Error::Encoding)?;

    let mut key_path = String::with_capacity(3);
    write!(&mut key_path, "{:02x}/", id[0]).unwrap();
    let key_path = agent_path.join(key_path);
    let root_file = agent_path.join("root_file");
    let key_file = key_path.join(&hex_id);

    let entry = [b"\nED25519 ".as_slice(), enc_id.as_slice()].concat();
    
    let mut agent_file = fs::OpenOptions::new().append(true).open(root_file).map_err(|_| Error::IO)?;

    fs::create_dir_all(&key_path).map_err(|_| Error::IO)?;
    fs::write(key_file, key_bytes).map_err(|_| Error::IO)?;
    agent_file.write(&entry).map_err(|_| Error::IO)?;
    
    Ok(Ed25519SetupResponse::new(id, pk))
}