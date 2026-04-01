mod keys;
mod request_handler;
mod setup;

// use keys::{add_ecdsa_p256_key, add_ed25519_key, sign_for_ecdsa_p256_id, sign_for_ed25519_id};

use ipc_channel::ipc::*;
use ipc_channel::IpcError;
use libcrux_agent::messages;
use libcrux_agent::Error;
use rand::SeedableRng;
use rand_chacha::*;
use std::env;
use std::sync::{LazyLock, RwLock};

static RNG: LazyLock<RwLock<ChaCha20Rng>> =
    LazyLock::new(|| RwLock::new(ChaCha20Rng::from_os_rng()));

fn main() {
    setup::do_setup();

    let args: Vec<String> = env::args().collect();

    let (tx0, rx0) = bytes_channel().unwrap();
    let (tx1, rx1) = bytes_channel().unwrap();
    let super_tx = IpcSender::connect(args[1].clone()).unwrap();
    super_tx.send((tx0, rx1)).unwrap();

    loop {
        let new_request = match rx0.recv() {
            Ok(bytes) => bytes,
            Err(IpcError::Disconnected) => break,
            Err(_) => continue,
        };
        let Ok(new_request) = messages::IPCRequest::try_from(new_request.as_ref()) else {
            continue;
        };
        match request_handler::handle_request(&new_request) {
            Ok(response) => tx1.send(response.into_bytes().as_ref()).unwrap(),
            Err(_) => continue,
        };
    }
}
