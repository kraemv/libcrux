mod keys;
mod request_handler;
mod setup;

use ipc_channel::ipc::*;
use ipc_channel::IpcError;
use libcrux_agent::messages::IPCRequest;
use libcrux_agent::Error;
use libcrux_hmac_drbg::HmacDrbgSha256;
use rand::SeedableRng;
use rand::rngs::SysRng;
use std::env;
use std::sync::{LazyLock, RwLock};

static RNG: LazyLock<RwLock<HmacDrbgSha256>> =
    LazyLock::new(|| RwLock::new(HmacDrbgSha256::try_from_rng(&mut SysRng).unwrap()));

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
        let Ok(mut new_request) = IPCRequest::try_from(new_request.as_ref()) else {
            continue;
        };
        let response = request_handler::handle_request(&mut new_request).unwrap_or_else(|err| err.into());
        tx1.send(response.into_bytes().as_ref()).unwrap();
    }
}
