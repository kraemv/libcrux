mod request_handler;

use libcrux_agent::{messages::IPCSetupRequest, Error};

use ipc_channel::{ipc::*, IpcError};

use std::env;

fn main() {
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
        let Ok(new_request) = IPCSetupRequest::try_from(new_request.as_slice()) else {
            continue;
        };
        let response = request_handler::handle_request(&new_request).unwrap_or_else(|err| err.into());
        tx1.send(response.into_bytes().as_ref()).unwrap();
    }
}
