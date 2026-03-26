mod request_handler;

use agent_lib::{Error, messages::IPCSetupRequest};

use ipc_channel::ipc::*;

use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();

    let (tx0, rx0) = bytes_channel().unwrap();
    let (tx1, rx1) = bytes_channel().unwrap();
    let super_tx = IpcSender::connect(args[1].clone()).unwrap();
    super_tx.send((tx0, rx1)).unwrap();

    loop {
        let new_request = rx0.recv().unwrap();
        let Ok(new_request) = IPCSetupRequest::try_from(new_request.as_ref()) else {continue;};
        match request_handler::handle_request(&new_request) {
            Ok(response) => tx1.send(response.into_bytes().as_ref()).unwrap(),
            Err(_) => continue,
        };
    }
}
