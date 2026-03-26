use agent_lib::Error;
use agent_lib::agent;
use std::sync::{LazyLock, Mutex, MutexGuard};

use crate::agent::Agent;

const NUM_AGENTS: usize = 16;

static AGENTS: LazyLock<[Mutex<agent::Agent>; NUM_AGENTS]> = LazyLock::new(|| core::array::from_fn(|_| Mutex::new(agent::Agent::connect_agent().unwrap())));

pub fn get_agent() -> Result<MutexGuard<'static, Agent>, Error> {
    AGENTS.iter().find_map(|agent| agent.try_lock().ok()).ok_or(Error::NoAgent)
}