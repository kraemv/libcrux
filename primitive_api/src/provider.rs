use libcrux_agent::agent::Agent;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex, MutexGuard};

static AGENT: LazyLock<Mutex<Agent>> = LazyLock::new(|| {
        let agent_path = PathBuf::from(env!("HOME"))
            .join("agent")
            .into_os_string()
            .into_string()
            .unwrap();
        Mutex::new(Agent::connect_agent(agent_path).expect("Agent failed to start"))
});

pub fn get_agent() -> Option<MutexGuard<'static, Agent>> {
    AGENT.lock().ok()
}