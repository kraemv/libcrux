use libcrux_agent::agent::Agent;
use std::path::PathBuf;
use std::sync::{LazyLock, Mutex, MutexGuard};

const AGENT_NUM: usize = 16;

static AGENTS: LazyLock<Vec<Mutex<Agent>>> = LazyLock::new(|| {
    let mut agents = Vec::with_capacity(AGENT_NUM);
    for _ in 0..AGENT_NUM {
        let agent_path = PathBuf::from(env!("HOME"))
            .join("agent")
            .into_os_string()
            .into_string()
            .unwrap();
        let agent = Agent::connect_agent(agent_path).expect("Agent failed to start");
        agents.push(Mutex::new(agent));
    }
    agents
});

pub fn get_agent() -> Option<MutexGuard<'static, Agent>> {
    AGENTS.iter().find_map(|agent| agent.try_lock().ok()) // TODO: Add Retry logic
}

pub fn get_agent_and_idx() -> Option<(MutexGuard<'static, Agent>, usize)> {
    AGENTS
        .iter()
        .enumerate()
        .find_map(|(idx, agent)| agent.try_lock().ok().map(|agent| (agent, idx)))
}

pub fn get_agent_by_idx(idx: usize) -> Option<MutexGuard<'static, Agent>> {
    AGENTS.get(idx)?.lock().ok()
}
