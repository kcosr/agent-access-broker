use agent_access_broker::{build_identity, composition};
use agent_access_broker_host::{BrokerApplication, BrokerExit};

fn main() -> BrokerExit {
    match composition() {
        Ok(composition) => BrokerApplication::new(composition, build_identity()).run_from_env(),
        Err(error) => error.into(),
    }
}
