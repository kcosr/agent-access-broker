use agent_access_broker_host::{BrokerApplication, BrokerExit};
use downstream_broker::{composition, identity};

fn main() -> BrokerExit {
    match composition() {
        Ok(composition) => BrokerApplication::new(composition, identity()).run_from_env(),
        Err(error) => error.into(),
    }
}
