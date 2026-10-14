use agent_access_broker::{build_identity, composition};
use agent_access_broker_host::{BrokerApplication, BrokerExit};

fn main() -> BrokerExit {
    match composition()
        .and_then(|composition| BrokerApplication::new(composition, build_identity()))
    {
        Ok(application) => application.run_from_env(),
        Err(error) => error.into(),
    }
}
