use agent_access_broker_host::{BrokerApplication, BrokerExit};
use downstream_broker::{build_identity, composition};

fn main() -> BrokerExit {
    match composition()
        .and_then(|composition| BrokerApplication::new(composition, build_identity()))
    {
        Ok(application) => application.run_from_env(),
        Err(error) => error.into(),
    }
}
