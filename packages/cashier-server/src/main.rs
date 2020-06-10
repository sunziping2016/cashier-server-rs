use std::error::Error;
use cashier_server::{config::Config, service};

#[actix_rt::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let config = Config::from_env()?;
    match config {
        Config::Init(init_config) => service::init::do_init(&init_config).await?,
        Config::Start(start_config) => service::start::do_start(&start_config).await?,
    }
    Ok(())
}