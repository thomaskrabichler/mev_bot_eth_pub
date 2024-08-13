#![allow(unused)]
extern crate mev_rodemar;

use log::error;
use mev_rodemar::{
    bot::mev_bot::MEVBot,
    services::mev_bundler::MevBundler,
    utils::{helpers::load_dotenv, settings::Settings},
};
#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        error!("Error: {}", e);
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    load_dotenv();
    env_logger::init();

    let settings = Settings::new()?;
    let mev_bundler = MevBundler::new()?;
    let bot = MEVBot::new(settings, mev_bundler)?;

    bot.run().await;

    Ok(())
}
