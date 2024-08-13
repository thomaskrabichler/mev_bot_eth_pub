use config::{Config, ConfigError, Environment};
use dotenv::dotenv;
use once_cell::sync::Lazy;
use serde_derive::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Settings {
    pub https_provider: String,
    pub ws_provider: String,
    pub flashbots_relay: String,
    pub wallet_signer_address: String,
    pub wallet_signer_private_key: String,
    pub bundle_signer_address: String,
    pub bundle_signer_private_key: String,
    pub victim_signer_address: String,
    pub victim_signer_private_key: String,
    pub weth_addr: String,
    pub uniswap_universal_router_addr: String,
    pub uniswap_v2_addr: String,
    pub uniswap_v2_factory_addr: String,
    pub uniswap_v2_erc20_addr: String,
    pub uniswap_v3_factory_addr: String,
    pub uniswap_v3_addr: String,
    pub chain_id: String,
    pub test_token_bar_addr: String,
    pub test_token_dai_addr: String,
    pub test_pair_addr: String,
    pub env: String,
}


impl Settings {
    pub fn new() -> Result<Self, ConfigError> {
        dotenv().ok();
        let s = Config::builder()
            .add_source(Environment::default())
            .build()?;
        s.try_deserialize()
    }
}

pub static SETTINGS: Lazy<Settings> =
    Lazy::new(|| Settings::new().expect("Failed to load settings"));

mod tests {

    #[test]
    fn test_load_env() {}
}
