use alloy::hex;
use alloy::primitives::utils::parse_units;
use alloy::primitives::{keccak256, Address, TxHash, U256};
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::rpc::types::Transaction;

use alloy_sol_types::sol_data::{Array, Bool, Uint};
use alloy_sol_types::{SolType, SolValue};
use chrono::{Duration, Utc};
use std::error::Error;
use std::io::Read;
use std::str::FromStr;

use futures_util::StreamExt;

use crate::bot::transactions::process_tx;
use crate::services::mev_bundler::MevBundler;
use crate::utils::contract_utils::get_pair_address;
use crate::utils::dex_addresses::{UNISWAP_V2_FACTORY_ADDR, WALLET_SIGNER_ADDRESS};
use crate::utils::settings::{Settings, SETTINGS};

pub struct MEVBot {
    settings: Settings,
    mev_bundler: MevBundler,
}

impl MEVBot {
    pub fn new(settings: Settings, mev_bundler: MevBundler) -> Result<Self, Box<dyn Error>> {
        Ok(MEVBot {
            settings,
            mev_bundler,
        })
    }
    pub async fn run(&self) {
        println!("MEV Bot running...");
        if let Err(e) = self.listen_pending_transactions().await {
            eprintln!("Error in transaction listener: {:?}", e);
        }
    }

    async fn listen_pending_transactions(&self) -> Result<(), Box<dyn Error>> {
        let ws_rpc_url = self.settings.ws_provider.clone();
        let ws = WsConnect::new(ws_rpc_url);
        let ws_provider = ProviderBuilder::new().on_ws(ws).await?;

        let http_rpc_url = self.settings.https_provider.clone().parse()?;
        let http_provider = ProviderBuilder::new().on_http(http_rpc_url);
        println!("Awaiting pending transactions...");

        let sub = ws_provider.subscribe_pending_transactions().await?;

        let mut stream = sub.into_stream();

        let http_provider = http_provider.clone();

        let handle = tokio::spawn(async move {
            while let Some(tx_hash) = stream.next().await {
                let http_provider = http_provider.clone();
                if let Ok(tx) = process_tx(http_provider, tx_hash).await {}
            }
        });

        handle.await?;

        Ok(())
    }
}
