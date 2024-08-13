use std::{error::Error, sync::Arc};

// use types::FlashbotClientType;

use alloy::{
    consensus::{TxEip1559, TxEnvelope},
    eips::BlockNumberOrTag,
    network::{eip2718::Encodable2718, Ethereum, EthereumWallet, TransactionBuilder, TxSignerSync},
    primitives::{Bytes, B256, U256, U64},
    providers::{
        fillers::{ChainIdFiller, FillProvider, GasFiller, JoinFill, NonceFiller, WalletFiller},
        Identity, Provider, ProviderBuilder, RootProvider,
    },
    rpc::types::{
        mev::{
            BundleItem, EthCallBundle, EthCallBundleResponse, EthSendBundle, Inclusion,
            SendBundleRequest, SendBundleResponse, SimBundleOverrides,
        },
        TransactionRequest,
    },
    signers::{local::PrivateKeySigner, Signature},
    transports::{
        http::{Client, Http},
        TransportResult,
    },
};
use alloy_mev::{BundleSigner, Endpoints, EthMevProviderExt, MevShareProviderExt};

use crate::utils::settings::SETTINGS;

type BundlerProvider = FillProvider<
    JoinFill<
        JoinFill<JoinFill<JoinFill<Identity, GasFiller>, NonceFiller>, ChainIdFiller>,
        WalletFiller<EthereumWallet>,
    >,
    RootProvider<Http<Client>>,
    Http<Client>,
    Ethereum,
>;

pub struct MevBundler {
    pub provider: BundlerProvider,
    pub endpoints: Endpoints,
    pub signer: PrivateKeySigner,
    pub wallet: EthereumWallet,
}

impl MevBundler {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        // let signing_key: B256 = SETTINGS.wallet_signer_private_key.clone().parse().unwrap();
        // let signer = PrivateKeySigner::from_bytes(&signing_key).unwrap();
        let rpc_url = SETTINGS.https_provider.clone();
        let signer = PrivateKeySigner::random();
        let wallet = EthereumWallet::new(signer.clone());


        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .wallet(wallet.clone())
            .on_http(rpc_url.parse().expect("Invalid RPC URL"));

        

        let endpoints = provider
            .endpoints_builder()
            // .beaverbuild()
            .flashbots(BundleSigner::flashbots(signer.clone()))
            // .titan(BundleSigner::flashbots(signer.clone()))
            // .rsync()
            .build();

        Ok(Self {
            provider,
            endpoints,
            signer,
            wallet,
        })
    }

    pub async fn create_eth_call_bundle(
        &self,
        txs: Vec<Bytes>,
    ) -> Result<EthCallBundle, Box<dyn Error>> {
        let block_number = self.provider.get_block_number().await? + 1;

        let bundle: EthCallBundle = EthCallBundle {
            txs,
            block_number,
            state_block_number: BlockNumberOrTag::Number(block_number - 1),
            ..Default::default()
        };

        Ok(bundle)
    }

    pub async fn create_eth_send_bundle(
        &self,
        txs: Vec<Bytes>,
    ) -> Result<EthSendBundle, Box<dyn Error>> {
        let block_number = self.provider.get_block_number().await? + 1;

        let bundle: EthSendBundle = EthSendBundle {
            txs,
            block_number,
            ..Default::default()
        };

        Ok(bundle)
    }

    pub async fn call_eth_bundle(
        &self,
        txs: Vec<Bytes>,
    ) -> Vec<TransportResult<EthCallBundleResponse>> {
        match self.create_eth_call_bundle(txs).await {
            Ok(bundle) => self.provider.call_eth_bundle(bundle, &self.endpoints).await,
            Err(e) => {
                println!("Error creating bundle: {}", e);
                vec![]
            }
        }
    }

    pub async fn send_eth_bundle(
        &self,
        txs: Vec<Bytes>,
    ) -> Vec<TransportResult<SendBundleResponse>> {
        match self.create_eth_send_bundle(txs).await {
            Ok(bundle) => self.provider.send_eth_bundle(bundle, &self.endpoints).await,
            Err(e) => {
                println!("Error creating bundle: {}", e);
                vec![]
            }
        }
    }
}
mod tests {

    use super::*;
    use crate::utils::helpers::load_dotenv;
    use alloy::primitives::Address;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_new_mev_bundler() {
        load_dotenv();
        let mev_bundler = MevBundler::new();
        assert!(mev_bundler.is_ok());
        let mev_bundler = mev_bundler.unwrap();
        assert_eq!(
            mev_bundler.signer.address(),
            Address::from_str(&SETTINGS.wallet_signer_address).unwrap()
        );
    }
}
