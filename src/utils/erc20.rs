use std::str::FromStr;

use alloy::{
    consensus::TxEip1559,
    network::{EthereumWallet, TransactionBuilder},
    primitives::{Address, B256, U256},
    providers::{Provider, RootProvider},
    rpc::types::{TransactionReceipt, TransactionRequest},
    signers::local::PrivateKeySigner,
    transports::http::{Client, Http},
};
use alloy_sol_macro::sol;

use crate::utils::settings::SETTINGS;

use super::{contract_utils::TransactionRequestParams, dex_addresses::UNISWAP_V2_ERC20_ADDR};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IERC20,
    "src/abis/erc_20_abi.json",
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IBAR,
    "src/abis/bar_pair_abi.json",
);
pub async fn get_approve_erc20_tx_request(
    signer: Address,
    spender: Address, //uniswap address
    amount: U256,     //first amount out
    params: TransactionRequestParams,
    token_addr: Address,
    provider: &RootProvider<Http<Client>>,
) -> TxEip1559 {
    // TODO: works when account is spender, but this way we pay gas. its possible to approve
    // without spending gas.
    let contract = IERC20::new(token_addr, provider);
    let tx_request = contract.approve(spender, amount).into_transaction_request();

    let input_bytes = tx_request.input.input.clone().unwrap();
    //todo calc locally
    let nonce = provider.get_transaction_count(signer).await.unwrap();

    // let tx_request: TransactionRequest = tx_request
    //     .with_nonce(nonce + 1)
    //     .with_from(signer)
    //     .with_gas_limit(params.gas_limit)
    //     .with_chain_id(params.chain_id)
    //     .value(U256::from(0)) // 0?
    //     .with_input(input_bytes)
    //     .transaction_type(params.transaction_type)
    //     .with_max_priority_fee_per_gas(params.max_priority_fee_per_gas)
    //     .with_max_fee_per_gas(params.max_fee_per_gas);

    // let to_addr =;
    TxEip1559 {
        nonce: nonce + 1,
        to: tx_request.to.unwrap(),
        // from:from(signer)
        gas_limit: params.gas_limit,
        chain_id: params.chain_id,
        value: U256::from(0),
        input: input_bytes,
        max_priority_fee_per_gas: params.max_priority_fee_per_gas,
        max_fee_per_gas: params.max_fee_per_gas,
        ..Default::default()
    }
}

mod tests {
    use alloy::{primitives::utils::parse_units, providers::ProviderBuilder};

    use crate::utils::{self, helpers::get_valid_timestamp, settings::SETTINGS};

    use super::*;
    use std::str::FromStr;

    #[tokio::test]
    async fn test_approve_erc20_tx_request() {
        utils::helpers::load_dotenv();

        let rpc_url = "http://127.0.0.1:8545/".parse().unwrap();
        let provider = ProviderBuilder::new().on_http(rpc_url);

        let token_addr = Address::from_str("0x777BE1c6075c20184C4fd76344b7b0B7c858fe6B").unwrap();
        let first_amount_out = U256::from_str("605513475355").unwrap();
        let to_addr = Address::from_str(&SETTINGS.uniswap_v2_addr).unwrap();

        let signer = Address::from_str(&SETTINGS.wallet_signer_address).unwrap();
        let tx_req_params = TransactionRequestParams {
            from: None,
            to: to_addr,
            gas: Some(U256::from(300000)),
            gas_price: None,
            gas_limit: 300000,
            value: U256::from(0),
            chain_id: 1,
            transaction_type: 2,
            max_fee_per_gas: 20_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
        };
        let token_addr = Address::from_str("0x2e6a60492fb5b58f5b5d08c7cafc75e740e6dc8e").unwrap();
        let approve_result = get_approve_erc20_tx_request(
            signer,
            to_addr,
            first_amount_out,
            tx_req_params,
            token_addr,
            &provider,
        )
        .await;

        let tx_request = approve_result;

        let erc20_approve_receipt = utils::uniswap_alloy::sign_send_transaction(
            SETTINGS.wallet_signer_private_key.clone(),
            tx_request.clone(),
            provider.clone(),
        );
        // match approve_result {
        //     Ok((tx_request, receipt)) => {
        //
        //         if let Some(receipt) = receipt {
        //             assert!(receipt.status(), "Approval is false. Failed?");
        //         }
        //     }
        //     Err(e) => {
        //         println!("Error: {:?}", e);
        //         panic!();
        //     }
        // }
    }
}
