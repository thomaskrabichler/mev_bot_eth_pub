use alloy::{
    consensus::{SignableTransaction, TxEip1559},
    dyn_abi::DynSolValue,
    network::{Ethereum, EthereumWallet, NetworkWallet, TransactionBuilder, TxSignerSync},
    node_bindings::Anvil,
    primitives::{Address, Bytes, TxKind, B256, U128, U256, U64},
    providers::{Provider, RootProvider},
    rpc::types::{TransactionReceipt, TransactionRequest},
    signers::local::PrivateKeySigner,
    sol,
    transports::http::{Client, Http},
};
use alloy_contract::{ContractInstance, Interface};
use serde::Serialize;

use crate::utils::{abis::UNISWAP_V2_ABI, dex_addresses::UNISWAP_V2_ADDR, settings::SETTINGS};
use std::str::FromStr;

use super::contract_utils::TransactionRequestParams;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IUniswapV2Router02,
    "src/abis/iuniswap_v2_abi.json"
);

pub async fn get_swap_exact_tokens_for_eth_tx_request(
    first_amount_out: U256,
    third_amount_out: U256,
    path: Vec<Address>,
    signer_addr: Address,
    deadline: u128,
    params: TransactionRequestParams,
    http_provider: &RootProvider<Http<Client>>,
) -> TxEip1559 {
    let contract = IUniswapV2Router02::new(*UNISWAP_V2_ADDR, http_provider);

    let deadline = U256::from(deadline);

    let tx_request = contract
        .swapExactTokensForETH(
            first_amount_out,
            third_amount_out,
            path,
            signer_addr,
            deadline,
        )
        .into_transaction_request();

    let nonce = http_provider
        .get_transaction_count(signer_addr)
        .await
        .unwrap();
    let to_addr = TxKind::from(Address::from_str(&SETTINGS.uniswap_v2_addr).unwrap());

    let input_bytes = tx_request.input.input.clone().unwrap();

    TxEip1559 {
        nonce,

        to: to_addr,
        gas_limit: params.gas_limit,
        chain_id: params.chain_id,
        max_priority_fee_per_gas: params.max_priority_fee_per_gas,
        max_fee_per_gas: params.max_fee_per_gas,
        input: input_bytes,
        value: U256::from(0),
        ..Default::default()
    }
}
pub async fn get_swap_exact_eth_for_tokens_tx_request(
    first_amount_out: U256,
    path: Vec<Address>,
    signer_addr: Address,
    deadline: u128,
    params: TransactionRequestParams,
    http_provider: &RootProvider<Http<Client>>,
) -> TxEip1559 {
    let contract = IUniswapV2Router02::new(*UNISWAP_V2_ADDR, http_provider);

    let deadline = U256::from(deadline);

    let tx_request = contract
        .swapExactETHForTokens(first_amount_out, path, signer_addr, deadline)
        .into_transaction_request();

    let nonce = http_provider
        .get_transaction_count(signer_addr)
        .await
        .unwrap();

    let input_bytes = tx_request.input.input.clone().unwrap();

    let to_addr = TxKind::from(Address::from_str(&SETTINGS.uniswap_v2_addr).unwrap());

    TxEip1559 {
        nonce,
        gas_limit: params.gas_limit,
        chain_id: params.chain_id,
        to: to_addr,
        max_priority_fee_per_gas: params.max_priority_fee_per_gas,
        max_fee_per_gas: params.max_fee_per_gas,
        value: params.value,
        input: input_bytes,
        ..Default::default()
    }
}

pub async fn sign_send_raw_swap_eth_for_tokens(
    first_amount_out: U256,
    path: Vec<Address>,
    signer_addr: Address,
    deadline: u128,
    params: TransactionRequestParams,
    http_provider: &RootProvider<Http<Client>>,
) {
    let tx_request = get_swap_exact_eth_for_tokens_tx_request(
        first_amount_out,
        path,
        signer_addr,
        deadline,
        params,
        http_provider,
    )
    .await;
    println!("Transaction Request: {:?}", tx_request);

    let nonce = http_provider
        .get_transaction_count(Address::from_str(&SETTINGS.wallet_signer_address.clone()).unwrap())
        .await
        .unwrap();

    let private_key = SETTINGS.wallet_signer_private_key.clone();

    let receipt = sign_send_transaction(private_key, tx_request, http_provider.clone()).await;
    println!("Receipt: {:?}", receipt);
}

pub async fn sign_send_transaction(
    signer_private_key_str: String,
    tx_request: TxEip1559,
    provider: RootProvider<Http<Client>>,
) -> TransactionReceipt {
    let private_key = signer_private_key_str.strip_prefix("0x").unwrap();

    let signing_key: B256 = private_key.parse().unwrap();
    let signer: PrivateKeySigner = PrivateKeySigner::from_bytes(&signing_key).unwrap();

    let wallet = EthereumWallet::from(signer);
    println!("Transaction Request: {:?}", tx_request.to);
    let tx: TransactionRequest = tx_request.into();

    let tx_envelope = tx.build(&wallet).await.unwrap();

    provider
        .send_tx_envelope(tx_envelope)
        .await
        .unwrap()
        .get_receipt()
        .await
        .unwrap()
}

mod tests {
    use alloy::{
        network::{Ethereum, EthereumWallet, TransactionBuilder},
        node_bindings::Anvil,
        primitives::{utils::parse_units, Address, TxHash, U256},
        providers::{Provider, ProviderBuilder},
        rpc::types::TransactionRequest,
        signers::local::PrivateKeySigner,
        sol,
        transports::http::{Client, Http},
    };
    use alloy_contract::{ContractInstance, Interface};
    use chrono::{Duration, Utc};
    use std::str::FromStr;

    use crate::{
        bot::{
            numbers::FrontrunSwapData,
            transactions::{get_amount_out, update_reserves_backrun},
        },
        utils::{
            self,
            abis::ERC20_ABI,
            contract_utils::{get_pair_address, get_pair_reserves},
            dex_addresses::{UNISWAP_V2_ADDR, UNISWAP_V2_ERC20_ADDR, UNISWAP_V2_FACTORY_ADDR},
            erc20::get_approve_erc20_tx_request,
            helpers::{
                format_token_amount_18, format_wei_to_eth, get_valid_timestamp,
                read_ith_object_from_json,
            },
            settings::SETTINGS,
            uniswap_alloy::TransactionRequestParams,
        },
    };

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        IERC20BAR,
        "src/abis/bar_pair_abi.json"
    );

    sol!(
        #[allow(missing_docs)]
        #[sol(rpc)]
        IERC20WETH,
        "src/abis/weth_abi.json"
    );

    #[tokio::test]
    async fn test_sign_send_swap_exact_tokens_for_eth() {
        utils::helpers::load_dotenv();
        println!("Running get_swap_eth_for_exact_tokens_tx_request");
        let rpc_url = "http://127.0.0.1:8545/".parse().unwrap();

        let provider = ProviderBuilder::new().on_http(rpc_url);
        let token_addr = Address::from_str(&SETTINGS.test_token_bar_addr).unwrap();
        let weth_addr = Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();

        let buy_amount_in = parse_units("1", "eth").unwrap().get_absolute();

        let weth_reserve = U256::from_str("1176004620145296002628").unwrap();
        let token_reserve = U256::from_str("714769051582874").unwrap();

        let first_amount_out = U256::from_str("605513475355").unwrap();

        // second amount out
        let victim_token_amount = U256::from_str("302857141733").unwrap();

        let (updated_reserve_weth, updated_reserve_token) = update_reserves_backrun(
            buy_amount_in,
            weth_reserve,
            token_reserve,
            victim_token_amount,
        );

        //backrun profit
        let third_amount_out = get_amount_out(
            first_amount_out,
            updated_reserve_token,
            updated_reserve_weth,
        )
        .unwrap();
        println!("Third Amount Out: {:?}", third_amount_out);
        println!("First Amount Out: {:?}", first_amount_out);

        let swap_path = vec![weth_addr, token_addr];
        let deadline = get_valid_timestamp(15 * 60 * 1000);
        let signer_addr = Address::from_str(&SETTINGS.wallet_signer_address).unwrap();
        let chain_id = SETTINGS.chain_id.clone();

        let tx_request = utils::uniswap_alloy::get_swap_exact_tokens_for_eth_tx_request(
            first_amount_out,
            third_amount_out,
            swap_path,
            signer_addr,
            deadline,
            TransactionRequestParams {
                from: None,
                to: signer_addr,
                gas: Some(U256::from(300000)),
                gas_price: None,
                gas_limit: 300000,
                value: buy_amount_in,
                chain_id: 1,
                transaction_type: 2,
                max_fee_per_gas: 20_000_000_000,
                max_priority_fee_per_gas: 1_000_000_000,
            },
            &provider,
        )
        .await;

        let receipt = utils::uniswap_alloy::sign_send_transaction(
            SETTINGS.wallet_signer_private_key.clone(),
            tx_request.clone(),
            provider.clone(),
        )
        .await;
        println!("Receipt: {:?}", receipt);

        // todo check balance before and after

        assert_eq!(tx_request.value, buy_amount_in, "Unexpected 'value' field");
        assert_eq!(
            tx_request.max_fee_per_gas, 20_000_000_000,
            "Unexpected 'max_fee_per_gas'"
        );
        assert_eq!(
            tx_request.max_priority_fee_per_gas, 1_000_000_000,
            "Unexpected 'max_priority_fee_per_gas'"
        );
        println!("Transaction Request: {:?}", tx_request);
    }
    #[tokio::test]
    async fn test_get_swap_exact_eth_for_tokens_tx_request() {
        utils::helpers::load_dotenv();
        println!("Running test_swap_exact_eth_for_tokens_frontrun");
        let rpc_url = "http://127.0.0.1:8545/".parse().unwrap();

        let provider = ProviderBuilder::new().on_http(rpc_url);
        let token_addr = Address::from_str(&SETTINGS.test_token_bar_addr).unwrap();
        let weth_addr = Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();

        let buy_amount_in = parse_units("1", "eth").unwrap().get_absolute();

        let weth_reserve = U256::from_str("1176004620145296002628").unwrap();
        let token_reserve = U256::from_str("714769051582874").unwrap();

        let first_amount_out = U256::from_str("605513475355").unwrap();

        let victim_token_amount = U256::from_str("302857141733").unwrap();
        let swap_path = vec![weth_addr, token_addr];
        let deadline = get_valid_timestamp(15 * 60 * 1000);
        let to_addr = Address::from_str(&SETTINGS.wallet_signer_address).unwrap();
        let chain_id = SETTINGS.chain_id.clone();

        let tx_request = utils::uniswap_alloy::get_swap_exact_eth_for_tokens_tx_request(
            first_amount_out,
            swap_path,
            to_addr,
            deadline,
            TransactionRequestParams {
                from: None,
                to: to_addr,
                gas: Some(U256::from(300000)),
                gas_price: None,
                gas_limit: 300000,
                value: buy_amount_in,
                chain_id: 1,
                transaction_type: 2,
                max_fee_per_gas: 20_000_000_000,
                max_priority_fee_per_gas: 1_000_000_000,
            },
            &provider,
        )
        .await;

        //todo: add additional asserts. eg get_token_balance and compare if the correct amount was sent
        assert_eq!(tx_request.value, buy_amount_in, "Unexpected 'value' field");
        assert_eq!(
            tx_request.max_fee_per_gas, 20_000_000_000,
            "Unexpected 'max_fee_per_gas'"
        );
        assert_eq!(
            tx_request.max_priority_fee_per_gas, 1_000_000_000,
            "Unexpected 'max_priority_fee_per_gas'"
        );
    }
    #[tokio::test]
    async fn test_sign_send_raw_swap_eth_for_tokens() {
        utils::helpers::load_dotenv();
        println!("Running test_swap_exact_eth_for_tokens_frontrun");
        let rpc_url = "http://127.0.0.1:8545/".parse().unwrap();

        let provider = ProviderBuilder::new().on_http(rpc_url);

        let weth_addr = Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();

        let token_addr = Address::from_str(&SETTINGS.test_token_bar_addr).unwrap();
        let buy_amount_in = parse_units("1", "eth").unwrap().get_absolute();

        let weth_reserve = U256::from_str("1176004620145296002628").unwrap();
        let token_reserve = U256::from_str("714769051582874").unwrap();

        let first_amount_out = U256::from_str("605513475355").unwrap();

        let victim_token_amount = U256::from_str("302857141733").unwrap();
        let swap_path = vec![weth_addr, token_addr];
        // let deadline = (Utc::now() + Duration::minutes(15)).timestamp();
        let deadline = get_valid_timestamp(15 * 60 * 1000);
        let signer_addr = Address::from_str(&SETTINGS.wallet_signer_address).unwrap();
        let pair = get_pair_address(
            weth_addr,
            token_addr,
            Address::from_str(&SETTINGS.uniswap_v2_factory_addr).unwrap(),
        );
        let pair_reserve_before = get_pair_reserves(pair, provider.clone()).await;
        println!("Pair Reserves Before: {:?}", pair_reserve_before);

        let data = utils::uniswap_alloy::sign_send_raw_swap_eth_for_tokens(
            first_amount_out,
            swap_path,
            signer_addr,
            deadline,
            TransactionRequestParams {
                from: None,
                to: signer_addr,
                gas: Some(U256::from(300000)),
                gas_price: None,
                gas_limit: 300000,
                value: buy_amount_in,
                chain_id: 1,
                transaction_type: 2,
                max_fee_per_gas: 20_000_000_000,
                max_priority_fee_per_gas: 1_000_000_000,
            },
            &provider,
        )
        .await;
        let pair_reserve_after = get_pair_reserves(pair, provider.clone()).await;
        println!("Pair Reserves After {:?}", pair_reserve_after);
    }

    #[tokio::test]
    async fn test_get_balance() {
        utils::helpers::load_dotenv();
        let rpc_url = "http://127.0.0.1:8545/".parse().unwrap();
        let provider = ProviderBuilder::new().on_http(rpc_url);

        let addr = Address::from_str(&SETTINGS.victim_signer_address).unwrap();

        let balance = provider.get_balance(addr);
        println!("Balance: {:?}", balance.await);
    }

    #[tokio::test]
    async fn test_get_token_balance() {
        utils::helpers::load_dotenv();
        let rpc_url = "http://127.0.0.1:8545/".parse().unwrap();
        let provider = ProviderBuilder::new().on_http(rpc_url);

        let account_addr = Address::from_str(&SETTINGS.victim_signer_address.clone()).unwrap();
        let token_addr = Address::from_str(&SETTINGS.test_token_dai_addr).unwrap();

        let contract = IERC20BAR::new(token_addr, provider);
        let x = contract.balanceOf(account_addr).call().await.unwrap();
        println!("Balance Token: {:?}", x._0);
        assert!(
            x._0 > U256::from(0),
            "Token Balance is zero. Make sure a Frontrun already happened before."
        );
    }
}
