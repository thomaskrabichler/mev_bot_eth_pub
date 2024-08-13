use serde_with::serde_as;
use std::{env, str::FromStr};

use alloy::{
    primitives::*,
    providers::{Provider, ProviderBuilder, RootProvider},
    rpc::types::Transaction,
    transports::http::{Client, Http},
};
use serde::{Deserialize, Serialize};

use crate::utils::{
    contract_utils::TransactionRequestParams,
    dex_addresses::UNISWAP_V2_FACTORY_ADDR,
    erc20::get_approve_erc20_tx_request,
    helpers::{format_token_amount_18, format_wei_to_eth, get_valid_timestamp},
    settings::SETTINGS,
    uniswap_alloy::{
        get_swap_exact_eth_for_tokens_tx_request, get_swap_exact_tokens_for_eth_tx_request,
        sign_send_transaction,
    },
};

use super::uniswap_decoder::UniswapV2Swap;

#[serde_as]
#[derive(Serialize, Deserialize, Clone)]
pub struct FrontrunSwapData {
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub victim_amount_in_eth: U256,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub attacker_amount_in_eth: U256,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub min_amount_out_tokens: U256,
    pub token_addr: Address,
    pub pair_addr: Address,
    pub weth_addr: Address,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub initial_reserve_weth: U256,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub initial_reserve_token: U256,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub optimized_amount_in_eth: U256,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub optimized_amount_out_tokens: U256,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub final_reserve_weth: U256,
    #[serde_as(as = "serde_with::DisplayFromStr")]
    pub final_reserve_token: U256,
    pub iterations: u32,
    pub execution_time_ns: u128,
    pub timestamp: u64,
}

pub async fn perform_sandwich_attack(
    tx: Transaction,
    swap: &UniswapV2Swap,
    provider: RootProvider<Http<Client>>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n");
    println!("Performing Sandwich Attack...");
    println!("\n");

    let victim_eth_in = tx.value;
    let victim_min_token_out = swap.amount_out_min;
    let token_address = swap.token_address;
    println!("Victim ETH In: {:?}", format_wei_to_eth(victim_eth_in));

    let bribe: u128 = 0;

    let base_gas_price = provider.get_gas_price().await.unwrap();
    let max_priority_fee_per_gas: u128 = 4000000000; //4 gwei
    let max_fee_per_gas = (2 * base_gas_price) + max_priority_fee_per_gas;

    let gas_limit_frontrun: u128 = 130_000u128;
    let gas_limit_approve: u128 = 60_000u128;
    let gas_limit_backrun: u128 = 150_000u128;

    let weth_address = Address::from_str(&SETTINGS.weth_addr).unwrap();
    let signer_address = Address::from_str(&SETTINGS.wallet_signer_address).unwrap();

    let victim_addr = Address::from_str(&SETTINGS.victim_signer_address).unwrap();
    let victim_private_key = &SETTINGS.victim_signer_private_key;

    let pair_address_main = crate::utils::contract_utils::get_pair_address(
        weth_address,
        token_address,
        *UNISWAP_V2_FACTORY_ADDR,
    );

    //ONLY FOR SEPOLIA TESTING
    let pair_address = match env::var("ENV") {
        Ok(env) if env == "sepolia" => Address::from_str(&SETTINGS.test_pair_addr).unwrap(),
        Ok(env) if env == "anvil" => pair_address_main,
        Ok(env) => pair_address_main,
        Err(e) => pair_address_main,
    };

    let pair_reserves =
        crate::utils::contract_utils::get_pair_reserves(pair_address, provider.clone())
            .await
            .unwrap();

    let (reserve_weth, reserve_token) = crate::bot::transactions::order_reserves(
        pair_reserves.reserve0,
        pair_reserves.reserve1,
        token_address,
        weth_address,
    );

    let frontrun_weth_amount_in = crate::utils::helpers::calculate_frontrun_amount_in(
        reserve_weth,
        reserve_token,
        victim_eth_in,
        victim_min_token_out,
        token_address,
        pair_address,
        weth_address,
    )
    .unwrap();
    println!(
        "Frontrun WETH Amount In: {}",
        format_wei_to_eth(frontrun_weth_amount_in)
    );
    let frontrun_token_out = crate::bot::transactions::get_amount_out(
        frontrun_weth_amount_in,
        reserve_weth,
        reserve_token,
    )
    .unwrap();
    println!(
        "Frontrun Token Out: {}",
        format_token_amount_18(frontrun_token_out)
    );

    let (reserve_weth_after_frontrun, reserve_token_after_frontrun) =
        crate::bot::transactions::update_reserves_frontrun(
            frontrun_weth_amount_in,
            reserve_weth,
            reserve_token,
            frontrun_token_out,
        );

    let victim_token_out = crate::bot::transactions::get_amount_out(
        victim_eth_in,
        reserve_weth_after_frontrun,
        reserve_token_after_frontrun,
    )
    .unwrap();
    println!("Victim Token Out: {}", victim_token_out);
    println!("Victim Min Tokens: {:?}", victim_min_token_out);

    if victim_token_out < victim_min_token_out {
        println!("**********************************************");
        println!("**********************************************");
        println!("**********************************************");
        println!("User would get less tokens than their minimum.");
        println!("**********************************************");
        println!("**********************************************");
        println!("**********************************************");
        // panic!();
        return Ok(());
    }

    let (reserve_weth_after_victim_out, reserve_token_after_victim_in) =
        crate::bot::transactions::update_reserves_backrun(
            victim_eth_in,
            reserve_weth_after_frontrun,
            reserve_token_after_frontrun,
            victim_token_out,
        );

    let backrun_weth_amount_out = crate::bot::transactions::get_amount_out(
        frontrun_token_out,
        reserve_token_after_victim_in,
        reserve_weth_after_victim_out,
    )
    .unwrap();
    let backrun_token_amount_in = frontrun_token_out;

    let expected_profit_no_gas = backrun_weth_amount_out - frontrun_weth_amount_in;
    let total_gas_price = base_gas_price + max_priority_fee_per_gas;

    let gas_cost_frontrun = gas_limit_frontrun * total_gas_price;
    let gas_cost_backrun = gas_limit_backrun * total_gas_price;

    let total_gas_costs = gas_cost_frontrun + gas_cost_backrun;
    let expected_profit = expected_profit_no_gas - U256::from(total_gas_costs);
    println!(
        "expected gas cost: {:?}",
        format_wei_to_eth(U256::from(total_gas_costs))
    );

    if is_negative(expected_profit_no_gas) {
        println!(
            "Negative Profit Before Gas: {:?}",
            format_wei_to_eth(expected_profit_no_gas)
        );
        println!("Aborting Swap...");
        return Ok(());
    }

    if is_negative(expected_profit) {
        println!(
            "Negative Profit After Gas: {:?}",
            format_wei_to_eth(expected_profit)
        );
        println!("Aborting Swap...");
        return Ok(());
    }

    println!("\n");
    println!("**********************************************");
    println!("**********************************************");
    println!("*********PROFITABLE SWAP DETECTED*************");
    println!("**********************************************");
    println!("**********************************************");
    println!("\n");
    println!(
        "Profit Before Gas: {:?}",
        format_wei_to_eth(expected_profit_no_gas)
    );
    println!("Profit After Gas: {:?}", format_wei_to_eth(expected_profit));

    // *********************** Proceed Only if Profitable ************************
    let frontrun_tx_request = get_swap_exact_eth_for_tokens_tx_request(
        frontrun_token_out,
        vec![weth_address, token_address],
        signer_address,
        get_valid_timestamp(15 * 60 * 1000),
        TransactionRequestParams {
            from: None,
            to: signer_address,
            gas: None,
            gas_price: None,
            gas_limit: gas_limit_frontrun,
            value: frontrun_weth_amount_in,
            chain_id: SETTINGS.chain_id.parse().unwrap(),
            transaction_type: 2,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        },
        &provider,
    )
    .await;
    let victim_sim_tx_request = get_swap_exact_eth_for_tokens_tx_request(
        victim_token_out,
        vec![weth_address, token_address],
        victim_addr,
        get_valid_timestamp(15 * 60 * 1000),
        TransactionRequestParams {
            from: None,
            to: victim_addr,
            gas: None,
            gas_price: None,
            gas_limit: gas_limit_frontrun,
            value: victim_eth_in,
            chain_id: SETTINGS.chain_id.parse().unwrap(),
            transaction_type: 2,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        },
        &provider,
    )
    .await;

    let balance_before = provider.get_balance(signer_address).await;
    println!(
        "Signer Balance Before: {:?}",
        format_wei_to_eth(balance_before.unwrap())
    );

    let uni_addr = Address::from_str(&SETTINGS.uniswap_v2_addr).unwrap();

    let approve_tx_request = get_approve_erc20_tx_request(
        signer_address,
        uni_addr,
        frontrun_token_out,
        TransactionRequestParams {
            from: None,
            to: uni_addr,
            gas: None,
            gas_price: None,
            gas_limit: gas_limit_approve,
            value: U256::from(0),
            chain_id: SETTINGS.chain_id.parse().unwrap(),
            transaction_type: 2,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        },
        Address::from_str(&SETTINGS.test_token_dai_addr).unwrap(),
        &provider,
    )
    .await;

    let receipt_frontrun_tx = sign_send_transaction(
        SETTINGS.wallet_signer_private_key.clone(),
        frontrun_tx_request,
        provider.clone(),
    )
    .await;

    let vicitm_tx_receipt = sign_send_transaction(
        victim_private_key.clone(),
        victim_sim_tx_request,
        provider.clone(),
    )
    .await;

    let receipt_approve = sign_send_transaction(
        SETTINGS.wallet_signer_private_key.clone(),
        approve_tx_request,
        provider.clone(),
    )
    .await;

    let backrun_tx_request = get_swap_exact_tokens_for_eth_tx_request(
        backrun_token_amount_in,
        backrun_weth_amount_out,
        vec![token_address, weth_address],
        signer_address,
        get_valid_timestamp(15 * 60 * 1000),
        TransactionRequestParams {
            from: None,
            to: signer_address,
            gas: None,
            gas_price: None,
            gas_limit: gas_limit_backrun,
            value: U256::from(0),
            chain_id: SETTINGS.chain_id.parse().unwrap(),
            transaction_type: 2,
            max_fee_per_gas,
            max_priority_fee_per_gas,
        },
        &provider,
    )
    .await;

    let receipt_backrun_tx = sign_send_transaction(
        SETTINGS.wallet_signer_private_key.clone(),
        backrun_tx_request.clone(),
        provider.clone(),
    )
    .await;

    let gas_used_backrun = receipt_backrun_tx.gas_used;
    let gas_used_frontrun = receipt_frontrun_tx.gas_used;
    let gas_used_approve = receipt_approve.gas_used;

    let gas_backrun = gas_used_backrun * (base_gas_price + max_priority_fee_per_gas);
    let gas_frontrun = gas_used_frontrun * (base_gas_price + max_priority_fee_per_gas);
    let gas_approve = gas_used_approve * (base_gas_price + max_priority_fee_per_gas);
    let total_gas_used = gas_frontrun + gas_backrun + gas_approve;
    let total_gas_used: U256 = U256::from(total_gas_used);

    let balance_after = provider.get_balance(signer_address).await;
    println!(
        "Signer Balance After: {:?}",
        format_wei_to_eth(balance_after.unwrap())
    );

    println!("Total Gas Used: {:?}", format_wei_to_eth(total_gas_used),);
    Ok(())
}

fn is_negative(value: U256) -> bool {
    value >= U256::from(1) << 255
}
