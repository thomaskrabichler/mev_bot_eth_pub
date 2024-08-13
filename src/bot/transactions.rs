use crate::bot::numbers::perform_sandwich_attack;
use crate::bot::uniswap_decoder::UniswapV2Swap;
use crate::utils::abis::UNISWAP_V2_ABI;
use crate::utils::dex_addresses::{
    DEX_ADDRESSES, UNISWAP_UNIVERSAL_ROUTER_ADDR, UNISWAP_V2_ADDR, UNISWAP_V2_ERC20_ADDR,
    UNISWAP_V2_FACTORY_ADDR, WALLET_SIGNER_ADDRESS,
};
use crate::utils::settings::SETTINGS;
use alloy::contract::{ContractInstance, Interface};
use alloy::dyn_abi::{DynSolValue, DynToken};
use alloy::network::Ethereum;
use alloy::primitives::utils::{parse_units, ParseUnits};
use alloy::primitives::{Address, Bytes, TxHash, U256};
use alloy::providers::{Provider, ProviderBuilder, RootProvider};
use alloy::rpc::types::Transaction;
use alloy::transports::http::{Client, Http};
use alloy_sol_types::{sol, SolValue};
use alloy_sol_types::{SolEnum, SolType};
use chrono::{Duration, Utc};
use serde_json::{json, Value};
use std::error::Error;
use std::ops::{Add, Sub};
use std::str::FromStr;
use tokio::time::sleep;

pub async fn process_tx(
    http_provider: RootProvider<Http<Client>>,
    tx_hash: TxHash,
) -> Result<(), Box<dyn Error>> {
    let tx = fetch_transaction(&http_provider, tx_hash).await?;

    if is_invalid_tx(&tx) {
        return Ok(());
    }

    let decoded_sol_function = crate::utils::contract_utils::decode_transaction_input(
        tx.to.unwrap_or_default(),
        &tx.input.0,
    );

    let decoded_tx = match decoded_sol_function {
        Some(decoded_tx) => decoded_tx,
        None => {
            return Ok(());
        }
    };
    if decoded_tx.name == "execute" {
        if let Some(commands) = decoded_tx.params.get("commands") {
            let contains_08 = commands.contains("08");
            let contains_00 = commands.contains("00");

            if !contains_08 && !contains_00 {
                return Ok(());
            }

            if contains_08 {
                let swap =
                    UniswapV2Swap::decode_universal_v2_swap_data(commands, &decoded_tx.inputs);
                println!("Universal Router Swap found");
                println!("{:#?}", swap);

                if let Some(ref swap) = swap {
                    perform_sandwich_attack(tx, swap, http_provider.clone()).await;
                } else {
                    return Ok(());
                }
            }

            if contains_00 {
                // println!("*** V3 Swap Found ***");
            }
        }
    } else if decoded_tx.name == "swapExactETHForTokens" {
        println!("SwapExactETHForTokens found");
        let swap = UniswapV2Swap::decode_v2_swap_data(decoded_tx);

        if let Some(ref swap) = swap {
            perform_sandwich_attack(tx, swap, http_provider.clone()).await;
        } else {
            println!("Swap Error");
        }

        return Ok(());
    }
    Ok(())
}
#[derive(Debug)]
struct FlashbotsTransaction {
    signer: Address,
    transaction: FrontrunTransactionData,
}

#[derive(Debug)]
struct PaymentData {
    value: U256,
    type_: U256,
    max_fee_per_gas: U256,
    max_priority_fee_per_gas: U256,
    gas_limit: U256,
}

sol! {
    struct PaymentDataSol {
        uint256 value;
        uint256 r#type;
        uint256 max_fee_per_gas;
        uint256 max_priority_fee_per_gas;
        uint256 gas_limit;
     }
}
impl From<PaymentData> for DynSolValue {
    fn from(payment_data: PaymentData) -> Self {
        DynSolValue::CustomStruct {
            name: "PaymentData".to_string(),
            prop_names: vec![
                "value".to_string(),
                "type_".to_string(),
                "max_fee_per_gas".to_string(),
                "max_priority_fee_per_gas".to_string(),
                "gas_limit".to_string(),
            ],
            tuple: vec![
                DynSolValue::Uint(payment_data.value, 256),
                DynSolValue::Uint(payment_data.type_, 256),
                DynSolValue::Uint(payment_data.max_fee_per_gas, 256),
                DynSolValue::Uint(payment_data.max_priority_fee_per_gas, 256),
                DynSolValue::Uint(payment_data.gas_limit, 256),
            ],
        }
    }
}
#[derive(Debug)]
struct FrontrunTransactionData {}

struct SignedMiddleTransaction {
    signed_tx: Value,
}
impl SignedMiddleTransaction {
    fn default() -> Self {
        todo!()
    }
}

struct SignedMiddleTransactionData {
    tx: Transaction,
    r: Bytes,
    s: Bytes,
    v: u8,
}

pub fn approve_erc20(
    first_amount_out: U256,
    uniswap_addres: Address,
    token_addr: Address,
    http_provider: RootProvider<Http<Client>>,
    payment_data: PaymentData,
    chain_id: String,
) {
    let abi = serde_json::from_str(crate::utils::abis::UNISWAP_V2_ERC20_ABI).unwrap();
    let contract: ContractInstance<Http<Client>, _, Ethereum> =
        ContractInstance::new(token_addr, http_provider, Interface::new(abi));

    let tx = contract
        .function(
            "approve",
            &[
                uniswap_addres.into(),
                first_amount_out.into(),
                payment_data.into(),
                chain_id.into(),
            ],
        )
        .unwrap();
}
sol! {
   struct Foo {
       uint256 bar;
       address[] baz;
   }
}
fn swap_exact_eth_for_tokens(
    first_amount_out: U256,
    path: Vec<Address>,
    to: Address,
    deadline: i64,
    payment_data: PaymentData,
    chain_id: String,
    http_provider: RootProvider<Http<Client>>,
) -> FrontrunTransactionData {
    let abi = serde_json::from_str(UNISWAP_V2_ABI).unwrap();
    let contract: ContractInstance<Http<Client>, _, Ethereum> =
        ContractInstance::new(*UNISWAP_V2_ADDR, http_provider, Interface::new(abi));

    let path = DynSolValue::Array(vec![
        DynSolValue::Address(path[0]),
        DynSolValue::Address(path[1]),
    ]);

    let tx = contract
        .function(
            "swapExactETHForTokens",
            &[
                first_amount_out.into(),
                path,
                to.into(),
                deadline.into(),
                payment_data.into(),
                chain_id.into(),
            ],
        )
        .unwrap();

    FrontrunTransactionData {}
}

fn swap_exact_tokens_for_eth(
    first_amount_out: U256,
    third_amount_out: U256,
    path: Vec<Address>,
    signing_wallet_address: Address,
    deadline: i64,
    payment_data: PaymentData,
    chain_id: String,
    http_provider: RootProvider<Http<Client>>,
) -> FrontrunTransactionData {
    let abi = serde_json::from_str(UNISWAP_V2_ABI).unwrap();
    let contract: ContractInstance<Http<Client>, _, Ethereum> =
        ContractInstance::new(*UNISWAP_V2_ADDR, http_provider, Interface::new(abi));

    let path = DynSolValue::Array(vec![
        DynSolValue::Address(path[1]),
        DynSolValue::Address(path[0]),
    ]);

    let tx = contract
        .function(
            "swapExactTokensForETH",
            &[
                first_amount_out.into(),
                third_amount_out.into(),
                path,
                signing_wallet_address.into(),
                deadline.into(),
                payment_data.into(),
                chain_id.into(),
            ],
        )
        .unwrap();

    FrontrunTransactionData {}
}

pub fn update_reserves_frontrun(
    buy_amount_in: U256,
    reserve_weth: U256,
    reserve_token: U256,
    first_amount_out: U256,
) -> (U256, U256) {
    let updated_reserve_weth = reserve_weth.add(buy_amount_in);
    let updated_reserve_token = reserve_token.sub(first_amount_out);

    (updated_reserve_weth, updated_reserve_token)
}

pub fn update_reserves_backrun(
    buy_amount_in: U256,
    reserve_weth: U256,
    reserve_token: U256,
    second_buy_amount: U256,
) -> (U256, U256) {
    let updated_reserve_weth = reserve_weth
        .checked_add(buy_amount_in)
        .expect("Overflow occurred while adding buy_amount_in to reserve_weth");
    let updated_reserve_token = reserve_token
        .checked_sub(
            second_buy_amount
                .checked_mul(U256::from(997))
                .expect("Overflow occurred while multiplying second_buy_amount by 997")
                .checked_div(U256::from(1000))
                .expect("Division by zero"),
        )
        .expect("Underflow occurred while subtracting second_buy_amount from reserve_token");

    (updated_reserve_weth, updated_reserve_token)
}

pub fn get_amount_out(
    amount_in: U256,
    reserve_in: U256,
    reserve_out: U256,
) -> Result<U256, &'static str> {
    if amount_in.is_zero() {
        return Err("INSUFFICIENT_INPUT_AMOUNT");
    }
    if reserve_in.is_zero() || reserve_out.is_zero() {
        return Err("INSUFFICIENT_LIQUIDITY");
    }

    let amount_in_with_fee = amount_in * U256::from(997);
    let numerator = amount_in_with_fee * reserve_out;
    let denominator = reserve_in * U256::from(1000) + amount_in_with_fee;
    let amount_out = numerator / denominator;

    Ok(amount_out)
}

pub fn order_reserves(
    reserve0: U256,
    reserve1: U256,
    token_addr: Address,
    weth_addr: Address,
) -> (U256, U256) {
    if weth_addr < token_addr {
        (reserve0, reserve1)
    } else {
        (reserve1, reserve0)
    }
}

pub fn calculate_bribe() -> U256 {
    parse_units("20", "gwei").unwrap().get_absolute()
}

pub fn calculate_max_gas_fee(tx_max_fee_per_gas: Option<u128>, bribe: U256) -> U256 {
    tx_max_fee_per_gas.map_or(bribe, |max_fee_per_gas| U256::from(max_fee_per_gas) + bribe)
}

async fn fetch_transaction(
    http_provider: &RootProvider<Http<Client>>,
    tx_hash: TxHash,
) -> Result<Transaction, Box<dyn Error>> {
    http_provider
        .get_transaction_by_hash(tx_hash)
        .await?
        .ok_or("Transaction not found".into())
}

fn is_invalid_tx(tx: &Transaction) -> bool {
    if tx.to.is_none() {
        return true;
    }

    if tx.value.is_zero() {
        return true;
    }

    if tx.input.0.is_empty() {
        return true;
    }

    if !DEX_ADDRESSES.contains(&tx.to.unwrap_or_default()) {
        return true;
    }

    let addr = Address::from_str("0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199").unwrap();

    if tx.from != addr {
        return false;
    }

    if SETTINGS.env == "sepolia" && tx.to.unwrap() != *UNISWAP_UNIVERSAL_ROUTER_ADDR {
        println!("Invalid tx addr: {:?}", tx.to.unwrap());
        return true;
    }

    false
}

#[cfg(test)]

mod tests {
    use std::collections::HashSet;
    use std::env;
    use std::ops::Deref;
    use std::str::FromStr;

    use crate::utils::abis::UNISWAP_V2_ABI;
    use crate::utils::contract_utils::{get_pair_address, get_pair_reserves};
    use crate::utils::helpers::load_dotenv;

    use super::*;
    use alloy::hex::decode;
    use alloy::primitives::{address, Address, Bytes, TxHash, Uint, U256};
    use alloy::providers::{Provider, RootProvider};
    use alloy::rpc::types::serde_helpers::OtherFields;
    use alloy::transports::http::Http;
    use once_cell::sync::Lazy;

    static VALID_ADDRESS: Lazy<Address> =
        Lazy::new(|| Address::from_str("0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD").unwrap());

    fn mock_transaction(to: Option<Address>, value: U256, input: &str) -> Transaction {
        Transaction {
            hash: TxHash::default(),
            nonce: u64::default(),
            block_hash: None,
            block_number: None,
            transaction_index: None,
            from: Address::default(),
            to,
            value,
            gas_price: None,
            gas: u128::default(),
            input: Bytes::default(),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            max_fee_per_blob_gas: None,
            signature: None,
            chain_id: None,
            blob_versioned_hashes: None,
            access_list: None,
            transaction_type: None,
            authorization_list: None,
            other: OtherFields::default(),
        }
    }


    #[test]
    fn test_invalid_tx_when_to_is_none() {
        let tx = mock_transaction(None, U256::from(100), "0x1");
        assert!(is_invalid_tx(&tx));
    }

    #[test]
    fn test_invalid_tx_when_value_is_zero() {
        let address = Address::default();
        let tx = mock_transaction(Some(address), U256::from(0), "0x1");
        assert!(is_invalid_tx(&tx));
    }

    #[test]
    fn test_order_reserves_weth_addr_greater() {
        let _reserve0 = Uint::from(1000u64);
        let _reserve1 = Uint::from(2000u64);

        // weth_addr > token_addr
        let weth_addr = Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        let token_addr = Address::from_str("0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD").unwrap();
        let (reserve0, reserve1) = order_reserves(_reserve0, _reserve1, token_addr, weth_addr);

        assert_eq!(reserve0, _reserve1);
        assert_eq!(reserve1, _reserve0);
    }
    #[test]
    fn test_order_reserves_weth_addr_smaller() {
        let _reserve0 = Uint::from(1000u64);
        let _reserve1 = Uint::from(2000u64);

        let weth_addr = Address::from_str("0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD").unwrap();
        let token_addr = Address::from_str("0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2").unwrap();
        let (reserve0, reserve1) = order_reserves(_reserve0, _reserve1, token_addr, weth_addr);

        assert_eq!(reserve0, _reserve0);
        assert_eq!(reserve1, _reserve1);
    }

    #[tokio::test]
    async fn test_get_amount_out_uniswap() {
        let amount_in = parse_units("0.5", "eth").unwrap().get_absolute();

        let reserve_weth = U256::from_str("69203101373176476454697").unwrap();
        let reserve_token = U256::from_str("44423447600381085504").unwrap();

        let http_rpc_url = "https://uk.rpc.blxrbdn.com".parse().unwrap();
        let http_provider = ProviderBuilder::new().on_http(http_rpc_url);

        let uniswap_abi = r#"[{"inputs":[{"internalType":"address","name":"_factory","type":"address"},{"internalType":"address","name":"_WETH","type":"address"}],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[],"name":"WETH","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"tokenA","type":"address"},{"internalType":"address","name":"tokenB","type":"address"},{"internalType":"uint256","name":"amountADesired","type":"uint256"},{"internalType":"uint256","name":"amountBDesired","type":"uint256"},{"internalType":"uint256","name":"amountAMin","type":"uint256"},{"internalType":"uint256","name":"amountBMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"addLiquidity","outputs":[{"internalType":"uint256","name":"amountA","type":"uint256"},{"internalType":"uint256","name":"amountB","type":"uint256"},{"internalType":"uint256","name":"liquidity","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"amountTokenDesired","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"addLiquidityETH","outputs":[{"internalType":"uint256","name":"amountToken","type":"uint256"},{"internalType":"uint256","name":"amountETH","type":"uint256"},{"internalType":"uint256","name":"liquidity","type":"uint256"}],"stateMutability":"payable","type":"function"},{"inputs":[],"name":"factory","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"uint256","name":"reserveIn","type":"uint256"},{"internalType":"uint256","name":"reserveOut","type":"uint256"}],"name":"getAmountIn","outputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"reserveIn","type":"uint256"},{"internalType":"uint256","name":"reserveOut","type":"uint256"}],"name":"getAmountOut","outputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"}],"name":"getAmountsIn","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"}],"name":"getAmountsOut","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountA","type":"uint256"},{"internalType":"uint256","name":"reserveA","type":"uint256"},{"internalType":"uint256","name":"reserveB","type":"uint256"}],"name":"quote","outputs":[{"internalType":"uint256","name":"amountB","type":"uint256"}],"stateMutability":"pure","type":"function"},{"inputs":[{"internalType":"address","name":"tokenA","type":"address"},{"internalType":"address","name":"tokenB","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountAMin","type":"uint256"},{"internalType":"uint256","name":"amountBMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"removeLiquidity","outputs":[{"internalType":"uint256","name":"amountA","type":"uint256"},{"internalType":"uint256","name":"amountB","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"removeLiquidityETH","outputs":[{"internalType":"uint256","name":"amountToken","type":"uint256"},{"internalType":"uint256","name":"amountETH","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"removeLiquidityETHSupportingFeeOnTransferTokens","outputs":[{"internalType":"uint256","name":"amountETH","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"bool","name":"approveMax","type":"bool"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"removeLiquidityETHWithPermit","outputs":[{"internalType":"uint256","name":"amountToken","type":"uint256"},{"internalType":"uint256","name":"amountETH","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"token","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountTokenMin","type":"uint256"},{"internalType":"uint256","name":"amountETHMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"bool","name":"approveMax","type":"bool"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"removeLiquidityETHWithPermitSupportingFeeOnTransferTokens","outputs":[{"internalType":"uint256","name":"amountETH","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"tokenA","type":"address"},{"internalType":"address","name":"tokenB","type":"address"},{"internalType":"uint256","name":"liquidity","type":"uint256"},{"internalType":"uint256","name":"amountAMin","type":"uint256"},{"internalType":"uint256","name":"amountBMin","type":"uint256"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"bool","name":"approveMax","type":"bool"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"removeLiquidityWithPermit","outputs":[{"internalType":"uint256","name":"amountA","type":"uint256"},{"internalType":"uint256","name":"amountB","type":"uint256"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapETHForExactTokens","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactETHForTokens","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactETHForTokensSupportingFeeOnTransferTokens","outputs":[],"stateMutability":"payable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForETH","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForETHSupportingFeeOnTransferTokens","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForTokens","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountIn","type":"uint256"},{"internalType":"uint256","name":"amountOutMin","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapExactTokensForTokensSupportingFeeOnTransferTokens","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"uint256","name":"amountInMax","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapTokensForExactETH","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"amountOut","type":"uint256"},{"internalType":"uint256","name":"amountInMax","type":"uint256"},{"internalType":"address[]","name":"path","type":"address[]"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"deadline","type":"uint256"}],"name":"swapTokensForExactTokens","outputs":[{"internalType":"uint256[]","name":"amounts","type":"uint256[]"}],"stateMutability":"nonpayable","type":"function"},{"stateMutability":"payable","type":"receive"}]"#;
        let address = Address::from_str("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap();

        let abi = serde_json::from_str(uniswap_abi).unwrap();
        let contract: ContractInstance<Http<Client>, _, Ethereum> =
            ContractInstance::new(address, http_provider.clone(), Interface::new(abi));
        let amount_out_uni = contract
            .function(
                "getAmountOut",
                &[amount_in.into(), reserve_weth.into(), reserve_token.into()],
            )
            .unwrap()
            .call()
            .await
            .unwrap();

        let amount_out_local = get_amount_out(amount_in, reserve_weth, reserve_token).unwrap();
        assert_eq!(amount_out_uni[0], amount_out_local.into());
    }

    #[test]
    fn test_update_reserves_frontrun() {
        let buy_amount_in = parse_units("1", "eth").unwrap().get_absolute();
        let reserve_weth = U256::from_str("10000000000000000000000").unwrap();
        let reserve_token = U256::from_str("1000000000000000000000000").unwrap();

        let first_amount_out = get_amount_out(buy_amount_in, reserve_weth, reserve_token).unwrap();

        let (updated_reserve_weth, updated_reserve_token) =
            update_reserves_frontrun(buy_amount_in, reserve_weth, reserve_token, first_amount_out);

        println!("Updated Reserve Weth: {:?}", updated_reserve_weth);
        println!("Updated Reserve Token: {:?}", updated_reserve_token);

        assert_eq!(updated_reserve_weth, reserve_weth + buy_amount_in);
        assert_eq!(updated_reserve_token, reserve_token - first_amount_out);
    }
}
