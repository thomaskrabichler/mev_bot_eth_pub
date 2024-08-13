use std::collections::HashMap;
use std::env;
use std::error::Error;
use std::str::FromStr;

use alloy::contract::{ContractInstance, Interface};
use alloy::dyn_abi::DynSolValue;
use alloy::hex;
use alloy::network::Ethereum;
use alloy::primitives::{keccak256, Address, Uint, U256};
use alloy::providers::RootProvider;
use alloy::transports::http::{Client, Http};
use alloy_sol_types::sol_data::{Array, Bool};
use alloy_sol_types::{SolType, SolValue};

use crate::utils::dex_addresses::UNISWAP_V2_FACTORY_ADDR;

use alloy::{primitives::bytes::Bytes, sol, sol_types::SolCall};
use once_cell::sync::Lazy;

use crate::utils::dex_addresses::{UNISWAP_UNIVERSAL_ROUTER_ADDR, UNISWAP_V2_ADDR};

use super::abis::{UNISWAP_V2_PAIR_ABI, UNISWAP_V2_PAIR_ABI_SEPOLIA};
use super::settings::SETTINGS;

#[derive(Debug)]
pub struct Reserves {
    pub reserve0: U256,
    pub reserve1: U256,
    pub exchange_rate_numerator: U256,
    pub exchange_rate_denominator: U256,
    pub exchange_rate: U256,
    pub block_timestamp_last: U256,
}

#[derive(Debug)]
pub struct TransactionRequestParams {
    pub from: Option<Address>,
    pub to: Address,
    pub gas: Option<U256>,
    pub gas_price: Option<U256>,
    pub gas_limit: u128,
    pub value: U256,
    pub chain_id: u64,
    pub transaction_type: u8,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

pub fn get_pair_address(token0: Address, token1: Address, factory: Address) -> Address {
    let (token0, token1) = if token0 < token1 {
        (token0, token1)
    } else {
        (token1, token0)
    };

    type PairSolType1 = (
        alloy_sol_types::sol_data::Address,
        alloy_sol_types::sol_data::Address,
    );

    let mut encoded_1 = PairSolType1::abi_encode_packed(&(token0, token1));

    let salt = keccak256(encoded_1);

    type PairSolType2 = (
        alloy_sol_types::sol_data::Address,
        alloy_sol_types::sol_data::Bytes,
    );

    let encoded_2 = PairSolType2::abi_encode_packed(&(factory, salt));

    let hexadem: Vec<u8> = vec![
        150, 232, 172, 66, 119, 25, 143, 248, 182, 247, 133, 71, 138, 169, 163, 159, 64, 60, 183,
        104, 221, 2, 203, 238, 50, 108, 62, 125, 163, 72, 132, 95,
    ];

    let mut final_buffer = Vec::new();
    final_buffer.push(0xff);
    final_buffer.extend_from_slice(&encoded_2);
    final_buffer.extend_from_slice(&hexadem);

    let create2_hash = keccak256(&final_buffer);

    let address_bytes = &create2_hash[12..];

    Address::from_slice(address_bytes)
}

pub async fn get_pair_reserves(
    address: Address,
    http_provider: RootProvider<Http<Client>>,
) -> Result<Reserves, Box<dyn Error>> {
    let abi_str = UNISWAP_V2_PAIR_ABI;
    // let abi_str = match env::var("ENV") {
    //     Ok(env) if env == "sepolia" => UNISWAP_V2_PAIR_ABI_SEPOLIA,
    //     Ok(env) if env == "anvil" => UNISWAP_V2_PAIR_ABI,
    //     Ok(env) => UNISWAP_V2_PAIR_ABI,
    //     Err(e) => UNISWAP_V2_PAIR_ABI,
    // };
    let abi = serde_json::from_str(abi_str).unwrap();

    let contract: ContractInstance<Http<Client>, _, Ethereum> =
        ContractInstance::new(address, http_provider.clone(), Interface::new(abi));

    let reserves = contract.function("getReserves", &[])?.call().await?;

    let (reserve0, _) = reserves[0].as_uint().unwrap();
    let (reserve1, _) = reserves[1].as_uint().unwrap();
    let (block_timestamp_last, _) = reserves[2].as_uint().unwrap();

    let (exchange_rate_numerator, exchange_rate_denominator) = (reserve1, reserve0);
    let exchange_rate = reserve1 / reserve0;

    Ok(Reserves {
        reserve0,
        reserve1,
        block_timestamp_last,
        exchange_rate_numerator,
        exchange_rate_denominator,
        exchange_rate,
    })
}

pub fn get_first_amount_out() {
    todo!()
}

#[derive(Debug)]
pub struct DecodedTx {
    pub name: String,
    pub params: HashMap<String, String>,
    pub inputs: Vec<String>,
}

trait Decoder {
    fn decode(&self, data: &Bytes) -> Option<DecodedTx>;
}

struct UniswapUniversalRouterDecoder;

impl Decoder for UniswapUniversalRouterDecoder {
    fn decode(&self, data: &Bytes) -> Option<DecodedTx> {
        println!("UNI");
        if let Ok(decoded) = executeCall::abi_decode(data, false) {
            let inputs: Vec<String> = decoded
                .inputs
                .iter()
                .map(|input| format!("0x{}", hex::encode(input)))
                .collect();

            return Some(DecodedTx {
                name: "execute".to_string(),
                params: HashMap::from([("commands".to_string(), decoded.commands.to_string())]),
                inputs,
            });
        }
        None
    }
}

type DecoderFn = Box<dyn Decoder + Send + Sync>;

static DEX_DECODERS: Lazy<HashMap<Address, DecoderFn>> = Lazy::new(|| {
    let mut decoders = HashMap::new();
    decoders.insert(*UNISWAP_V2_ADDR, Box::new(UniswapV2Decoder) as DecoderFn);
    decoders.insert(
        *UNISWAP_UNIVERSAL_ROUTER_ADDR,
        Box::new(UniswapUniversalRouterDecoder) as DecoderFn,
    );
    decoders
});

pub fn decode_transaction_input(address: Address, data: &Bytes) -> Option<DecodedTx> {
    println!("Decoding transaction input for address: {:?}", address);
    if let Some(decoder) = DEX_DECODERS.get(&address) {
        decoder.decode(data)
    } else {
        None
    }
}
struct UniswapV2Decoder;

impl Decoder for UniswapV2Decoder {
    fn decode(&self, data: &Bytes) -> Option<DecodedTx> {
        if let Ok(decoded) = swapExactTokensForTokensCall::abi_decode(data, false) {
            return Some(DecodedTx {
                name: "swapExactTokensForTokens".to_string(),
                params: HashMap::from([
                    ("amountIn".to_string(), decoded.amountIn.to_string()),
                    ("amountOutMin".to_string(), decoded.amountOutMin.to_string()),
                ]),
                inputs: vec![],
            });
        }

        if let Ok(decoded) = swapTokensForExactTokensCall::abi_decode(data, false) {
            return Some(DecodedTx {
                name: "swapTokensForExactTokens".to_string(),
                params: HashMap::from([
                    ("amountOut".to_string(), decoded.amountOut.to_string()),
                    ("amountInMax".to_string(), decoded.amountInMax.to_string()),
                ]),
                inputs: vec![],
            });
        }

        if let Ok(decoded) = swapExactETHForTokensCall::abi_decode(data, false) {
            return Some(DecodedTx {
                name: "swapExactETHForTokens".to_string(),
                params: HashMap::from([
                    ("amountOutMin".to_string(), decoded.amountOutMin.to_string()),
                    ("weth".to_string(), decoded.path[0].to_string()),
                    ("token".to_string(), decoded.path[1].to_string()),
                ]),
                inputs: vec![],
            });
        }

        if let Ok(decoded) = swapTokensForExactETHCall::abi_decode(data, false) {
            return Some(DecodedTx {
                name: "swapTokensForExactETH".to_string(),
                params: HashMap::from([
                    ("amountOut".to_string(), decoded.amountOut.to_string()),
                    ("amountInMax".to_string(), decoded.amountInMax.to_string()),
                ]),
                inputs: vec![],
            });
        }
        if let Ok(decoded) = swapExactTokensForETHCall::abi_decode(data, false) {
            return Some(DecodedTx {
                name: "swapExactTokensForETH".to_string(),
                params: HashMap::from([
                    ("amountIn".to_string(), decoded.amountIn.to_string()),
                    ("amountOutMin".to_string(), decoded.amountOutMin.to_string()),
                ]),
                inputs: vec![],
            });
        }

        if let Ok(decoded) = swapETHForExactTokensCall::abi_decode(data, false) {
            return Some(DecodedTx {
                name: "swapETHForExactTokens".to_string(),
                params: HashMap::from([("amountOut".to_string(), decoded.amountOut.to_string())]),
                inputs: vec![],
            });
        }

        if let Ok(decoded) =
            swapExactTokensForTokensSupportingFeeOnTransferTokensCall::abi_decode(data, false)
        {
            return Some(DecodedTx {
                name: "swapExactTokensForTokensSupportingFeeOnTransferTokens".to_string(),
                params: HashMap::from([
                    ("amountIn".to_string(), decoded.amountIn.to_string()),
                    ("amountOutMin".to_string(), decoded.amountOutMin.to_string()),
                ]),
                inputs: vec![],
            });
        }

        if let Ok(decoded) =
            swapExactETHForTokensSupportingFeeOnTransferTokensCall::abi_decode(data, false)
        {
            return Some(DecodedTx {
                name: "swapExactETHForTokensSupportingFeeOnTransferTokens".to_string(),
                params: HashMap::from([(
                    "amountOutMin".to_string(),
                    decoded.amountOutMin.to_string(),
                )]),
                inputs: vec![],
            });
        }

        if let Ok(decoded) =
            swapExactTokensForETHSupportingFeeOnTransferTokensCall::abi_decode(data, false)
        {
            return Some(DecodedTx {
                name: "swapExactTokensForETHSupportingFeeOnTransferTokens".to_string(),
                params: HashMap::from([
                    ("amountIn".to_string(), decoded.amountIn.to_string()),
                    ("amountOutMin".to_string(), decoded.amountOutMin.to_string()),
                ]),
                inputs: vec![],
            });
        }
        None
    }
}

//UNISWAP_V3
#[cfg(not(tarpaulin_include))]
sol!(
    #[allow(missing_docs)]
    function execute(
        bytes calldata commands,
        bytes[] calldata inputs,
        uint256 deadline
    ) external payable;
);

//UNISWAP_V2
#[cfg(not(tarpaulin_include))]
sol!(
    #[allow(missing_docs)]
    function swapExactTokensForTokens(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] calldata path,
        address to,
        uint256 deadline
      ) external returns (uint256[] memory amounts);
);

#[cfg(not(tarpaulin_include))]
sol!(
    #[allow(missing_docs)]
    function swapTokensForExactTokens(
      uint amountOut,
      uint amountInMax,
      address[] calldata path,
      address to,
      uint deadline
    ) external returns (uint[] memory amounts);
);

#[cfg(not(tarpaulin_include))]
sol!(
     #[allow(missing_docs)]
     function swapExactETHForTokens(
       uint amountOutMin,
       address[] calldata path,
       address to,
       uint deadline
     ) external payable returns (uint[] memory amounts);
);

#[cfg(not(tarpaulin_include))]
sol!(
   #[allow(missing_docs)]
   function swapTokensForExactETH(
       uint amountOut,
       uint amountInMax,
       address[] calldata path,
       address to,
       uint deadline
    ) external returns (uint[] memory amounts);
);

#[cfg(not(tarpaulin_include))]
sol!(
    #[allow(missing_docs)]
    function swapExactTokensForETH(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
);

#[cfg(not(tarpaulin_include))]
sol!(
    #[allow(missing_docs)]
    function swapETHForExactTokens(
      uint amountOut,
      address[] calldata path,
      address to,
      uint deadline
  ) external payable returns (uint[] memory amounts);
);

#[cfg(not(tarpaulin_include))]
sol!(
    #[allow(missing_docs)]
    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
      uint amountIn,
      uint amountOutMin,
      address[] calldata path,
      address to,
      uint deadline
    ) external;
);

#[cfg(not(tarpaulin_include))]
sol!(
    #[allow(missing_docs)]
    function swapExactETHForTokensSupportingFeeOnTransferTokens(
      uint amountOutMin,
      address[] calldata path,
      address to,
      uint deadline
    ) external payable;
);

#[cfg(not(tarpaulin_include))]
sol!(
    #[allow(missing_docs)]
    function swapExactTokensForETHSupportingFeeOnTransferTokens(
      uint amountIn,
      uint amountOutMin,
      address[] calldata path,
      address to,
      uint deadline
    ) external;
);

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::hex::decode;
    use alloy::primitives::{Address, U256};
    use alloy::providers::ProviderBuilder;
    use mockall::mock;
    use std::str::FromStr;

    mock! {
        pub ContractInstance {
            pub fn new(address: Address, provider: RootProvider<Http<Client>>, interface: Interface) -> Self;
            pub fn function(&self, name: &str, params: &[()]) -> Result<MockContractCall, Box<dyn Error>>;
        }
    }

    mock! {
        pub ContractCall {
            pub async fn call(&self) -> Result<Vec<DynSolValue>, Box<dyn Error>>;
        }
    }

    #[test]
    fn test_uniswap_universal_router_decoder_decode() {
        let data = hex::decode(
            "3593564c000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000066a16cc300000000000000000000000000000000000000000000000000000000000000040b080604000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000e0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000002800000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000753d533d9680000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000753d533d96800000000000000000000000000000000000000000000000017424f97b5cbe778f0100000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2000000000000000000000000289ff00235d2b98b0145ff5d4435d3e92f9540a60000000000000000000000000000000000000000000000000000000000000060000000000000000000000000289ff00235d2b98b0145ff5d4435d3e92f9540a6000000000000000000000000000000fee13a103a10d593b9ae06b3e05f2e7e1c00000000000000000000000000000000000000000000000000000000000000190000000000000000000000000000000000000000000000000000000000000060000000000000000000000000289ff00235d2b98b0145ff5d4435d3e92f9540a6000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000017336cd5692e982c79a",
        )
        .unwrap();
        let bytes = Bytes::from(data);

        let decoder = UniswapUniversalRouterDecoder;

        let decoded_tx = decoder.decode(&bytes).unwrap();

        assert_eq!(
            decoded_tx.name, "execute",
            "Decoded transaction name is incorrect"
        );
        assert!(
            decoded_tx.params.contains_key("commands"),
            "Decoded transaction params missing 'commands'"
        );
        assert_eq!(
            decoded_tx.params["commands"], "0x0b080604",
            "Decoded transaction params 'commands' value mismatch"
        );
        let expected_input = "0x000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000753d533d968000";
        assert_eq!(
            decoded_tx.inputs[0], expected_input,
            "Decoded transaction input value mismatch"
        );
    }

    #[test]
    fn test_uniswap_universal_router_decoder_decode_fail() {
        let invalid_data = hex::decode("ffffffff").unwrap();
        let bytes = Bytes::from(invalid_data);

        let decoder = UniswapUniversalRouterDecoder;

        let decoded_tx = decoder.decode(&bytes);
        assert!(
            decoded_tx.is_none(),
            "Decoding should have failed and returned None"
        );
    }

    #[test]
    fn test_get_pair_address_ordered_tokens() {
        // todo!()
        let token0 = Address::from_str("0x777be1c6075c20184c4fd76344b7b0b7c858fe6b").unwrap();
        let token1 = Address::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let factory = Address::from_str("0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f").unwrap();

        let pair_address = get_pair_address(token0, token1, factory);

        let expected_address =
            Address::from_str("0xce5debe9dd76f96bb5fa00eb3cc084d43ec0dbf3").unwrap();

        assert_eq!(pair_address, expected_address);
    }

    #[test]
    fn test_get_pair_address_unordered_tokens() {
        // todo!()
        let token0 = Address::from_str("0x777be1c6075c20184c4fd76344b7b0b7c858fe6b").unwrap();
        let token1 = Address::from_str("0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let factory = Address::from_str("0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f").unwrap();

        let pair_address = get_pair_address(token1, token0, factory);

        let expected_address =
            Address::from_str("0xce5debe9dd76f96bb5fa00eb3cc084d43ec0dbf3").unwrap();

        assert_eq!(pair_address, expected_address);
    }

    #[should_panic]
    #[test]
    fn test_get_pair_address_invalid_token_length() {
        // todo!()
        let token0 = Address::from_str("0x777bec6075c20184c4fd76344b7b0b7c858fe6b").unwrap();
        let token1 = Address::from_str("0xc02aa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap();
        let factory = Address::from_str("0x5c69bee701ef814a2b6a3edd4b1652cb9cc5aa6f").unwrap();

        let pair_address = get_pair_address(token1, token0, factory);

        let expected_address =
            Address::from_str("0xce5debe9dd76f96bb5fa00eb3cc084d43ec0dbf3").unwrap();

        assert_eq!(pair_address, expected_address);
    }

    #[tokio::test]
    async fn test_get_pair_reserves() {
        let address = Address::from_str("0xce5debe9dd76f96bb5fa00eb3cc084d43ec0dbf3").unwrap();

        let http_rpc_url = "http://127.0.0.1:8545/".parse().unwrap();
        let http_provider = ProviderBuilder::new().on_http(http_rpc_url);

        let reserves = get_pair_reserves(address, http_provider.clone())
            .await
            .unwrap();

        println!("Reserves: {:?}", reserves);

        assert!(
            reserves.reserve0 > Uint::from(0),
            "reserve0 should be greater than zero"
        );
        assert!(
            reserves.reserve1 > Uint::from(0),
            "reserve1 should be greater than zero"
        );
    }
}
