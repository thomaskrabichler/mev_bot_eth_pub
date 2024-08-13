use std::str::FromStr;

use alloy::{hex, primitives::Bytes};
use alloy_sol_types::sol_data::{Address, Array, Bool, Uint};
use alloy_sol_types::{SolType, SolValue};

use crate::utils::contract_utils::DecodedTx;
use crate::utils::dex_addresses::WETH_ADDR;

#[derive(Debug)]
pub struct UniswapV2Swap {
    pub amount_out_min: alloy::primitives::Uint<256, 4>,
    pub token_address: alloy::primitives::Address,
}

impl UniswapV2Swap {
    pub fn decode_v2_swap_data(decoded_tx: DecodedTx) -> Option<UniswapV2Swap> {
        let amount_out_min =
            alloy::primitives::U256::from_str(&decoded_tx.params["amountOutMin"]).unwrap();
        let token_address =
            alloy::primitives::Address::from_str(&decoded_tx.params["token"]).unwrap();

        let swap = {
            UniswapV2Swap {
                amount_out_min,
                token_address,
            }
        };
        Some(swap)
    }

    pub fn decode_universal_v2_swap_data(
        commands: &str,
        inputs: &[String],
    ) -> Option<UniswapV2Swap> {
        let substring = &commands[2..];
        let swap_position_commands = match substring.find("08") {
            Some(index) => (index) / 2,
            None => {
                println!("Substring not found");
                return None;
            }
        };

        let swap_input = &inputs[swap_position_commands];

        let input = swap_input.strip_prefix("0x").ok_or(swap_input).unwrap();

        let input_bytes = hex::decode(input).unwrap();

        type SwapSolType = (Address, Uint<256>, Uint<256>, Array<Address>, Bool);

        let decoded = SwapSolType::abi_decode_params(&input_bytes, true).unwrap();

        let address_bytes: &[u8] = decoded.0.as_slice();
        let recipient = *address_bytes
            .last()
            .ok_or("Failed to get the last byte of the address")
            .unwrap();

        let amount_in = decoded.1;
        let amount_out_min = decoded.2;
        let _path = decoded.3;

        // if recipient == 2 {
        //     println!("Recipient is 2... Invalid");
        //     // Todo maybe also allow recipient 2
        //     return None;
        // }

        if _path.len() != 2 {
            //Todo: In future, also handle multi token swaps
            // eg. here return all paths instead of just 2, and then handle
            println!("Path length is not 2... Invalid");
            return None;
        }

        if _path[0] != *WETH_ADDR {
            println!("First path element is not WETH... Invalid");
            return None;
        }
        let token_address = _path[1];

        let swap: UniswapV2Swap = {
            UniswapV2Swap {
                amount_out_min,
                token_address,
            }
        };

        Some(swap)
    }
}
