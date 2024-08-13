use alloy::primitives::Address;
use once_cell::sync::Lazy;
use std::collections::HashSet;
use std::str::FromStr;

use crate::utils::settings::SETTINGS;

pub static ENV: Lazy<String> =
    Lazy::new(|| std::env::var("ENV").unwrap_or_else(|_| "mainnet".to_string()));

pub static WETH_ADDR: Lazy<Address> = Lazy::new(|| Address::from_str(&SETTINGS.weth_addr).unwrap());
pub static UNISWAP_UNIVERSAL_ROUTER_ADDR: Lazy<Address> =
    Lazy::new(|| Address::from_str(&SETTINGS.uniswap_universal_router_addr).unwrap());
pub static UNISWAP_V2_ADDR: Lazy<Address> =
    Lazy::new(|| Address::from_str(&SETTINGS.uniswap_v2_addr).unwrap());
pub static UNISWAP_V2_FACTORY_ADDR: Lazy<Address> =
    Lazy::new(|| Address::from_str(&SETTINGS.uniswap_v2_factory_addr).unwrap());
pub static UNISWAP_V2_ERC20_ADDR: Lazy<Address> =
    Lazy::new(|| Address::from_str(&SETTINGS.uniswap_v2_erc20_addr).unwrap());
pub static UNISWAP_V3_FACTORY_ADDR: Lazy<Address> =
    Lazy::new(|| Address::from_str(&SETTINGS.uniswap_v3_factory_addr).unwrap());
pub static UNISWAP_V3_ADDR: Lazy<Address> =
    Lazy::new(|| Address::from_str(&SETTINGS.uniswap_v3_addr).unwrap());
pub static WALLET_SIGNER_ADDRESS: Lazy<Address> =
    Lazy::new(|| Address::from_str(&SETTINGS.wallet_signer_address).unwrap());
pub static BUNDLE_SIGNER_ADDRESS: Lazy<Address> =
    Lazy::new(|| Address::from_str(&SETTINGS.bundle_signer_address).unwrap());
// pub static WALLET_PRIVATE_KEY: Lazy<Address> =
//     Lazy::new(|| Address::from_str(&SETTINGS.bundle_signer_address).unwrap());


pub static DEX_ADDRESSES: Lazy<HashSet<Address>> = Lazy::new(|| {
    let mut addresses = HashSet::new();
    addresses.insert(*UNISWAP_UNIVERSAL_ROUTER_ADDR);
    addresses.insert(*UNISWAP_V2_ADDR);
    addresses.insert(*UNISWAP_V2_FACTORY_ADDR);
    addresses.insert(*UNISWAP_V3_FACTORY_ADDR);
    addresses.insert(*UNISWAP_V3_ADDR);
    addresses
});
