use std::{
    env,
    error::Error,
    fs::File,
    io::BufReader,
    path::Path,
    str::FromStr,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use alloy::primitives::{
    utils::{format_units, parse_units},
    Address, U256,
};
use dotenv::dotenv;

use crate::bot::{numbers::FrontrunSwapData, transactions::get_amount_out};

pub fn calculate_frontrun_amount_in(
    reserve_in: U256,
    reserve_out: U256,
    victim_eth_input: U256,
    min_amount_out_tokens: U256,
    token_addr: Address,
    pair_addr: Address,
    weth_addr: Address,
) -> Result<U256, &'static str> {
    let now = Instant::now();
    let start_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();

    let mut sim_in = victim_eth_input;
    let mut step_size = U256::from_str("2000000000000000").unwrap();
    let max_iterations = 117000;
    let mut iterations = 0;

    let victim_output_now = match get_amount_out(victim_eth_input, reserve_in, reserve_out) {
        Ok(output) => output,
        Err(_) => return Err("Failed to calculate initial victim output"),
    };

    let mut new_reserve_weth = reserve_in;
    let mut new_reserve_token = reserve_out;
    let mut victim_output_after_attack = victim_output_now;
    let min_allowed_output = min_amount_out_tokens + (min_amount_out_tokens / U256::from(100)); // min + 1%

    let mut last_valid_sim_in = sim_in;

    while iterations < max_iterations {
        let simulate_result = simulate_frontrun(sim_in, reserve_in, reserve_out);

        if let Ok((new_weth, new_token)) = simulate_result {
            new_reserve_weth = new_weth;
            new_reserve_token = new_token;
        } else {
            println!("Error in frontrun simulation, reducing step size.");
            step_size /= U256::from(2);
            if step_size.is_zero() {
                println!("Step size is zero, reverting to last valid value.");
                return Ok(last_valid_sim_in); // Revert to last valid value
            }
            continue;
        }

        let amount_out_result =
            get_amount_out(victim_eth_input, new_reserve_weth, new_reserve_token);

        if let Ok(output) = amount_out_result {
            victim_output_after_attack = output;
        } else {
            println!("Error calculating output, reducing step size.");
            step_size /= U256::from(2);
            if step_size.is_zero() {
                println!("Step size is zero, reverting to last valid value.");
                return Ok(last_valid_sim_in); // Revert to last valid value
            }
            continue;
        }

        if victim_output_after_attack >= min_allowed_output {
            break;
        }

        let previous_sim_in = sim_in;

        if victim_output_after_attack < min_allowed_output {
            if sim_in <= step_size {
                println!("Sim_in is too small to reduce further, reverting to last valid value.");
                return Ok(last_valid_sim_in);
            }
            sim_in -= step_size;
        } else {
            sim_in += step_size;
        }

        if sim_in == previous_sim_in {
            println!("Convergence achieved, breaking loop.");
            break;
        }

        last_valid_sim_in = sim_in;
        iterations += 1;
    }

    if iterations >= max_iterations {
        println!("Maximum iterations reached, reverting to last valid value.");
        return Ok(last_valid_sim_in);
    }

    let execution_time_ns = now.elapsed().as_nanos();

    Ok(sim_in)
}

fn calculate_slippage(current_price: U256, min_price: U256) -> f64 {
    let price_now: f64 = f64::from(current_price);
    let min_price: f64 = f64::from(min_price);

    let difference = price_now - min_price;
    let fractional_difference = difference / min_price;
    fractional_difference * 100.0
}

fn simulate_frontrun(
    frontrun_weth_amount_in: U256,
    reserve_weth: U256,
    reserve_token: U256,
) -> Result<(U256, U256), &'static str> {
    if frontrun_weth_amount_in.is_zero() {
        return Err("FRONTRUN_AMOUNT_ZERO");
    }
    let frontrun_token_out =
        get_amount_out(frontrun_weth_amount_in, reserve_weth, reserve_token).unwrap();
    let new_reserve_weth = reserve_weth + frontrun_weth_amount_in;
    let new_reserve_token = reserve_token - frontrun_token_out;

    Ok((new_reserve_weth, new_reserve_token))
}

fn save_data_to_json(data: FrontrunSwapData, pair_address: &Address) {
    let filename = format!("data/frontrun/frontrun_swaps_{}.json", pair_address);
    let path = std::path::Path::new(&filename);
    let display = path.display();

    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(_) => std::fs::File::create(path).unwrap_or_else(|err| {
            panic!("Couldn't create {}: {}", display, err);
        }),
    };

    let mut json_data: Vec<FrontrunSwapData> = match serde_json::from_reader(&file) {
        Ok(data) => data,
        Err(_) => Vec::new(),
    };

    json_data.push(data);

    file = File::create(path).unwrap_or_else(|err| {
        panic!("Couldn't create {}: {}", display, err);
    });

    serde_json::to_writer(file, &json_data).unwrap_or_else(|err| {
        panic!("Couldn't write to {}: {}", display, err);
    });
}
pub fn read_ith_object_from_json(
    pair_address: &Address,
    index: usize,
) -> Result<FrontrunSwapData, &'static str> {
    let filename = format!("data/frontrun/frontrun_swaps_{}.json", pair_address);
    let path = Path::new(&filename);
    println!("Reading from file: {:?}", path.display());

    let file = File::open(path).map_err(|_| "Failed to open file")?;
    let reader = BufReader::new(file);
    let json_data: Vec<FrontrunSwapData> =
        serde_json::from_reader(reader).map_err(|_| "Failed to read JSON data")?;

    if index >= json_data.len() {
        return Err("Index out of bounds");
    }

    Ok(json_data[index].clone())
}
pub fn format_wei_to_eth(wei: U256) -> String {
    format_units(wei, "eth").unwrap()
}

pub fn format_token_amount_18(token_amount: U256) -> String {
    format_units(token_amount, 18).unwrap()
}

pub fn get_valid_timestamp(future_millis: u128) -> u128 {
    let start = SystemTime::now();
    let since_epoch = start.duration_since(UNIX_EPOCH).unwrap();
    since_epoch.as_millis().checked_add(future_millis).unwrap()
}

pub fn load_dotenv() {
    dotenv().ok();
    let env_file = match env::var("ENV") {
        Ok(env) if env == "sepolia" => ".sepolia.env",
        Ok(env) if env == "anvil" => ".anvil.env",
        Ok(env) => ".mainnet.env",
        Err(e) => {
            println!("Error: {}", e);
            ".mainnet.env"
        }
    };
    println!("Loading {}", env_file);
    dotenv::from_filename(env_file).ok();
}
