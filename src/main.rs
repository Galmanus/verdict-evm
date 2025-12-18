
use clap::Parser;
use colored::*;
use ethers::{
    abi::Token,
    contract::BaseContract,
    core::types::{H160, H256, U256, TransactionRequest},
    providers::{Http, Middleware, Provider},
    types::Bytes,
    utils::parse_ether,
};
use std::str::FromStr;
use serde::{Deserialize, Serialize};
use serde_json;
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use tracing::{info, warn, error};
use tokio::time::{timeout, Duration};

// Define state override structures
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StateOverride {
    #[serde(flatten)]
    accounts: HashMap<String, AccountOverride>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    balance: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<Bytes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "stateDiff")]
    state_diff: Option<HashMap<String, String>>,
}

impl StateOverride {
    fn new() -> Self {
        Self {
            accounts: HashMap::new(),
        }
    }

    fn insert(&mut self, address: H160, override_data: AccountOverride) {
        self.accounts.insert(format!("0x{:040x}", address), override_data);
    }
}

impl AccountOverride {
    fn new() -> Self {
        Self {
            balance: None,
            nonce: None,
            code: None,
            state: None,
            state_diff: None,
        }
    }
}

// Whitelist para tokens especiais que podem ter comportamento estranho (como rebase tokens)
fn is_special_token(token_addr: H160) -> bool {
    let token_str = format!("{:?}", token_addr).to_lowercase();
    match token_str.as_str() {
        "0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0" => true,  // wstETH
        "0xbe9895146f7af43049ca1c1ae358b0d4a48a8cb0" => true,  // cbETH
        "0xae78736cd615f374d3085123a210448e74fc6393" => true,  // rETH
        "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2" => true,  // WETH
        "0x5e8422345238f3427508c91da888c83d515b1225" => true,  // frxETH
        _ => false,
    }
}





fn parse_error(revert_msg: &str) -> String {
    let lower = revert_msg.to_lowercase();
    
    // Enhanced honeypot detection patterns
    if lower.contains("transfer amount exceeds balance") || lower.contains("insufficient balance") || lower.contains("balance too low") {
        "[HONEYPOT] Cannot Sell".to_string()
    } else if lower.contains("paused") || lower.contains("pause") {
        "[HONEYPOT] Paused".to_string()
    } else if lower.contains("approve") || lower.contains("allowance") {
        "[HONEYPOT] Approval Failed".to_string()
    } else if lower.contains("revert") {
        format!("[HONEYPOT] Execution Reverted: {}", revert_msg)
    } else if lower.contains("out of gas") {
        "[HONEYPOT] Out of Gas".to_string()
    } else if lower.contains("stack underflow") || lower.contains("stack overflow") {
        "[HONEYPOT] Stack Error".to_string()
    } else if lower.contains("execution reverted") {
        format!("[HONEYPOT] Reverted: {}", revert_msg)
    } else {
        format!("Execution reverted: {}", revert_msg)
    }
}

fn print_verdict(
    verdict_type: &str,
    description: &str,
    buy_tax: f64,
    sell_tax: f64,
    used_brute_force: bool,
    is_tradable: bool
) {
    println!("\n{}", "═".repeat(70));
    println!("{}", " FINAL VERDICT ".bright_cyan().bold().on_black());
    println!("{}", "═".repeat(70));
    
    // Verdict type with appropriate color
    let verdict_str = if verdict_type.contains("HONEYPOT") {
        format!("{}", verdict_type).red().bold().to_string()
    } else if verdict_type.contains("HIGH RISK") {
        format!("{}", verdict_type).yellow().bold().to_string()
    } else if verdict_type.contains("SPECIAL TOKEN") {
        format!("{}", verdict_type).cyan().bold().to_string()
    } else if verdict_type.contains("SAFE") {
        format!("{}", verdict_type).green().bold().to_string()
    } else {
        format!("{}", verdict_type).white().bold().to_string()
    };
    
    println!("VERDICT:  {}", verdict_str);
    println!("STATUS:   {}", description);
    
    if is_tradable {
        println!("TRADE:    {}", "✅ CAN BE TRADED".green());
    } else {
        println!("TRADE:    {}", "❌ CANNOT BE TRADED".red());
    }
    
    println!("\n{}", "─".repeat(70));
    println!("TAX ANALYSIS:");
    println!("├─ Buy Tax:   {:>8.2}%", buy_tax);
    println!("├─ Sell Tax:  {:>8.2}%", sell_tax);
    println!("├─ Method:    {}", if used_brute_force { 
        "Safe Bombing Fallback (Proxy-Safe)".yellow()
    } else {
        "Standard State Override".green()
    });
    
    let special_status = if buy_tax.abs() > 50.0 || sell_tax.abs() > 50.0 {
        "HIGH TAX ALERT!".red().bold().to_string()
    } else if sell_tax < 0.0 {
        "Negative tax detected (special token mechanics)".cyan().to_string()
    } else {
        "Normal tax range".green().to_string()
    };
    println!("└─ Special:   {}", special_status);
    
    println!("{}", "═".repeat(70));
    
    // Additional risk warnings
    if used_brute_force && is_tradable {
        println!("{}", "⚠️  WARNING: Token required Safe Bombing fallback - may have Proxy implementation".yellow());
    }
    
    if buy_tax.abs() > 30.0 || sell_tax.abs() > 30.0 {
        println!("{}", "⚠️  WARNING: High transaction taxes detected - be careful with slippage!".yellow());
    }
    
    if sell_tax < -5.0 {
        println!("{}", "⚠️  NOTICE: Negative sell tax may indicate special token mechanics (rebase, staking, etc.)".cyan());
    }
    
    println!("\n");
}

fn decode_sell_result(result: &serde_json::Value) -> Result<U256, Box<dyn std::error::Error>> {
    if let Some(result_str) = result.as_str() {
        if let Some(stripped) = result_str.strip_prefix("0x") {
            if let Ok(bytes) = hex::decode(stripped) {
                // Decode the return values - swapExactTokensForETH returns uint256[] memory
                if let Ok(decoded) = ethers::abi::decode(&[ethers::abi::ParamType::Array(Box::new(ethers::abi::ParamType::Uint(256)))], &bytes) {
                    if let Some(Token::Array(tokens)) = decoded.get(0) {
                        if let Some(Token::Uint(amount)) = tokens.last() {
                            return Ok(*amount);
                        }
                    }
                }

                // If the above decoding fails, try to interpret the result as just the amount of ETH received
                // This could happen if the function returns a single value instead of an array
                if bytes.len() >= 32 {
                    // Take the last 32 bytes as the ETH amount
                    let start = bytes.len() - 32;
                    let eth_amount_bytes = &bytes[start..];
                    let eth_amount = U256::from_big_endian(eth_amount_bytes);
                    if !eth_amount.is_zero() {
                        return Ok(eth_amount);
                    }
                }
            }
        }
    }

    // If still can't decode, return 0 as amount
    Ok(U256::zero())
}



#[derive(Parser)]
#[command(name = "VERDICT")]
#[command(about = "Advanced honeypot detection using state overrides")]
struct Args {
    /// The token address to check for honeypot
    #[arg(short, long)]
    token_address: String,

    /// RPC endpoint URL (e.g., Alchemy)
    #[arg(short, long, default_value = "https://eth-mainnet.alchemyapi.io/v2/YOUR_API_KEY")]
    rpc_url: String,

    /// Amount of WETH to use for buying (in ETH units, default: 0.01)
    #[arg(long, default_value = "0.01")]
    eth_amount: f64,

    /// Target chain ID (1 for Ethereum, 42161 for Arbitrum, 8453 for Base)
    #[arg(long, default_value = "1")]
    chain_id: u64,
}

/// ABI strings for contracts
const UNISWAP_V2_ROUTER_ABI: &str = r#"[
    {
        "inputs": [
            {"internalType": "uint256", "name": "amountIn", "type": "uint256"},
            {"internalType": "address[]", "name": "path", "type": "address[]"}
        ],
        "name": "getAmountsOut",
        "outputs": [{"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "amountOutMin", "type": "uint256"},
            {"internalType": "address[]", "name": "path", "type": "address[]"},
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "deadline", "type": "uint256"}
        ],
        "name": "swapExactETHForTokens",
        "outputs": [{"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}],
        "stateMutability": "payable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "uint256", "name": "amountIn", "type": "uint256"},
            {"internalType": "uint256", "name": "amountOutMin", "type": "uint256"},
            {"internalType": "address[]", "name": "path", "type": "address[]"},
            {"internalType": "address", "name": "to", "type": "address"},
            {"internalType": "uint256", "name": "deadline", "type": "uint256"}
        ],
        "name": "swapExactTokensForETH",
        "outputs": [{"internalType": "uint256[]", "name": "amounts", "type": "uint256[]"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "address", "name": "spender", "type": "address"},
            {"internalType": "uint256", "name": "value", "type": "uint256"}
        ],
        "name": "approve",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]"#;

const ERC20_ABI: &str = r#"[
    {
        "inputs": [{"internalType": "address", "name": "owner", "type": "address"}],
        "name": "balanceOf",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "address", "name": "owner", "type": "address"}, {"internalType": "address", "name": "spender", "type": "address"}],
        "name": "allowance",
        "outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "address", "name": "spender", "type": "address"},
            {"internalType": "uint256", "name": "value", "type": "uint256"}
        ],
        "name": "approve",
        "outputs": [{"internalType": "bool", "name": "", "type": "bool"}],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "decimals",
        "outputs": [{"internalType": "uint8", "name": "", "type": "uint8"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "symbol",
        "outputs": [{"internalType": "string", "name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [],
        "name": "name",
        "outputs": [{"internalType": "string", "name": "", "type": "string"}],
        "stateMutability": "view",
        "type": "function"
    }
]"#;

/// Known router addresses for different chains
const UNISWAP_V2_ROUTER_ADDRESS_ETH: &str = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"; // Uniswap V2 on Ethereum
const SUSHISWAP_ROUTER_ADDRESS_ARBITRUM: &str = "0x1b02dA8Cb0d097eB8D57A175b88c7D8b47997506"; // SushiSwap on Arbitrum
const UNISWAP_V2_ROUTER_ADDRESS_BASE: &str = "0x4752ba5dbc23f44d87826276bf6fd6b1c372ad24"; // Uniswap on Base
const PANCAKESWAP_ROUTER_ADDRESS_BSC: &str = "0x10ED43C7186122334098Fb82BA78B177B5B5cEd7"; // PancakeSwap on BSC
const WETH_ADDRESS_ETH: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"; // WETH on Ethereum
const WETH_ADDRESS_ARBITRUM: &str = "0x82aF49447D8a07e3bd95BD0d56f35241523fBab1"; // WETH on Arbitrum
const WETH_ADDRESS_BASE: &str = "0x4200000000000000000000000000000000000006"; // WETH on Base
const WBNB_ADDRESS_BSC: &str = "0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c"; // WBNB on BSC


fn calculate_balance_storage_key(user_addr: H160, balance_slot: u64) -> H256 {
    // Balance key calculation using ethers::abi::encode + keccak256
    let encoded = ethers::abi::encode(&[
        Token::Address(user_addr),
        Token::Uint(U256::from(balance_slot))
    ]);
    H256::from_slice(&Keccak256::digest(&encoded))
}


fn calculate_allowance_storage_key(owner: H160, spender: H160, allowance_slot: u64) -> H256 {
    // Inner hash: keccak256(abi.encode(owner, slot))
    // The slot must be encoded as U256
    let inner_encoded = ethers::abi::encode(&[
        Token::Address(owner),
        Token::Uint(U256::from(allowance_slot))
    ]);
    let inner_hash = H256::from_slice(&Keccak256::digest(&inner_encoded));

    // Outer hash: keccak256(abi.encode(spender, inner_hash))
    let outer_encoded = ethers::abi::encode(&[
        Token::Address(spender),
        Token::FixedBytes(inner_hash.as_bytes().to_vec())
    ]);
    H256::from_slice(&Keccak256::digest(&outer_encoded))
}


async fn find_allowance_slot(
    provider: &Provider<Http>,
    token_addr: H160,
    owner_addr: H160,
    spender_addr: H160,
) -> Result<u64, Box<dyn std::error::Error>> {
    println!("{}", "[*] Finding allowance slot...".cyan());

    let token_contract: BaseContract = ethers::abi::Contract::load(ERC20_ABI.as_bytes())
        .unwrap()
        .into();

    // Try slots 0 to 20 using state override method (more reliable)
    for slot in 0..20 {
        let mut state_override = StateOverride::new();
        let mut account_override = AccountOverride::new();

        let storage_key = calculate_allowance_storage_key(owner_addr, spender_addr, slot);

        let test_value = U256::from(987654321u64);
        let mut buffer = [0u8; 32];
        test_value.to_big_endian(&mut buffer);

        let mut storage_map = HashMap::new();
        storage_map.insert(format!("0x{:064x}", storage_key), format!("0x{:064x}", H256::from_slice(&buffer)));
        account_override.state_diff = Some(storage_map);
        state_override.insert(token_addr, account_override);

        let data = token_contract.encode("allowance", (owner_addr, spender_addr))?;
        let tx = TransactionRequest::new()
            .from(owner_addr)
            .to(token_addr)
            .data(data);

        let params = serde_json::json!([tx, "latest", state_override]);

        match provider.request::<serde_json::Value, serde_json::Value>("eth_call", params).await {
            Ok(result) => {
                if let Some(result_str) = result.as_str() {
                    if let Some(stripped) = result_str.strip_prefix("0x") {
                        if let Ok(bytes) = hex::decode(stripped) {
                            let allowance_value = U256::from_big_endian(&bytes);

                            if allowance_value == test_value {
                                println!("{}", format!("[+] Allowance slot found: {}", slot).green());
                                return Ok(slot);
                            }
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }

    // Also try the direct lookup method as backup
    // Get current allowance value
    let data = token_contract.encode("allowance", (owner_addr, spender_addr))?;
    let tx = TransactionRequest::new()
        .from(owner_addr)
        .to(token_addr)
        .data(data);

    let current_allowance_bytes = provider.call(&tx.into(), None).await?;
    let current_allowance = U256::from_big_endian(&current_allowance_bytes);

    // Try to find the slot that contains the current allowance
    for slot in 0..20 {
        // Calculate the storage key for allowance[owner][spender] in the nested mapping
        let storage_key = calculate_allowance_storage_key(owner_addr, spender_addr, slot);

        // Get the actual value at this storage slot
        let storage_value = provider.get_storage_at(
            token_addr,
            storage_key.into(),
            None
        ).await?;

        let slot_value = U256::from_big_endian(&storage_value.0);

        if slot_value == current_allowance && !slot_value.is_zero() {
            println!("{}", format!("[+] Allowance slot found: {}", slot).green());
            return Ok(slot);
        }
    }


    println!("{}", "[!] Could not find allowance slot - using slot 10 as fallback".yellow());
    Ok(10) // USDC uses slot 10 for allowances
}


async fn find_balance_slot(
    provider: &Provider<Http>,
    token_addr: H160,
    user_addr: H160,
) -> Result<u64, Box<dyn std::error::Error>> {
    println!("[*] Finding balance storage slot...");

    let token_contract: BaseContract = ethers::abi::Contract::load(ERC20_ABI.as_bytes())
        .unwrap()
        .into();


    // Try slots 0 to 20 using state override method (more reliable)
    for slot in 0..20 {
        // Create a state override to set a test value
        let mut state_override = StateOverride::new();
        let mut account_override = AccountOverride::new();

        // Calculate storage key using consistent ethers::abi::encode method
        let storage_key = calculate_balance_storage_key(user_addr, slot);

        // Set a unique test value
        let test_value = U256::from(123456789u64);
        let mut buffer = [0u8; 32];
        test_value.to_big_endian(&mut buffer);

        let mut storage_map = HashMap::new();
        storage_map.insert(format!("0x{:064x}", storage_key), format!("0x{:064x}", H256::from_slice(&buffer)));
        account_override.state_diff = Some(storage_map);
        state_override.insert(token_addr, account_override);

        // Test if balanceOf returns our test value
        let data = token_contract.encode("balanceOf", (user_addr,))?;
        let tx = TransactionRequest::new()
            .from(user_addr)
            .to(token_addr)
            .data(data);

        let params = serde_json::json!([tx, "latest", state_override]);

        match provider.request::<serde_json::Value, serde_json::Value>("eth_call", params).await {
            Ok(result) => {
                if let Some(result_str) = result.as_str() {
                    if let Some(stripped) = result_str.strip_prefix("0x") {
                        if let Ok(bytes) = hex::decode(stripped) {
                            let balance_value = U256::from_big_endian(&bytes);

                            if balance_value == test_value {
                                println!("[+] Found balance slot at index: {}", slot);
                                return Ok(slot);
                            }
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }

    // Also try the direct lookup method as backup
    // First, get the current balance to use as a reference
    let data = token_contract.encode("balanceOf", (user_addr,))?;
    let tx = TransactionRequest::new()
        .from(user_addr)
        .to(token_addr)
        .data(data);

    let current_balance_bytes = provider.call(&tx.into(), None).await?;
    let current_balance = U256::from_big_endian(&current_balance_bytes);


    // Try storage slots from 0 to 20
    for slot in 0..20 {
        // Calculate the storage key for balanceOf[user_addr] in the mapping
        let storage_key = calculate_balance_storage_key(user_addr, slot);

        // Get the actual value at this storage slot
        let storage_value = provider.get_storage_at(
            token_addr,
            storage_key.into(),
            None
        ).await?;


        // Check if this slot contains the user's balance
        // We're looking for a slot where the value matches the user's balance
        if U256::from_big_endian(&storage_value.0) == current_balance {
            println!("[+] Found balance slot at index: {}", slot);
            return Ok(slot);
        }
    }


    println!("[!] Could not find balance slot - using slot 0 as fallback");
    Ok(0) // Fallback to slot 0
}


async fn simulate_buy(
    provider: &Provider<Http>,
    router_addr: H160,
    weth_addr: H160,
    token_addr: H160,
    eth_amount: U256,
) -> Result<U256, Box<dyn std::error::Error>> {
    println!("[*] Simulating token purchase...");
    
    let router_contract: BaseContract = ethers::abi::Contract::load(UNISWAP_V2_ROUTER_ABI.as_bytes())
        .unwrap()
        .into();
    
    let path = vec![weth_addr, token_addr];
    let to = "0x000000000000000000000000000000000000dEaD".parse::<H160>()?; // Dead address instead of zero
    let deadline = U256::max_value();

    // Encode the function call
    let data = router_contract
        .encode("swapExactETHForTokens", (U256::zero(), path, to, deadline))?;

    // Perform the simulation call
    let tx = TransactionRequest::new()
        .from(H160([0; 20]))
        .to(router_addr)
        .value(eth_amount)
        .data(data);

    let result = provider.call(&tx.into(), None).await?;
    
    // Decode the return values - swapExactETHForTokens returns uint256[] memory
    if let Ok(decoded) = ethers::abi::decode(&[ethers::abi::ParamType::Array(Box::new(ethers::abi::ParamType::Uint(256)))], &result) {
        if let Some(Token::Array(tokens)) = decoded.get(0) {
            if let Some(Token::Uint(amount)) = tokens.last() {
                return Ok(*amount);
            }
        }
    }

    // If the above decoding fails, try to interpret the result as just the amount of tokens received
    // This could happen if the function returns a single value instead of an array
    if result.len() >= 32 {
        // Take the last 32 bytes as the token amount
        let start = result.len() - 32;
        let token_amount_bytes = &result[start..];
        let token_amount = U256::from_big_endian(token_amount_bytes);
        if !token_amount.is_zero() {
            return Ok(token_amount);
        }
    }

    // If still can't decode, return 0 as amount
    Ok(U256::zero())
}


async fn simulate_approve(
    provider: &Provider<Http>,
    token_addr: H160,
    router_addr: H160,
    token_amount: U256,
) -> Result<bool, Box<dyn std::error::Error>> {
    println!("[*] Simulating token approval...");

    let token_contract: BaseContract = ethers::abi::Contract::load(ERC20_ABI.as_bytes())
        .unwrap()
        .into();
        
    let data = token_contract.encode("approve", (router_addr, token_amount))?;

    let tx = TransactionRequest::new()
        .from(H160([0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44])) // Use um endereço não-zero
        .to(token_addr)
        .data(data);

    let result = provider.call(&tx.into(), None).await;
    Ok(result.is_ok())
}


async fn simulate_sell_with_override(
    provider: &Provider<Http>,
    router_addr: H160,
    weth_addr: H160,
    token_addr: H160,
    token_amount: U256,
    balance_slot: u64,
    allowance_slot: u64,
    user_addr: H160,
) -> Result<(U256, bool), Box<dyn std::error::Error>> {
    println!("[*] Simulating token sale with Safe Dynamic Bombing...");
    println!("balance_slot: {}", balance_slot);
    println!("allowance_slot: {}", allowance_slot);

    let router_contract: BaseContract = ethers::abi::Contract::load(UNISWAP_V2_ROUTER_ABI.as_bytes())
        .unwrap()
        .into();

    let path = vec![token_addr, weth_addr];
    let to = "0x000000000000000000000000000000000000dEaD".parse::<H160>()?; // Dead address instead of zero
    let deadline = U256::max_value();

    let data = router_contract
        .encode("swapExactTokensForETH", (token_amount, U256::zero(), path, to, deadline))?;

    // Create state override to set user's token balance AND allowance using Safe Dynamic Bombing
    let mut state_override = StateOverride::new();
    let mut account_override = AccountOverride::new();
    let mut storage_map = HashMap::new();

    let max_buffer = [0xffu8; 32]; // 0xFF...FF (U256::MAX)

    println!("[*] Injection Mode: SAFE DYNAMIC BOMBING (Slots 0-50 with proxy protection)");

    // Safe Dynamic Bombing: Loop from 0 to 50, skip proxy-critical slots 0,1,2 unless they are detected slots
    for i in 0..=50 {
        // Safety check: Skip slots 0, 1, 2 to protect proxy state (implementation, owner, paused)
        if i <= 2 && i != balance_slot && i != allowance_slot {
            continue;
        }

        // Write U256::MAX to balance slots
        let balance_storage_key = calculate_balance_storage_key(user_addr, i);
        storage_map.insert(
            format!("0x{:064x}", balance_storage_key),
            format!("0x{:064x}", H256::from_slice(&max_buffer))
        );

        // Write U256::MAX to allowance slots
        let allowance_storage_key = calculate_allowance_storage_key(user_addr, router_addr, i);
        storage_map.insert(
            format!("0x{:064x}", allowance_storage_key),
            format!("0x{:064x}", H256::from_slice(&max_buffer))
        );
    }

    account_override.state_diff = Some(storage_map);
    state_override.insert(token_addr, account_override);


    println!("[*] Safe Dynamic Bombing applied. Attempting direct sale...");

    let tx = TransactionRequest::new()
        .from(user_addr)
        .to(router_addr)
        .data(data);

    // Using the JSON-RPC method for eth_call with state override
    let params = serde_json::json!([tx, "latest", state_override]);

    match provider.request::<serde_json::Value, serde_json::Value>("eth_call", params).await {
        Ok(result) => {
            let amount = decode_sell_result(&result)?;
            return Ok((amount, false));
        },
        Err(e) => {
            let error_msg = format!("{}", e);
            // Extract revert reason from error message
            let revert_msg = if error_msg.contains("execution reverted:") {
                let parts: Vec<&str> = error_msg.split("execution reverted:").collect();
                if parts.len() > 1 {
                    parts[1].trim().to_string()
                } else {
                    "Unknown revert reason".to_string()
                }
            } else {
                "Execution reverted without message".to_string()
            };


            println!("[!] Specific slot override failed: {}", parse_error(&revert_msg));
            println!("[*] Attempting Safe Bombing fallback (Proxy-safe injection into slots 3-50)...");

            // Fallback: Create new StateOverride with MAX_UINT in ALL slots from 3 to 50
            // This is SAFE for Proxy contracts as it skips slots 0, 1, 2 which contain:
            // slot 0: implementation address
            // slot 1: admin address  
            // slot 2: reserved for future use
            let mut fallback_state_override = StateOverride::new();
            let mut fallback_account_override = AccountOverride::new();
            let mut fallback_storage_map = HashMap::new();

            println!("[*] Safe Bombing: Injecting MAX_UINT into balance and allowance slots 3-50");
            println!("[*] Safe Bombing: Skipping proxy-critical slots 0, 1, 2 to avoid breaking Proxy implementation");

            for i in 3..=50 {
                // Inject MAX_UINT into balance slots
                let balance_storage_key = calculate_balance_storage_key(user_addr, i);
                fallback_storage_map.insert(
                    format!("0x{:064x}", balance_storage_key),
                    format!("0x{:064x}", H256::from_slice(&max_buffer))
                );

                // Inject MAX_UINT into allowance slots
                let allowance_storage_key = calculate_allowance_storage_key(user_addr, router_addr, i);
                fallback_storage_map.insert(
                    format!("0x{:064x}", allowance_storage_key),
                    format!("0x{:064x}", H256::from_slice(&max_buffer))
                );
            }

            fallback_account_override.state_diff = Some(fallback_storage_map);
            fallback_state_override.insert(token_addr, fallback_account_override);

            let fallback_params = serde_json::json!([tx, "latest", fallback_state_override]);

            match provider.request::<serde_json::Value, serde_json::Value>("eth_call", fallback_params).await {
                Ok(fallback_result) => {
                    let amount = decode_sell_result(&fallback_result)?;
                    if amount > U256::zero() {
                        println!("[+] Safe Bombing fallback successful! Token is tradable via brute force.");
                        return Ok((amount, true));
                    } else {
                        eprintln!("[-] Safe Bombing fallback returned zero amount");
                        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, parse_error(&revert_msg))));
                    }
                },
                Err(fallback_e) => {
                    let fallback_error_msg = format!("{}", fallback_e);
                    let fallback_revert_msg = if fallback_error_msg.contains("execution reverted:") {
                        let parts: Vec<&str> = fallback_error_msg.split("execution reverted:").collect();
                        if parts.len() > 1 {
                            parts[1].trim().to_string()
                        } else {
                            "Unknown revert reason".to_string()
                        }
                    } else {
                        "Execution reverted without message".to_string()
                    };

                    eprintln!("[-] Safe Bombing fallback also failed: {}", parse_error(&fallback_revert_msg));
                    Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, parse_error(&revert_msg))))
                }
            }
        }
    }
}


async fn get_token_info(
    provider: &Provider<Http>,
    token_addr: H160,
) -> Result<(String, String, u8), Box<dyn std::error::Error>> {
    println!("[*] Getting token information...");

    let token_contract: BaseContract = ethers::abi::Contract::load(ERC20_ABI.as_bytes())
        .unwrap()
        .into();

    // Get token symbol
    let symbol = match token_contract.encode("symbol", ()) {
        Ok(data) => {
            let tx = TransactionRequest::new()
                .from(H160([0; 20]))
                .to(token_addr)
                .data(data);
            match provider.call(&tx.into(), None).await {
                Ok(result) => {
                    ethers::abi::decode(&[ethers::abi::ParamType::String], &result)
                        .ok()
                        .and_then(|tokens| tokens.get(0).cloned())
                        .and_then(|token| token.into_string())
                        .unwrap_or_else(|| "UNKNOWN".to_string())
                }
                Err(_) => {
                    warn!("Could not fetch token symbol");
                    "UNKNOWN".to_string()
                }
            }
        }
        Err(_) => {
            warn!("Could not encode symbol call");
            "UNKNOWN".to_string()
        }
    };

    // Get token name
    let name = match token_contract.encode("name", ()) {
        Ok(data) => {
            let tx = TransactionRequest::new()
                .from(H160([0; 20]))
                .to(token_addr)
                .data(data);
            match provider.call(&tx.into(), None).await {
                Ok(result) => {
                    ethers::abi::decode(&[ethers::abi::ParamType::String], &result)
                        .ok()
                        .and_then(|tokens| tokens.get(0).cloned())
                        .and_then(|token| token.into_string())
                        .unwrap_or_else(|| "Unknown Token".to_string())
                }
                Err(_) => {
                    warn!("Could not fetch token name");
                    "Unknown Token".to_string()
                }
            }
        }
        Err(_) => {
            warn!("Could not encode name call");
            "Unknown Token".to_string()
        }
    };

    // Get token decimals
    let decimals = match token_contract.encode("decimals", ()) {
        Ok(data) => {
            let tx = TransactionRequest::new()
                .from(H160([0; 20]))
                .to(token_addr)
                .data(data);
            match provider.call(&tx.into(), None).await {
                Ok(result) => {
                    ethers::abi::decode(&[ethers::abi::ParamType::Uint(8)], &result)
                        .ok()
                        .and_then(|tokens| tokens.get(0).cloned())
                        .and_then(|token| token.into_uint())
                        .map(|u| u.as_u32() as u8)
                        .unwrap_or(18)
                }
                Err(_) => {
                    warn!("Could not fetch token decimals");
                    18
                }
            }
        }
        Err(_) => {
            warn!("Could not encode decimals call");
            18
        }
    };

    Ok((name, symbol, decimals))
}


async fn run_simulation(args: Args) -> Result<(), Box<dyn std::error::Error>> {
    println!("[*] Starting VERDICT Analysis for Honeypot Detection");
    println!("[*] Target:      {}", args.token_address);
    println!("[*] RPC:         {}", args.rpc_url);
    println!();

    // Parse inputs
    let token_addr = H160::from_str(&args.token_address)?;
    let eth_amount = parse_ether(args.eth_amount)?
        .try_into()
        .map_err(|_| "Failed to convert ETH amount")?;
    
    // Use the appropriate router and WETH based on chain ID
    let (router_addr, weth_addr) = match args.chain_id {
        1 => (  // Ethereum
            H160::from_str(UNISWAP_V2_ROUTER_ADDRESS_ETH)?,
            H160::from_str(WETH_ADDRESS_ETH)?
        ),
        56 => (  // Binance Smart Chain
            H160::from_str(PANCAKESWAP_ROUTER_ADDRESS_BSC)?,
            H160::from_str(WBNB_ADDRESS_BSC)?
        ),
        42161 => (  // Arbitrum
            H160::from_str(SUSHISWAP_ROUTER_ADDRESS_ARBITRUM)?,
            H160::from_str(WETH_ADDRESS_ARBITRUM)?
        ),
        8453 => (  // Base
            H160::from_str(UNISWAP_V2_ROUTER_ADDRESS_BASE)?,
            H160::from_str(WETH_ADDRESS_BASE)?
        ),
        _ => (
            H160::from_str(UNISWAP_V2_ROUTER_ADDRESS_ETH)?,
            H160::from_str(WETH_ADDRESS_ETH)?
        ), // Default to Ethereum
    };

    // Connect to RPC
    let provider = Provider::<Http>::try_from(&args.rpc_url)?;
    

    // Get token info
    let (name, symbol, decimals) = get_token_info(&provider, token_addr).await?;
    println!("[*] Token:       {} ({})", name, symbol);
    println!("[*] Decimals:    {}", decimals);
    println!();


    // Step 1: Buy simulation
    let tokens_received = match simulate_buy(&provider, router_addr, weth_addr, token_addr, eth_amount).await {
        Ok(amount) => amount,
        Err(e) => {
            eprintln!("[-] Buy simulation failed: {}", e);
            println!("[-] TRADING DISABLED / UNBUYABLE");
            return Ok(());
        }
    };
    println!("[+] Buy Success: {} tokens", tokens_received);
    

    // Step 2: Approve simulation
    let approval_success = simulate_approve(&provider, token_addr, router_addr, tokens_received).await?;
    if !approval_success {
        eprintln!("[-] Approval simulation failed");
        println!("[-] HONEYPOT DETECTED - Cannot approve tokens for selling");
        return Ok(());
    } else {
        println!("[+] Approval OK");
    }
    

    // Step 2.5: Get balance and allowance storage slots (dynamic detection only)
    let fake_user = H160::from_str("0x1111111111111111111111111111111111111111").unwrap(); // Fixed fake user address

    // Always perform dynamic slot detection (no caching)
    let detected_balance_slot = match timeout(Duration::from_secs(30), find_balance_slot(&provider, token_addr, fake_user)).await {
        Ok(Ok(slot)) => slot,
        Ok(Err(e)) => {
            warn!("Balance slot detection failed: {}", e);
            println!("[!] Slot detection timed out - using fallback");
            0
        },
        Err(_) => {
            println!("[!] Slot detection timed out - using fallback");
            0
        }
    };

    let detected_allowance_slot = match timeout(Duration::from_secs(30), find_allowance_slot(&provider, token_addr, fake_user, router_addr)).await {
        Ok(Ok(slot)) => slot,
        Ok(Err(e)) => {
            warn!("Allowance slot detection failed: {}", e);
            println!("[!] Slot detection timed out - using fallback");
            10  // Default for allowances
        },
        Err(_) => {
            println!("[!] Slot detection timed out - using fallback");
            10
        }
    };

    // Trust the finder directly - no verification needed
    let balance_slot = detected_balance_slot;
    let allowance_slot = detected_allowance_slot;

    println!("[+] Using balance slot: {}", balance_slot);
    println!("[+] Using allowance slot: {}", allowance_slot);

    // Check if this is a special token that might behave differently
    let is_special = is_special_token(token_addr);
    if is_special {
        println!("[!] SPECIAL TOKEN DETECTED: This token might have special behavior (rebase, etc.)");
    }


    // Step 3: Sell simulation with state override
    let (eth_returned, used_brute_force) = match simulate_sell_with_override(&provider, router_addr, weth_addr, token_addr, tokens_received, balance_slot, allowance_slot, fake_user).await {
        Ok((amount, brute_force)) => {
            info!("Sale simulation successful, returned: {}", amount);
            (amount, brute_force)
        },
        Err(e) => {
            // Error parsing is now handled in simulate_sell_with_override
            eprintln!("[-] Sale simulation failed: {}", e);

            // For special tokens, don't immediately flag as honeypot - they might just have different mechanics
            if is_special {
                println!("[!] SPECIAL TOKEN: Sale failed but may be due to token mechanics, not honeypot");
                return Ok(());
            }

            // For the current implementation, we'll still flag it as honeypot for standard tokens
            // In a production version, we'd want more sophisticated error handling
            println!("[-] HONEYPOT DETECTED - Cannot sell tokens");
            return Ok(());
        }
    };
    
    println!("[+] Sell Success: {} WETH", eth_returned);
    
    // Calculate the expected return without tax using getAmountsOut to get accurate tax calculation
    let expected_return = {
        let router_contract: BaseContract = ethers::abi::Contract::load(UNISWAP_V2_ROUTER_ABI.as_bytes())
            .unwrap()
            .into();

        let path = vec![token_addr, weth_addr];
        let data = router_contract.encode("getAmountsOut", (tokens_received, path))?;
        let tx = TransactionRequest::new()
            .from(H160([0; 20]))
            .to(router_addr)
            .data(data);

        match provider.call(&tx.into(), None).await {
            Ok(result) => {
                if let Ok(decoded) = ethers::abi::decode(&[ethers::abi::ParamType::Array(Box::new(ethers::abi::ParamType::Uint(256)))], &result) {
                    if let Some(ethers::abi::Token::Array(tokens)) = decoded.get(0) {
                        if let Some(ethers::abi::Token::Uint(expected_amount)) = tokens.last() {
                            *expected_amount
                        } else {
                            eth_returned // fallback to actual return if decoding fails
                        }
                    } else {
                        eth_returned
                    }
                } else {
                    eth_returned
                }
            },
            Err(_) => eth_returned // fallback to actual return if call fails
        }
    };

    // Calculate buy tax by comparing expected vs received tokens
    let buy_tax = {
        let router_contract: BaseContract = ethers::abi::Contract::load(UNISWAP_V2_ROUTER_ABI.as_bytes())
            .unwrap()
            .into();

        let path = vec![weth_addr, token_addr];
        let data = router_contract.encode("getAmountsOut", (eth_amount, path))?;
        let tx = TransactionRequest::new()
            .from(H160([0; 20]))
            .to(router_addr)
            .data(data);

        match provider.call(&tx.into(), None).await {
            Ok(result) => {
                if let Ok(decoded) = ethers::abi::decode(
                    &[ethers::abi::ParamType::Array(Box::new(ethers::abi::ParamType::Uint(256)))],
                    &result
                ) {
                    if let Some(ethers::abi::Token::Array(amounts)) = decoded.get(0) {
                        if let Some(ethers::abi::Token::Uint(expected_tokens)) = amounts.last() {
                            let expected_f64 = expected_tokens.as_u128() as f64;
                            let received_f64 = tokens_received.as_u128() as f64;

                            if expected_f64 > 0.0 {
                                ((expected_f64 - received_f64) / expected_f64) * 100.0
                            } else {
                                0.0
                            }
                        } else { 0.0 }
                    } else { 0.0 }
                } else { 0.0 }
            },
            Err(_) => 0.0
        }
    };

    // Sell tax: actual received vs expected return
    let sell_tax = if expected_return > U256::zero() {
        let expected_f64 = expected_return.as_u128() as f64;
        let received_f64 = eth_returned.as_u128() as f64;

        if received_f64 <= expected_f64 {
            ((expected_f64 - received_f64) / expected_f64) * 100.0
        } else {
            // Taxa negativa - pode indicar arbitragem ou erro (ganho inesperado)
            let gain = ((received_f64 - expected_f64) / expected_f64) * 100.0;
            -gain  // Retorna taxa negativa
        }
    } else {
        0.0
    };

    // Check for negative sell tax (unexpected gains) that might indicate special token behavior
    let has_negative_tax = sell_tax < 0.0;
    let is_significantly_negative = sell_tax < -10.0; // Arbitrary threshold for significant negative tax



    // Verdict Logic with enhanced summary
    if eth_returned.is_zero() {
        // If zero returned, it means the sell transaction reverted - honeypot detected
        error!("Honeypot detected - zero ETH returned");
        print_verdict(
            "HONEYPOT DETECTED",
            &format!("Cannot sell tokens - execution reverted"),
            buy_tax,
            sell_tax,
            used_brute_force,
            false
        );
    } else if is_significantly_negative {
        // Special handling for tokens with significant negative sell tax
        warn!("Special token with negative tax detected: {:.2}%", sell_tax);
        print_verdict(
            "SPECIAL TOKEN",
            &format!("Negative tax: {:.2}% - may indicate rebase token or staking rewards", sell_tax),
            buy_tax,
            sell_tax,
            used_brute_force,
            false
        );
    } else if sell_tax > 50.0 {
        warn!("High sell tax detected: {:.2}%", sell_tax);
        print_verdict(
            "HIGH RISK / SCAM",
            &format!("Sell tax: {:.2}% - extremely high transaction tax", sell_tax),
            buy_tax,
            sell_tax,
            used_brute_force,
            false
        );
    } else {
        info!("Token is tradable with reasonable taxes");
        let verdict_type = if used_brute_force {
            "[SAFE] TRADABLE (via Brute Force)"
        } else if has_negative_tax {
            "[SAFE] TRADABLE (WITH NEGATIVE TAX)"
        } else {
            "[SAFE] TRADABLE"
        };
        
        let verdict_desc = if used_brute_force {
            "Token is tradable but required safe bombing fallback - Proxy contract compatible".to_string()
        } else if has_negative_tax {
            "Token is tradable but has negative sell tax - may indicate special token mechanics".to_string()
        } else {
            "Token is tradable with normal transaction taxes".to_string()
        };
        
        print_verdict(
            verdict_type,
            &verdict_desc,
            buy_tax,
            sell_tax,
            used_brute_force,
            true
        );
    }
    
    Ok(())
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logger
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    // Clear screen (optional but nice)
    print!("\x1B[2J\x1B[1;1H");

    println!("{}", r#"
    __      __ _______________  ________  .___  ______________________
    \ \    / /\_   _____/\__  \ \______ \ |   | \_   ___ \__    ___/
     \ \  / /  |    __)_  /   /  |    |  \|   | /    \  \/ |    |
      \ \/ /   |        \/   \   |    `   \   | \     \____|    |
       \__/   /_______  /\___/  /_______  /___|  \______  /|____|
                      \/                \/              \/
    "#.bright_cyan().bold());

    println!("{}", "    :: RUST EVM HONEYPOT DETECTOR :: v0.3.0 ::".white().dimmed());
    println!("{}", "    :: STATE OVERRIDE ENGINE ACTIVE ::".red().dimmed());
    println!();

    info!("Starting VERDICT analysis for token: {}", args.token_address);

    match run_simulation(args).await {
        Ok(()) => {
            println!("\n[*] Analysis completed.");
        },
        Err(e) => {
            error!("Error during analysis: {}", e);
            eprintln!("[-] Error: {}", e);
        }
    }

    Ok(())
}
