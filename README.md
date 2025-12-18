# VERDICT - Advanced Honeypot Detection Engine

VERDICT is a sophisticated honeypot detection tool that uses Ethereum state override technology to safely analyze tokens without spending gas. It provides comprehensive trading analysis including tax calculations, special token detection, and proxy-safe testing methodologies.

## Key Features

### State Override Technology
VERDICT leverages Ethereum's state override capability to simulate transactions without executing them on-chain. This enables:
- **Zero Gas Cost**: All analyses are performed through simulation, requiring no actual gas expenditure
- **Safe Testing**: Transactions are executed in a virtual state environment
- **Dynamic State Manipulation**: Ability to override contract storage slots for comprehensive analysis

### Cost Zero Analysis
- **Simulation-Based**: All buy/sell operations are simulated using `eth_call`
- **No Real Transactions**: Zero actual ETH or token transfers
- **Storage Override**: Uses state diffs to override contract storage without gas costs
- **Instant Results**: Rapid analysis without waiting for block confirmations

### Advanced Detection Methods

#### Safe Dynamic Bombing
- **Proxy Protection**: Safely handles proxy contracts by skipping critical storage slots (0, 1, 2)
- **Fallback Strategy**: Multiple injection methods ensure maximum detection success
- **Storage Slot Detection**: Dynamically identifies balance and allowance storage locations
- **MAX_UINT Injection**: Uses maximum uint values to bypass restrictions

#### Comprehensive Token Analysis
- **Honeypot Detection**: Identifies tokens that cannot be sold
- **Tax Calculation**: Accurate buy/sell tax analysis with real-time calculations
- **Special Token Handling**: Recognizes rebase tokens (wstETH, cbETH, rETH, WETH, frxETH)
- **Multi-Chain Support**: Ethereum, Arbitrum, Base, and BSC compatibility

### Technical Innovation

#### Storage Slot Detection
- **Dynamic Discovery**: Automatically finds balance and allowance storage slots
- **Hash-Based Calculation**: Uses keccak256 for accurate storage key computation
- **Fallback Methods**: Multiple detection strategies ensure reliability
- **Proxy-Safe**: Protects proxy implementation slots from corruption

#### State Override Engine
```rust
// Example of state override structure
struct StateOverride {
    accounts: HashMap<String, AccountOverride>,
}

struct AccountOverride {
    balance: Option<U256>,
    nonce: Option<u64>,
    code: Option<Bytes>,
    state: Option<HashMap<String, String>>,
    state_diff: Option<HashMap<String, String>>,
}
```

## Installation

### Prerequisites
- Rust 1.70+ 
- Internet connection for RPC calls
- Valid RPC endpoint (Alchemy, Infura, etc.)

### Build
```bash
# Clone the repository
git clone <repository-url>
cd VERDICT

# Build the project
cargo build --release

# Run the binary
./target/release/verdict --help
```

## Usage

### Basic Analysis
```bash
# Analyze a token on Ethereum mainnet
./verdict 0xTokenAddress --rpc-url https://eth-mainnet.alchemyapi.io/v2/YOUR_API_KEY

# Custom ETH amount
./verdict 0xTokenAddress --eth-amount 0.1

# Different chain (Arbitrum)
./verdict 0xTokenAddress --chain-id 42161 --rpc-url YOUR_ARBITRUM_RPC
```

### Command Line Options
- `--token-address`: Token contract address to analyze (required)
- `--rpc-url`: RPC endpoint URL (default: Alchemy Ethereum)
- `--eth-amount`: Amount of ETH to use for buying (default: 0.01)
- `--chain-id`: Target chain ID (1=ETH, 56=BSC, 42161=Arbitrum, 8453=Base)

### Supported Chains
- **Ethereum**: Chain ID 1 (Uniswap V2)
- **BSC**: Chain ID 56 (PancakeSwap)
- **Arbitrum**: Chain ID 42161 (SushiSwap)
- **Base**: Chain ID 8453 (Uniswap V2)

## Output Analysis

### Verdict Categories
1. **[SAFE] TRADABLE**: Token is safe to trade with normal taxes
2. **[SAFE] TRADABLE (via Brute Force)**: Token requires Safe Bombing but is tradable
3. **[SAFE] TRADABLE (WITH NEGATIVE TAX)**: Special token with negative sell tax
4. **[HIGH RISK / SCAM]**: High transaction taxes (>50%)
5. **HONEYPOT DETECTED**: Cannot sell tokens

### Tax Analysis
- **Buy Tax**: Percentage lost when purchasing tokens
- **Sell Tax**: Percentage lost when selling tokens
- **Negative Tax**: Indicates special token mechanics (rebase, staking rewards)

### Risk Indicators
- **High Tax Alert**: Buy/sell tax >50%
- **Proxy Warning**: Token required Safe Bombing fallback
- **Special Token Notice**: Negative tax detection

## Technical Architecture

### Core Components

#### State Override System
```rust
// Safe Dynamic Bombing implementation
for i in 0..=50 {
    if i <= 2 && i != balance_slot && i != allowance_slot {
        continue; // Protect proxy slots
    }
    
    let storage_key = calculate_balance_storage_key(user_addr, i);
    storage_map.insert(
        format!("0x{:064x}", storage_key),
        format!("0x{:064x}", H256::from_slice(&max_buffer))
    );
}
```

#### Storage Slot Detection
- **Balance Slots**: Dynamic discovery using test value injection
- **Allowance Slots**: Hash-based calculation with fallback methods
- **Proxy Protection**: Skips implementation-critical storage locations

#### Error Parsing
```rust
fn parse_error(revert_msg: &str) -> String {
    let lower = revert_msg.to_lowercase();
    
    if lower.contains("transfer amount exceeds balance") {
        "[HONEYPOT] Cannot Sell".to_string()
    } else if lower.contains("paused") {
        "[HONEYPOT] Paused".to_string()
    }
    // ... additional patterns
}
```

### Dependencies
- `ethers`: Ethereum client and ABI encoding
- `tokio`: Async runtime for concurrent operations
- `serde`: JSON serialization/deserialization
- `clap`: Command-line argument parsing
- `sha3`: Keccak256 hash implementation

## Advanced Features

### Special Token Recognition
VERDICT automatically detects and handles special token types:
- **Rebase Tokens**: wstETH, cbETH, rETH
- **Wrapped Tokens**: WETH, frxETH
- **Staking Derivatives**: Tokens with negative tax mechanics

### Multi-Strategy Analysis
1. **Standard State Override**: Direct storage manipulation
2. **Safe Dynamic Bombing**: Proxy-safe slot injection
3. **Fallback Strategy**: Multiple detection methods
4. **Error Classification**: Sophisticated revert reason parsing

### Performance Optimizations
- **Concurrent Processing**: Async/await throughout
- **Timeout Handling**: 30-second slot detection limit
- **Caching**: Dynamic slot caching (optional)
- **Resource Management**: Efficient memory usage

## Security Considerations

### State Override Safety
- **Read-Only**: All operations use `eth_call` (no state changes)
- **Proxy Protection**: Skips critical storage slots
- **Simulation Only**: No actual contract execution
- **Zero Gas**: Complete cost-free analysis

### Risk Mitigation
- **Fallback Methods**: Multiple detection strategies
- **Timeout Protection**: Prevents hanging operations
- **Error Handling**: Comprehensive exception management
- **Safe Defaults**: Conservative fallback values

## Contributing

### Development Setup
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add target
rustup target add x86_64-unknown-linux-gnu

# Run tests
cargo test

# Lint
cargo clippy
```

### Code Structure
- **main.rs**: Core application logic
- **State Override**: Storage manipulation functions
- **Detection**: Honeypot identification algorithms
- **Analysis**: Tax calculation and reporting

## License

This project is licensed under the GNU Affero General Public License v3.0 - see the [LICENSE.txt](LICENSE.txt) file for details.

## Disclaimer

VERDICT is a tool for educational and research purposes. While it uses advanced simulation techniques, users should:
- Verify results independently
- Use at their own risk
- Not rely solely on automated detection
- Perform manual contract audits for high-value transactions

The state override technology provides powerful analysis capabilities but should be used responsibly and in accordance with applicable laws and terms of service.

## Support

For issues, questions, or contributions:
- Open an issue on the repository
- Review the documentation
- Check the examples directory for usage patterns

---

**VERDICT** - Advanced honeypot detection using state override technology with zero cost analysis.
