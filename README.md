# **SampQuery**
This is a project for a tool that executes queries to servers using the UDP protocol provided by SAMP. Written in Rust.

Read more about it at:
- [Documentation - SAMP Query Mechanism](https://open.mp/docs/tutorials/QueryMechanism)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
samp_query = "0.1.0"
samp_query = { git = "https://github.com/TanF12/samp_query" }

## Examples

### Basic Usage

The simplest way to query a server using default settings (2s timeout, 2 retries).

```rust
use samp_query::SampClient;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the client
    let client = SampClient::builder().build()?;

    // Query the server (DNS resolution is automatic)
    let info = client.get_information("45.145.224.162:6969")?;

    println!("Hostname: {}", info.hostname);
    println!("Players : {}/{}", info.players, info.max_players);
    println!("Gamemode: {}", info.gamemode);
    
    Ok(())
}
```

### Batch Querying

To query multiple servers in parallel using the built-in thread pool:

```rust
use samp_query::query_batch;

fn main() {
    let targets = vec![
        "45.145.224.162:6969".to_string(),
        "server.ls-rp.com:7777".to_string(),
    ];

    // Query targets using 4 worker threads
    let results = query_batch(targets, 4);

    for (ip, result) in results {
        match result {
            Ok(info) => println!("[{}] {}", ip, info.hostname),
            Err(e) => eprintln!("[{}] Error: {}", ip, e),
        }
    }
}

### Advanced Configuration

For production environments, you might want to tune timeouts or bind to specific ports.

```rust
use samp_query::SampClient;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = SampClient::builder()
        .timeout(Duration::from_secs(5)) // Increased timeout for slow networks
        .retries(3) // Retry up to 3 times on packet loss
        .bind_port(0)  // 0 = Let OS choose a random port
        .build()?;

    match client.get_information("server.ls-rp.com:7777") {
        Ok(info) => println!("Server is Online: {:?}", info),
        Err(e) => eprintln!("Failed to query: {}", e),
    }

    Ok(())
}
```

## CLI

Check the `examples/` directory for a full CLI implementation.