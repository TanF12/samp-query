# samp-query

A zero-dependency, high-throughput SA:MP and open.mp query implementation written in pure Rust.

This library implements a custom non-blocking I/O reactor to handle thousands of concurrent queries without the overhead of heavy async runtimes.

Resources I used to understand the quirky SA-MP query mechanism and its edge cases for this implementation:
- [Documentation - SAMP Query Mechanism](https://open.mp/docs/tutorials/QueryMechanism)
- [open.mp server's query C++ mechanism](https://github.com/openmultiplayer/open.mp/blob/master/Server/Components/LegacyNetwork/Query/query.cpp)
- [Southclaws' Go implementation](https://github.com/Southclaws/go-samp-query)

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
samp_query = { git = "https://github.com/TanF12/samp_query" }
```

## Usage

## Usage

### Basic Client

The `SampClient` provides a simple, synchronous interface for single-target queries.

```rust
use samp_query::SampClient;
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialise the socket with a read/write timeout
    let client = SampClient::new(Duration::from_secs(2))?;

    // Query server info
    let info = client.get_info("45.145.224.162:7777")?;

    println!("Hostname : {}", info.hostname);
    println!("Players  : {}/{}", info.players, info.max_players);
    println!("Gamemode : {}", info.gamemode);
    println!("Language : {}", info.mapname);
    
    // You can also get rules or clients
    let rules = client.get_rules("45.145.224.162:7777")?;
    for rule in rules {
        println!("{} = {}", rule.name, rule.value);
    }
    
    // Calculate ping
    let ping = client.get_ping("45.145.224.162:7777")?;
    println!("Ping: {:?}", ping);

    Ok(())
}
```

### High-Performance Batch Scan

To query hundreds or thousands of servers, use `query_info_batch`. This bypasses standard threading models in favor of a single-threaded event loop that multiplexes I/O, ensuring CPU usage remains near zero while maintaining high packet throughput.

```rust
use samp_query::query_info_batch;
use std::time::Duration;

fn main() {
    let targets = vec![
        "45.145.224.162:7777".to_string(),
        "server.ls-rp.com:7777".to_string(),
    ];

    // Targets: List of strings (host:port)
    // Timeout: 1 second per request
    // Retries: 1 retry if packet is lost
    // PPS Limit: 5000 packets per second
    // DNS Threads: 4 background threads for resolving hostnames
    let results = query_info_batch(targets, Duration::from_secs(1), 1, 5000, 4).unwrap();

    for res in results {
        match res.result {
            Ok(info) => {
                println!(
                    "[ONLINE] {} ({:?}) - {} ({}/{})", 
                    res.target, 
                    res.rtt, 
                    info.hostname, 
                    info.players, 
                    info.max_players
                );
            },
            Err(e) => {
                eprintln!("[FAIL] {} - Reason: {}", res.original_input, e);
            }
        }
    }
}
```

## CLI

Check the `examples/` directory for a full, proper CLI implementation.

<sub>Fueled by Hawkwind and Monster energy</sub>