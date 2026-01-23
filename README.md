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

### Basic Client

The `SampClient` provides a synchronous interface for single-target queries.

```rust
use samp_query::{SampClient};
use std::time::Duration;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize with a global timeout of 2 seconds
    let client = SampClient::new(Duration::from_secs(2))?;

    // Query the server
    let info = client.get_info("45.145.224.162:7777")?;

    println!("Hostname : {}", info.hostname);
    println!("Players  : {}/{}", info.players, info.max_players);
    println!("Gamemode : {}", info.gamemode);
    println!("Mapname  : {}", info.mapname);
    
    // You can also get rules
    let rules = client.get_rules("45.145.224.162:7777")?;
    for rule in rules {
        println!("{} = {}", rule.name, rule.value);
    }

    Ok(())
}
```

### Batch Scan

To query multiple servers, use `query_batch`. Unlike usual thread pools, this uses a non-blocking socket reactor to handle I/O.

```rust
use samp_query::query_batch;
use std::time::Duration;

fn main() {
    let targets = vec![
        "45.145.224.162:7777".to_string(),
        "server.ls-rp.com:7777".to_string(),
    ];
    // Scan targets with:
    // - 1s timeout
    // - 1 retry per server
    // - 2000 packets per second limit (Global GCRA limit)
    let results = query_batch(targets, Duration::from_secs(1), 1, 2000).unwrap();

    for res in results {
        // The field is named 'result', not 'info'
        match res.result {
            Ok(info) => println!("[ONLINE] {} - {}", res.target, info.hostname),
            Err(e) => eprintln!("[OFFLINE] {} - Reason: {}", res.target, e),
        }
    }
}
```

## CLI

Check the `examples/` directory for a full, proper CLI implementation.

<sub>Fueled by Hawkwind and Monster energy</sub>