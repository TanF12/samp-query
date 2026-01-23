use samp_query::{SampClient, SampError, query_batch};
use std::env;
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() <= 1 {
        print_help();
        return;
    }

    if args.len() > 2 {
        run_batch_mode(&args[1..]);
    } else {
        run_single_mode(&args[1]);
    }
}

fn print_help() {
    println!("Usage:");
    println!("  Single server : cargo run --example check -- <IP:PORT>");
    println!("  Batch scan    : cargo run --example check -- <IP1> <IP2> <IP3> ...");
}

fn run_single_mode(target: &str) {
    println!("Connecting to {}...", target);

    let client = SampClient::new(Duration::from_secs(2)).expect("Failed to initialize UDP socket");

    let start = Instant::now();

    match client.get_info(target) {
        Ok(info) => {
            let rtt = start.elapsed();

            println!("\nSERVER INFO (RTT: {:.2?})", rtt);
            println!("┌──────────────────────────────────────────────┐");
            println!("│ Hostname : {:<33} │", truncate(&info.hostname, 33));
            println!("│ Gamemode : {:<33} │", truncate(&info.gamemode, 33));
            println!("│ Language : {:<33} │", truncate(&info.mapname, 33));
            println!("├──────────────────────────────────────────────┤");
            println!(
                "│ Players  : {:<12} {:>20} │",
                format!("{}/{}", info.players, info.max_players),
                if info.password {
                    "Pass: Yes"
                } else {
                    "Pass: No"
                }
            );
            println!("└──────────────────────────────────────────────┘");

            println!("\nFetching rules...");
            match client.get_rules(target) {
                Ok(rules) => {
                    println!("┌──────────────────────────────────────────────┐");
                    if rules.is_empty() {
                        println!("│ {:<44} │", "No rules defined");
                    } else {
                        for rule in rules.iter().take(8) {
                            let line = format!("{} = {}", rule.name, rule.value);
                            println!("│ {:<44} │", truncate(&line, 44));
                        }
                        if rules.len() > 8 {
                            println!("│ ... and {} more {:<23} │", rules.len() - 8, "");
                        }
                    }
                    println!("└──────────────────────────────────────────────┘");
                }
                Err(e) => {
                    println!("Error fetching rules: {}", e);
                }
            };

            if info.players > 0 {
                println!("\nFetching clients...");
                match client.get_clients(target) {
                    Ok(clients) => print_basic_clients(&clients),
                    Err(e) => println!("Could not retrieve players: {}", e),
                }
            } else {
                println!("\nNo players online.");
            }
        }
        Err(e) => print_error(e, start.elapsed()),
    }
}

fn run_batch_mode(targets: &[String]) {
    println!("Scanning {} servers...", targets.len());
    let start = Instant::now();

    match query_batch(targets.to_vec(), Duration::from_secs(2), 1, 2000) {
        Ok(results) => {
            let duration = start.elapsed();
            let mut online_count = 0;

            println!("\nRESULTS:");
            println!("----------------------------------------------------------");
            println!("{:<20} | {:<7} | {:<30}", "Address", "Players", "Hostname");
            println!("----------------------------------------------------------");

            for result in results {
                match result.result {
                    Ok(info) => {
                        online_count += 1;
                        println!(
                            "{:<20} | {:>7} | {}",
                            result.original_input,
                            format!("{}/{}", info.players, info.max_players),
                            truncate(&info.hostname, 30)
                        );
                    }
                    Err(e) => {
                        println!(
                            "{:<20} | {:<7} | [ERROR] {}",
                            result.original_input, "---", e
                        );
                    }
                }
            }
            println!("----------------------------------------------------------");
            println!(
                "Online: {}/{} (Time: {:.2?})",
                online_count,
                targets.len(),
                duration
            );
        }
        Err(e) => {
            eprintln!("Batch scan failed to initialize: {}", e);
        }
    }
}

fn print_error(e: SampError, duration: Duration) {
    eprintln!("\nCONNECTION FAILED ({:.2?})", duration);
    eprintln!("   Reason: {}", e);
    std::process::exit(1);
}

fn print_basic_clients(clients: &[samp_query::ServerClient]) {
    println!("┌──────────────────────────────────────────────┐");
    println!("│ {:<25} │ {:>16} │", "Name", "Score");
    println!("├──────────────────────────────────────────────┤");
    for (i, player) in clients.iter().enumerate() {
        if i >= 15 {
            println!("│ ... and {} more {:<23} │", clients.len() - 15, "");
            break;
        }
        println!(
            "│ {:<25} │ {:>16} │",
            truncate(&player.name, 25),
            player.score
        );
    }
    println!("└──────────────────────────────────────────────┘");
}

fn truncate(s: &str, max_width: usize) -> String {
    if s.chars().count() > max_width {
        let mut truncated: String = s.chars().take(max_width - 3).collect();
        truncated.push_str("...");
        truncated
    } else {
        s.to_string()
    }
}
