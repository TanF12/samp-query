use samp_query::{SampClient, SampError, query_batch};
use std::env;
use std::time::Duration;

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
    println!("Uso:");
    println!("  Single server : cargo run -- <IP:PORT>");
    println!("  Multiple servers (//) : cargo run -- <IP1> <IP2> <IP3> ...");
    println!("\nExample:");
    println!("  cargo run -- 45.145.224.162:6969");
}

fn run_single_mode(target: &str) {
    println!("Querying {}...", target);

    let client = SampClient::builder()
        .timeout(Duration::from_secs(4))
        .retries(2)
        .build()
        .expect("Couldn't create UDP socket");

    let start = std::time::Instant::now();
    let result = client.get_information(target);
    let duration = start.elapsed();

    match result {
        Ok(info) => {
            let players_str = format!("{} / {}", info.players, info.max_players);
            let password_str = if info.has_password { "Yes" } else { "No" };

            println!("\nSERVER ({:.2?})", duration);
            println!("┌──────────────────────────────────────────────┐");
            println!("│ Hostname : {:<33} │", truncate(&info.hostname, 33));
            println!("│ Gamemode : {:<33} │", truncate(&info.gamemode, 33));
            println!("│ Map      : {:<33} │", truncate(&info.mapname, 33));
            println!("├──────────────────────────────────────────────┤");
            println!("│ Players  : {:<33} │", players_str);
            println!("│ Password : {:<33} │", password_str);
            println!("└──────────────────────────────────────────────┘\n");
        }
        Err(e) => print_error(e, duration),
    }
}

fn run_batch_mode(targets: &[String]) {
    println!("Starting parallel scan on {} servers...", targets.len());
    let start = std::time::Instant::now();
    let results = query_batch(targets.to_vec(), 8);
    let duration = start.elapsed();
    let mut online_count = 0;

    println!("\nRESULTS:");
    println!("------------------------------------------------");
    for (ip, res) in results {
        match res {
            Ok(info) => {
                online_count += 1;
                println!("[ONLINE] {:<20} | {}", ip, info.hostname);
            }
            Err(e) => {
                println!("[ERROR ] {:<20} | {}", ip, e);
            }
        }
    }
    println!("------------------------------------------------");
    println!(
        "Scan finished in {:.2?}. Online: {}/{}",
        duration,
        online_count,
        targets.len()
    );
}

fn print_error(e: SampError, duration: Duration) {
    eprintln!("\nCONNECTION FAILED ({:.2?})", duration);
    eprintln!("   Reason: {}", e);

    match e {
        SampError::Io(_) => {
            eprintln!("   Check whether the IP address is correct and the server is online.")
        }
        SampError::PacketTooShort => {
            eprintln!("    Response does not match expected protocol.")
        }
        SampError::OriginMismatch => {
            eprintln!("   Response came from a different IP (possible IP spoofing).")
        }
        _ => {}
    }
    std::process::exit(1);
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
