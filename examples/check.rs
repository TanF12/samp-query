use samp_query::{SampClient, query_info_batch};
use std::env;
use std::io::{self, Write};
use std::time::{Duration, Instant};

struct Config {
    targets: Vec<String>,
    timeout: Duration,
    json: bool,
    batch: bool,
    retry: usize,
}

fn main() {
    let stdout = io::stdout();
    let mut handle = std::io::BufWriter::new(stdout.lock());

    let config = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(handle, "Error: {}", e);
            print_help(&mut handle);
            return;
        }
    };

    if config.targets.is_empty() {
        print_help(&mut handle);
        return;
    }

    if config.batch {
        run_batch_mode(&mut handle, config);
    } else {
        run_single_mode(&mut handle, config);
    }
}

fn run_single_mode<W: Write>(w: &mut W, cfg: Config) {
    let target = &cfg.targets[0];

    if !cfg.json {
        let _ = writeln!(w, "Connecting to {}...", target);
    }

    let client = match SampClient::new(cfg.timeout) {
        Ok(c) => c,
        Err(e) => {
            let _ = writeln!(w, "Failed to bind socket: {}", e);
            return;
        }
    };

    let start = Instant::now();
    let info_res = client.get_info(target);
    let rules_res = client.get_rules(target);
    let clients_res = client.get_clients(target);
    let ping_res = client.get_ping(target);
    let rtt = start.elapsed();

    if cfg.json {
        if let Ok(info) = info_res {
            let _ = writeln!(w, "{{");
            let _ = writeln!(w, "  \"hostname\": {:?},", info.hostname);
            let _ = writeln!(w, "  \"players\": {},", info.players);
            let _ = writeln!(w, "  \"max_players\": {},", info.max_players);
            let _ = writeln!(w, "  \"gamemode\": {:?},", info.gamemode);
            let _ = writeln!(w, "  \"language\": {:?},", info.mapname);
            let _ = writeln!(w, "  \"password\": {}", info.password);
            let _ = writeln!(w, "}}");
        } else {
            let _ = writeln!(w, "{{ \"error\": \"Connection failed\" }}");
        }
        return;
    }

    match info_res {
        Ok(info) => {
            let ping_display = ping_res
                .map(|p| format!("{:.0}ms", p.as_millis()))
                .unwrap_or_else(|_| "N/A".to_string());

            let _ = writeln!(w, "\n{}", style("SERVER ONLINE", "32;1")); // Green Bold

            let mut table = Table::new();
            table.add_row(vec!["Address".to_string(), target.to_string()]);
            table.add_row(vec!["Hostname".to_string(), info.hostname.to_string()]);
            table.add_row(vec![
                "Ping".to_string(),
                format!("{} (Total RTT: {:.2?})", ping_display, rtt),
            ]);
            table.add_row(vec!["Gamemode".to_string(), info.gamemode.to_string()]);
            table.add_row(vec!["Language".to_string(), info.mapname.to_string()]);
            table.add_row(vec![
                "Players".to_string(),
                format!("{}/{}", info.players, info.max_players),
            ]);
            table.add_row(vec![
                "Password".to_string(),
                if info.password {
                    "Yes".to_string()
                } else {
                    "No".to_string()
                },
            ]);
            table.print(w);

            if let Ok(rules) = rules_res {
                if !rules.is_empty() {
                    let _ = writeln!(w, "\n{}", style("RULES", "1"));
                    let mut rule_table = Table::new();
                    let mid = (rules.len() as f32 / 2.0).ceil() as usize;
                    for i in 0..mid {
                        let left = &rules[i];
                        let right = rules.get(i + mid);

                        let r_name = right.map(|r| r.name.as_str()).unwrap_or("");
                        let r_val = right.map(|r| r.value.as_str()).unwrap_or("");

                        rule_table.add_row(vec![
                            left.name.clone(),
                            left.value.clone(),
                            "|".to_string(),
                            r_name.to_string(),
                            r_val.to_string(),
                        ]);
                    }
                    rule_table.print(w);
                }
            }

            if info.players > 0 {
                if let Ok(clients) = clients_res {
                    let _ = writeln!(w, "\n{} (Top 20)", style("PLAYERS", "1"));
                    let mut client_table = Table::new();
                    client_table.set_headers(vec!["ID", "Name", "Score"]);

                    for (i, c) in clients.iter().take(20).enumerate() {
                        client_table.add_row(vec![
                            i.to_string(),
                            c.name.clone(),
                            c.score.to_string(),
                        ]);
                    }
                    client_table.print(w);
                    if clients.len() > 20 {
                        let _ = writeln!(w, "... and {} more.", clients.len() - 20);
                    }
                }
            }
        }
        Err(e) => {
            let _ = writeln!(w, "\n{}", style("CONNECTION FAILED", "31;1"));
            let _ = writeln!(w, "Reason: {}", e);
        }
    }
}

fn run_batch_mode<W: Write>(w: &mut W, cfg: Config) {
    if !cfg.json {
        let _ = writeln!(
            w,
            "Scanning {} targets (Chunked Stream)...",
            cfg.targets.len()
        );
        let _ = writeln!(
            w,
            "{:<21} {:<9} {:<15} {}",
            "ADDRESS", "PLAYERS", "PING", "HOSTNAME"
        );
        let _ = writeln!(w, "{}", "-".repeat(80));
    }

    let mut online_total = 0;

    for chunk in cfg.targets.chunks(50) {
        let chunk_vec = chunk.to_vec();

        match query_info_batch(chunk_vec, cfg.timeout, cfg.retry, 2000, 4) {
            Ok(results) => {
                for res in results {
                    match res.result {
                        Ok(info) => {
                            online_total += 1;
                            if cfg.json {
                                let _ = writeln!(
                                    w,
                                    "{{ \"ip\": \"{}\", \"hostname\": {:?}, \"players\": {} }},",
                                    res.target, info.hostname, info.players
                                );
                            } else {
                                let _ = writeln!(
                                    w,
                                    "{:<21} {:<9} {:<15} {}",
                                    res.target.to_string(),
                                    format!("{}/{}", info.players, info.max_players),
                                    format!("{:.0}ms", res.rtt.as_millis()),
                                    truncate(&info.hostname, 35)
                                );
                            }
                        }
                        Err(_) => {
                            if !cfg.json {
                                let _ = writeln!(
                                    w,
                                    "{:<21} {:<9} {:<15} [OFFLINE]",
                                    res.original_input, "-", "-"
                                );
                            }
                        }
                    }
                }
            }
            Err(e) => {
                let _ = writeln!(w, "Chunk Error: {}", e);
            }
        }
        let _ = w.flush();
    }

    if !cfg.json {
        let _ = writeln!(w, "{}", "-".repeat(80));
        let _ = writeln!(
            w,
            "Scan Complete. Online: {}/{}",
            online_total,
            cfg.targets.len()
        );
    }
}

struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    fn new() -> Self {
        Self {
            headers: vec![],
            rows: vec![],
        }
    }

    fn set_headers(&mut self, headers: Vec<&str>) {
        self.headers = headers.iter().map(|s| s.to_string()).collect();
    }

    fn add_row(&mut self, row: Vec<String>) {
        self.rows.push(row);
    }

    fn print<W: Write>(&self, w: &mut W) {
        if self.rows.is_empty() {
            return;
        }

        let cols = self.rows[0].len();
        let mut widths = vec![0; cols];

        for (i, h) in self.headers.iter().enumerate() {
            if i < cols {
                widths[i] = widths[i].max(h.chars().count());
            }
        }
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                if i < cols {
                    widths[i] = widths[i].max(cell.chars().count());
                }
            }
        }

        for w in &mut widths {
            *w += 2;
        }
        self.print_separator(w, &widths, "┌", "─", "┐", "┬");

        if !self.headers.is_empty() {
            write!(w, "│").unwrap();
            for (i, h) in self.headers.iter().enumerate() {
                write!(w, "{:width$}", format!(" {}", h), width = widths[i]).unwrap();
                if i < cols - 1 {
                    write!(w, "│").unwrap();
                }
            }
            writeln!(w, "│").unwrap();
            self.print_separator(w, &widths, "├", "─", "┤", "┼");
        }

        for row in &self.rows {
            write!(w, "│").unwrap();
            for (i, cell) in row.iter().enumerate() {
                write!(w, "{:width$}", format!(" {}", cell), width = widths[i]).unwrap();
                if i < cols - 1 {
                    write!(w, "│").unwrap();
                }
            }
            writeln!(w, "│").unwrap();
        }

        self.print_separator(w, &widths, "└", "─", "┘", "┴");
    }

    fn print_separator<W: Write>(
        &self,
        w: &mut W,
        widths: &[usize],
        left: &str,
        mid: &str,
        right: &str,
        join: &str,
    ) {
        write!(w, "{}", left).unwrap();
        for (i, width) in widths.iter().enumerate() {
            write!(w, "{}", mid.repeat(*width)).unwrap();
            if i < widths.len() - 1 {
                write!(w, "{}", join).unwrap();
            }
        }
        writeln!(w, "{}", right).unwrap();
    }
}

fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = env::args().collect();
    let mut targets = Vec::new();
    let mut timeout = Duration::from_secs(2);
    let mut json = false;
    let mut retry = 1;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => json = true,
            "--timeout" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --timeout".to_string());
                }
                let secs: u64 = args[i].parse().map_err(|_| "Invalid timeout number")?;
                timeout = Duration::from_secs(secs);
            }
            "--retry" => {
                i += 1;
                if i >= args.len() {
                    return Err("Missing value for --retry".to_string());
                }
                retry = args[i].parse().map_err(|_| "Invalid retry number")?;
            }
            val if val.starts_with("--") => return Err(format!("Unknown flag: {}", val)),
            val => targets.push(val.to_string()),
        }
        i += 1;
    }

    Ok(Config {
        batch: targets.len() > 1,
        targets,
        timeout,
        json,
        retry,
    })
}

fn style(text: &str, code: &str) -> String {
    if std::env::var("NO_COLOR").is_ok() {
        text.to_string()
    } else {
        format!("\x1b[{}m{}\x1b[0m", code, text)
    }
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

fn print_help<W: Write>(w: &mut W) {
    let _ = writeln!(
        w,
        "
Usage:
  Single check : cargo run --example cli -- <IP:PORT>
  Batch scan   : cargo run --example cli -- <IP1> <IP2> ...
  
Options:
  --json       : Output results in JSON format
  --timeout N  : Set socket timeout in seconds (default: 2)
  --retry N    : Set number of retries per server (default: 1)
"
    );
}
