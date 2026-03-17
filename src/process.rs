use std::collections::HashMap;
use std::process::Command;
use std::str;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use std::{thread, time};


// In sysinfo 0.30+, traits like ProcessExt/SystemExt are gone.
// We just need the main types.
#[cfg(target_os = "macos")]
use sysinfo::System;

pub struct ProcessResolver {
    port_to_app: HashMap<u16, (String, time::Instant)>,
    last_updated: time::Instant,
}
impl ProcessResolver {
    pub fn new() -> Self {
        Self {
            port_to_app: HashMap::new(),
            last_updated: time::Instant::now(),
        }
    }
    pub fn resolve(&self, port: u16) -> String {
        self.port_to_app
            .get(&port)
            .map(|(name, _)| name.clone()) // Just take the name
            .unwrap_or_else(|| "Unknown".to_string())
    }
    pub fn migrate(&mut self, new_map: HashMap<u16, String>) {
        let now = time::Instant::now();

        for (port, name) in new_map {
            self.port_to_app.insert(port, (name, now));
        }

        self.port_to_app.retain(|_port, (_name, last_seen)| {
            now.duration_since(*last_seen) < time::Duration::from_secs(3)
        });
        self.last_updated = now
    }
}
#[cfg(target_os = "linux")]
pub fn run_ss_updater(resolever: Arc<RwLock<ProcessResolver>>) {
    loop {
        let ss_output = Command::new("ss")
            .arg("-tunap")
            .output()
            .expect("error exec ss command");
        let ss_output_str = str::from_utf8(&ss_output.stdout).expect("not valid utf8");

        let mut temp_map = HashMap::new();

        for line in ss_output_str.lines() {
            if let Some((port, app_name)) = parse_ss(line) {
                temp_map.insert(port, app_name);
            }
        }
        if let Ok(mut guard) = resolever.write() {
            guard.migrate(temp_map);
        }
        thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(target_os = "linux")]
fn parse_ss(ss_output: &str) -> Option<(u16, String)> {
    let cols: Vec<&str> = ss_output.split_whitespace().collect();

    if cols.len() < 7 {
        return None;
    }

    let port = cols[4].rsplit(":").next()?.parse::<u16>().ok()?;
    let app_name = cols[6].split('"').nth(1)?.to_string();

    Some((port, app_name))
}

#[cfg(target_os = "macos")]
pub fn run_ss_updater(resolever: Arc<RwLock<ProcessResolver>>) {
    loop {
        let output = Command::new("lsof")
            .args(["-n", "-P", "-i", "+c", "0"])
            .output()
            .expect("error running lsof command");
        let output_str = str::from_utf8(&output.stdout).expect("not valid utf8");
        let mut hashmap = HashMap::new();
        for line in output_str.lines() {
            if let Some((port, app_name)) = parse_lsof(line) {
                hashmap.insert(port, app_name);
            }
        }
        if let Ok(mut guard) = resolever.write() {
            guard.migrate(hashmap);
        }
        thread::sleep(Duration::from_secs(1));
    }
}
#[cfg(target_os = "macos")]
fn parse_lsof(output: &str) -> Option<(u16, String)> {
    let cols: Vec<&str> = output.split_whitespace().collect();

    if cols.len() < 9 {
        return None;
    }

    let name_col = cols[8]; // e.g., "192.168.1.10:56789->1.2.3.4:443"

    // 1. Get the local side (everything before the arrow)
    let local_part = name_col.split("->").next()?;

    // 2. Get the port from the local side (the last part after the colon)
    let port_str = local_part.rsplit(':').next()?;

    let port = port_str.parse::<u16>().ok()?;
    let app_name = cols[0].to_string();

    Some((port, app_name))
}
