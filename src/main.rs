mod capture;
mod process;
mod ui;

use crate::capture::{PacketData, parse_packet_full};
use crate::process::ProcessResolver;
use chrono::Local;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend, widgets::ListState};
use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

#[derive(PartialEq, Debug)]
pub enum InputMode {
    Normal,
    Search,
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub enum Tab {
    Feed,
    Connections,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Device Selection
    let devices = pcap::Device::list()?;
    println!("--- Available Interfaces ---");
    for (i, d) in devices.iter().enumerate() {
        println!("[{}] {}", i, d.name);
    }
    print!("Select Interface Number: ");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    let index: usize = input.trim().parse().map_err(|_| "Invalid selection")?;
    let selected_device = devices[index].clone();

    // 2. Terminal Setup
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout))?;

    // 3. Shared State & Channels
    let (tx, rx) = mpsc::channel::<PacketData>();
    let resolver: Arc<Mutex<ProcessResolver>> = Arc::new(Mutex::new(ProcessResolver::new()));
    let save_file: Arc<Mutex<Option<pcap::Savefile>>> = Arc::new(Mutex::new(None));

    // App state
    let mut active_tab = Tab::Feed;
    let mut connections: HashMap<(String, String, String, String), u64> = HashMap::new();
    let mut feed_list_state = ListState::default();
    let mut connections_list_state = ListState::default();
    let mut local_packets: Vec<PacketData> = Vec::new();
    let mut input_mode = InputMode::Normal;
    let mut filter_text = String::new();
    let mut is_paused = false;
    let mut is_saving = false;
    let mut selected_spike_index: Option<usize> = None; // Initialize here
    // Throughput tracking
    let mut throughput_history: Vec<u64> = vec![0; 200];
    let mut bytes_current_second = 0;
    let mut last_tick = Instant::now();
    let mut pause_time: Option<Instant> = None;
    let mut frozen_history: Vec<u64> = Vec::new(); // Store the chart state here when paused
    // 4. Capture Thread
    let resolver_cap = Arc::clone(&resolver);
    let save_file_capture = Arc::clone(&save_file);

    // FIX: Clone the device so the thread can own one copy while main() keeps the other
    let device_for_thread = selected_device.clone();

    thread::spawn(move || {
        let mut cap = pcap::Capture::from_device(device_for_thread)
            .unwrap()
            .promisc(true)
            .immediate_mode(true)
            .open()
            .unwrap();

        let mut last_refresh = Instant::now();

        while let Ok(packet) = cap.next_packet() {
            // Log to file if active

            if let Ok(mut guard) = save_file_capture.lock() {
                if let Some(file) = guard.as_mut() {
                    file.write(&packet);
                }
            }

            // Refresh process mappings every 2s
            if last_refresh.elapsed() > Duration::from_secs(2) {
                if let Ok(mut res) = resolver_cap.lock() {
                    res.refresh();
                }
                last_refresh = Instant::now();
            }

            let mut app_name = String::from("Unknown");

            // Try SLL first (for 'any' device) then Ethernet
            let parsed_headers = etherparse::SlicedPacket::from_linux_sll(&packet.data)
                .or_else(|_| etherparse::SlicedPacket::from_ethernet(&packet.data));

            if let Ok(p) = parsed_headers {
                if let Some(t) = p.transport {
                    let (src, dst) = match t {
                        etherparse::TransportSlice::Tcp(s) => {
                            (s.source_port(), s.destination_port())
                        }
                        etherparse::TransportSlice::Udp(s) => {
                            (s.source_port(), s.destination_port())
                        }
                        _ => (0, 0),
                    };

                    if let Ok(res_guard) = resolver_cap.lock() {
                        app_name = res_guard.resolve_port(src);
                        if app_name == "Unknown" && dst > 0 {
                            app_name = res_guard.resolve_port(dst);
                        }
                    }
                }
            }

            if let Some(parsed) = parse_packet_full(&packet.data, app_name) {
                if parsed.proto_label == "SSDP"
                    || parsed.dest.contains("239.255.255.250")
                    || parsed.dest.contains("ff05::c")
                // Catch the IPv6 version too!
                {
                    continue; // Skip this packet and move to the next one
                }
                let _ = tx.send(parsed);
            }
        }
    });

    // 5. UI Loop
    loop {
        let mut received_new = false;

        // Handle incoming packets
        while let Ok(packet) = rx.try_recv() {
            if !is_paused {
                let key = (
                    packet.source.clone(),
                    packet.dest.clone(),
                    packet.proto_label.clone(),
                    packet.app_name.clone(),
                );
                *connections.entry(key).or_insert(0) += packet.length as u64;
                bytes_current_second += packet.length as u64;

                local_packets.push(packet);
                received_new = true;
                if local_packets.len() > 1000 {
                    local_packets.remove(0);
                }
            }
        }

        // Update throughput graph
        if last_tick.elapsed() >= Duration::from_secs(1) {
            throughput_history.push(bytes_current_second);
            if throughput_history.len() > 200 {
                throughput_history.remove(0);
            }
            bytes_current_second = 0;
            last_tick = Instant::now();
        }

        // Data Filtering
        let filtered_packets: Vec<&PacketData> = local_packets
            .iter()
            .filter(|p| {
                filter_text.is_empty()
                    || p.summary
                        .to_lowercase()
                        .contains(&filter_text.to_lowercase())
                    || p.app_name
                        .to_lowercase()
                        .contains(&filter_text.to_lowercase())
            })
            .collect();

        // Autoscroll logic
        if !is_paused && received_new && active_tab == Tab::Feed {
            if !filtered_packets.is_empty() {
                feed_list_state.select(Some(filtered_packets.len() - 1));
            }
        }

        // Render
        terminal.draw(|f| {
            let chart_data = if is_paused {
                &frozen_history
            } else {
                &throughput_history
            };
            ui::draw(
                f,
                active_tab,
                &local_packets,
                &connections,
                &chart_data,
                &is_paused,
                &is_saving,
                &filter_text,
                &input_mode,
                &mut feed_list_state,
                &mut connections_list_state,
                selected_spike_index,
                pause_time,
            );
        })?;

        // Input Handling
        if event::poll(Duration::from_millis(10))? {
            if let Event::Key(key) = event::read()? {
                match input_mode {
                    InputMode::Normal => match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('1') => active_tab = Tab::Feed,
                        KeyCode::Char('2') => active_tab = Tab::Connections,
                        KeyCode::Char('/') => input_mode = InputMode::Search,
                        KeyCode::Char(' ') => {
                            is_paused = !is_paused;
                            if is_paused {
                                frozen_history = throughput_history.clone();
                                selected_spike_index = Some(frozen_history.len().saturating_sub(1));
                                pause_time = Some(Instant::now()); // Capture the "frozen" moment
                            } else {
                                selected_spike_index = None;
                                pause_time = None;
                            }
                        }
                        KeyCode::Char('c') => {
                            local_packets.clear();
                            connections.clear();
                        }
                        KeyCode::Char('w') => {
                            let mut guard = save_file.lock().unwrap();
                            if guard.is_some() {
                                *guard = None;
                                is_saving = false;
                            } else {
                                let ts = Local::now().format("%Y-%m-%d_%H-%M-%S");
                                let filename = format!("net-sniff_{}.pcap", ts);
                                // FIX: Use a temporary capture handle to spawn the savefile
                                if let Ok(tmp_cap) =
                                    pcap::Capture::from_device(selected_device.clone())
                                        .unwrap()
                                        .open()
                                {
                                    if let Ok(file) = tmp_cap.savefile(filename) {
                                        *guard = Some(file);
                                        is_saving = true;
                                    }
                                }
                            }
                        }
                        KeyCode::Char('j') | KeyCode::Down => {
                            let state = if active_tab == Tab::Feed {
                                &mut feed_list_state
                            } else {
                                &mut connections_list_state
                            };
                            let i = match state.selected() {
                                Some(i) => i + 1,
                                None => 0,
                            };
                            state.select(Some(i));
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            let state = if active_tab == Tab::Feed {
                                &mut feed_list_state
                            } else {
                                &mut connections_list_state
                            };
                            let i = match state.selected() {
                                Some(i) => i.saturating_sub(1),
                                None => 0,
                            };
                            state.select(Some(i));
                        }
                        // In your KeyCode match block:
                        KeyCode::Left => {
                            if let Some(idx) = selected_spike_index {
                                selected_spike_index = Some(idx.saturating_sub(1));
                            }
                        }
                        KeyCode::Right => {
                            if let Some(idx) = selected_spike_index {
                                if idx < throughput_history.len() - 1 {
                                    selected_spike_index = Some(idx + 1);
                                }
                            }
                        }
                        _ => {}
                    },
                    InputMode::Search => match key.code {
                        KeyCode::Enter | KeyCode::Esc => input_mode = InputMode::Normal,
                        KeyCode::Char(c) => filter_text.push(c),
                        KeyCode::Backspace => {
                            filter_text.pop();
                        }
                        _ => {}
                    },
                }
            }
        }
    }

    // Cleanup
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    Ok(())
}
