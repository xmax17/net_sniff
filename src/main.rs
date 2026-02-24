mod capture;
mod ui;
mod process;

use crate::capture::{parse_packet_full, PacketData};
use crate::process::ProcessResolver;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, widgets::ListState, Terminal};
use std::io::{self, Write};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

#[derive(PartialEq, Debug)]
pub enum InputMode { Normal, Search }

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
    
    let mut local_packets: Vec<PacketData> = Vec::new();
    let mut list_state = ListState::default();
    let mut input_mode = InputMode::Normal;
    let mut filter_text = String::new();
    let mut is_paused = false;

    // 4. Capture Thread
    let resolver_cap = Arc::clone(&resolver);
    thread::spawn(move || {
        let mut cap = pcap::Capture::from_device(selected_device)
            .unwrap()
            .promisc(true)
            .immediate_mode(true) 
            .open()
            .unwrap();

        let mut last_refresh = Instant::now();

        while let Ok(packet) = cap.next_packet() {
            // Refresh process mappings every 2s
            if last_refresh.elapsed() > Duration::from_secs(2) {
                if let Ok(mut res) = resolver_cap.lock() {
                    res.refresh();
                }
                last_refresh = Instant::now();
            }

            let mut app_name = String::from("Unknown");
            if let Ok(p) = etherparse::SlicedPacket::from_ethernet(&packet.data) {
                if let Some(t) = p.transport {
                    let (src, dst) = match t {
                        etherparse::TransportSlice::Tcp(s) => (s.source_port(), s.destination_port()),
                        etherparse::TransportSlice::Udp(s) => (s.source_port(), s.destination_port()),
                        _ => (0, 0),
                    };

                    app_name = resolver_cap.lock().unwrap().resolve_port(src);
                    if app_name == "Unknown" && dst > 0 {
                        app_name = resolver_cap.lock().unwrap().resolve_port(dst);
                    }
                }
            }

            if let Some(parsed) = parse_packet_full(&packet.data, app_name) {
                let _ = tx.send(parsed);
            }
        }
    });

    // 5. UI Loop
    loop {
        // Check if we should autoscroll before adding new packets
        let is_at_bottom = match list_state.selected() {
            Some(i) => i >= local_packets.len().saturating_sub(1),
            None => true,
        };

        let mut received_new = false;
        while let Ok(packet) = rx.try_recv() {
            if !is_paused {
                local_packets.push(packet);
                received_new = true;
                if local_packets.len() > 1000 { local_packets.remove(0); }
            }
        }

        let filtered: Vec<&PacketData> = local_packets.iter()
            .filter(|p| {
                filter_text.is_empty() 
                || p.summary.to_lowercase().contains(&filter_text.to_lowercase())
                || p.app_name.to_lowercase().contains(&filter_text.to_lowercase())
            })
            .collect();

        // Autoscroll logic: follow if we were at the bottom and got new packets
        if received_new && is_at_bottom && !is_paused && !filtered.is_empty() {
            list_state.select(Some(filtered.len() - 1));
        }

        terminal.draw(|f| {
            ui::draw(f, &filtered, &is_paused, &filter_text, &input_mode, &mut list_state);
        })?;

        if event::poll(Duration::from_millis(10))? {
            if let Event::Key(key) = event::read()? {
                match input_mode {
                    InputMode::Normal => match key.code {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('/') => input_mode = InputMode::Search,
                        KeyCode::Char(' ') => is_paused = !is_paused,
                        KeyCode::Char('c') => {
                            local_packets.clear();
                            list_state.select(None);
                        }
                        KeyCode::Char('g') => {
    list_state.select(Some(0));
},

// New: Jump to Bottom (G)
KeyCode::Char('G') => {
    if !filtered.is_empty() {
        list_state.select(Some(filtered.len() - 1));
    }
},
                        KeyCode::Char('j') | KeyCode::Down => {
                            let i = match list_state.selected() {
                                Some(i) => if i >= filtered.len().saturating_sub(1) { 0 } else { i + 1 },
                                None => 0,
                            };
                            list_state.select(Some(i));
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            let i = match list_state.selected() {
                                Some(i) => if i == 0 { filtered.len().saturating_sub(1) } else { i - 1 },
                                None => 0,
                            };
                            list_state.select(Some(i));
                        }
                        _ => {}
                    },
                    InputMode::Search => match key.code {
                        KeyCode::Enter | KeyCode::Esc => input_mode = InputMode::Normal,
                        KeyCode::Char(c) => filter_text.push(c),
                        KeyCode::Backspace => { filter_text.pop(); }
                        _ => {}
                    },
                }
            }
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    Ok(())
}
