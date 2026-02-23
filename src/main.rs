use ratatui::{
    Terminal, backend::CrosstermBackend, widgets::ListState
};
use crossterm::{
    event::{self, Event, KeyCode}, execute, terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode}
};
use std::io;
use pcap::Capture;
use std::thread;
use std::sync::mpsc;

// Import our custom logic
mod capture;
mod ui;
use crate::capture::{parse_packet_full, PacketData};

#[derive(Clone, PartialEq)]
pub enum InputMode {
    Normal,
    Search,
}

fn main() -> Result<(), io::Error> {
    // --- 1. TERMINAL SETUP ---
    enable_raw_mode()?; 
    let mut stdout = io::stdout(); 
    execute!(stdout, EnterAlternateScreen)?; 
    
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // --- 2. PACKET CAPTURE SETUP ---
    let device = pcap::Device::lookup().unwrap().expect("No device found");
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        let mut cap = Capture::from_device(device.name.as_str())
            .unwrap()
            .immediate_mode(true)
            .open()
            .unwrap();
        
        while let Ok(packet) = cap.next_packet() {
            // Use the full parser to get summary, hex, and details
            if let Some(data) = parse_packet_full(packet.data) {
                if tx.send(data).is_err() { break; }
            }
        }
    });

    // --- 3. APP STATE ---
    let mut list_state = ListState::default();
    let mut input_mode = InputMode::Normal;
    let mut paused = false;
    let mut search_query = String::new();
    let mut all_packets: Vec<PacketData> = Vec::new();

    // --- 4. MAIN LOOP ---
    loop {
        // Handle incoming packets
        if !paused {
            while let Ok(packet) = rx.try_recv() {
                all_packets.push(packet);
                // Memory management: keep last 10k packets
                if all_packets.len() > 10000 {
                    all_packets.remove(0);
                }
            }
        }

        // Create the filtered view for the UI
        let filtered_view: Vec<&PacketData> = all_packets
            .iter()
            .filter(|p| {
                search_query.is_empty() || 
                p.summary.to_lowercase().contains(&search_query.to_lowercase())
            })
            .collect();

        // Auto-scroll logic: stick to bottom if live and in normal mode
        if !paused && !filtered_view.is_empty() && input_mode == InputMode::Normal {
            list_state.select(Some(filtered_view.len().saturating_sub(1)));
        }

        // Draw UI
        terminal.draw(|f| {
            ui::draw(
                f, 
                &filtered_view, 
                &paused, 
                &search_query, 
                &input_mode, 
                &mut list_state
            );
        })?;

        // --- 5. INPUT HANDLING ---
        if event::poll(std::time::Duration::from_millis(16))? {
            if let Event::Key(key) = event::read()? {
                match input_mode {
                    InputMode::Normal => {
                        match key.code {
                            // Navigation
                            KeyCode::Up | KeyCode::Char('k') => {
                                let i = match list_state.selected() {
                                    Some(i) => if i == 0 { 0 } else { i - 1 },
                                    None => 0,
                                };
                                list_state.select(Some(i));
                            },
                            KeyCode::Down | KeyCode::Char('j') => {
                                let i = match list_state.selected() {
                                    Some(i) => {
                                        if filtered_view.is_empty() { 0 }
                                        else if i >= filtered_view.len().saturating_sub(1) { i }
                                        else { i + 1 }
                                    },
                                    None => 0,
                                };
                                list_state.select(Some(i));
                            },
                            // Actions
                            KeyCode::Char('c') => {
                                all_packets.clear();
                                list_state.select(Some(0));
                            },
                            KeyCode::Char(' ') => paused = !paused,
                            KeyCode::Char('/') => input_mode = InputMode::Search,
                            KeyCode::Char('q') => break,
                            _ => {}
                        }
                    }
                    InputMode::Search => {
                        match key.code {
                            KeyCode::Char(c) => search_query.push(c),
                            KeyCode::Backspace => { search_query.pop(); },
                            KeyCode::Esc => {
                                search_query.clear();
                                input_mode = InputMode::Normal;
                            },
                            KeyCode::Enter => input_mode = InputMode::Normal,
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    // --- 6. CLEANUP ---
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}
