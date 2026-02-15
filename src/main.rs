use ratatui::{
    Terminal, backend::CrosstermBackend, layout::{Constraint, Direction, Layout}, style::{Color,Style}, widgets::{Block, Borders, Paragraph}
};
use crossterm::{
    event::{self, Event, KeyCode}, execute, style::style, terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode}
};
use std::io;
use pcap::Capture;
use std::thread;
use std::sync::mpsc;
use crate::capture::parse_packet_to_line;
mod capture;
mod ui;


fn main() -> Result<(), io::Error> {
    // --- 1. SETUP TERMINAL ---
    enable_raw_mode()?; 
    let device = pcap::Device::lookup().unwrap().expect("No device found");
    let mut stdout = io::stdout(); 
    execute!(stdout, EnterAlternateScreen)?; 
    
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    
    //init capture 
    let (tx,rx) = mpsc::channel();
    let mut captured_packets: Vec<ratatui::text::Line> = Vec::new();
   thread::spawn(move ||{
       let mut cap = Capture::from_device(device.name.as_str())
           .unwrap()
           .immediate_mode(true)
           .open()
           .unwrap();
        while let Ok(packet) = cap.next_packet() {

        if let Some(line) = parse_packet_to_line(packet.data) {
            if tx.send(line).is_err() {break;}
        }
    }
   });

    // --- 2. MAIN APP LOOP ---
    loop {
        while let Ok(packet_desc) = rx.try_recv() {
        captured_packets.push(packet_desc);
        // Keep the list from growing forever and eating RAM
        if captured_packets.len() > 40 {
            captured_packets.remove(0);
        }
    }
        terminal.draw(|f| {
        ui::draw(f, &captured_packets);
        })?;
        

        // --- 3. HANDLE INPUT ---

        if event::poll(std::time::Duration::from_millis(16))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }
    }

    // --- 4. RESTORE TERMINAL ---
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}
