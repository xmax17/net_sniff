use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};
use crate::capture::PacketData;
use crate::InputMode;

pub fn draw(
    f: &mut Frame,
    captured_packets: &[&PacketData], // Receives the filtered slice
    paused: &bool,
    filter: &str,
    mode: &InputMode,
    list_state: &mut ListState,
) {
    // 1. Create the vertical split: Top (Main App) vs Bottom (Status)
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),    // Feed and Inspector
            Constraint::Length(4), // Status Bar
        ])
        .split(f.area());

    // 2. Create the horizontal split in the top area: Left (Feed) vs Right (Inspector)
    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(70), // Packet Feed
            Constraint::Percentage(30), // Inspector Pane
        ])
        .split(main_chunks[0]);

    // --- PACKET FEED (LEFT) ---
    let items: Vec<ListItem> = captured_packets
        .iter()
        .map(|p| {
            // We can add some color back to the summary here
            ListItem::new(Line::from(vec![
                Span::styled(&p.summary, Style::default().fg(Color::White)),
            ]))
        })
        .collect();

    let feed_block = Block::default()
        .title(" LIVE PACKET FEED ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    let list_widget = List::new(items)
        .block(feed_block)
        .highlight_style(Style::default().bg(Color::Rgb(50, 50, 50)).bold())
        .highlight_symbol(">> ");

    f.render_stateful_widget(list_widget, top_chunks[0], list_state);

    // --- INSPECTOR PANE (RIGHT) ---
    // Logic: Get data from the selected packet
    let inspector_content = if let Some(idx) = list_state.selected() {
        if let Some(packet) = captured_packets.get(idx) {
            format!(
                "{}\n\n-- HEX DUMP --\n{}",
                packet.full_details, packet.hex_dump
            )
        } else {
            "No data found".to_string()
        }
    } else {
        "Select a packet to inspect...".to_string()
    };

    let inspector_block = Block::default()
        .title(" INSPECTOR ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Yellow));

    let inspector_widget = Paragraph::new(inspector_content)
        .block(inspector_block)
        .wrap(Wrap { trim: true });

    f.render_widget(inspector_widget, top_chunks[1]);

    // --- STATUS BAR (BOTTOM) ---
    let (mode_text, mode_color) = match mode {
        InputMode::Normal => (" NORMAL MODE ", Color::Green),
        InputMode::Search => (" SEARCH MODE ", Color::Cyan),
    };

    let status_text = vec![
        Line::from(vec![
            Span::styled(mode_text, Style::default().fg(mode_color).bold()),
            Span::raw(format!(" | Filter: [{}]", filter)),
            Span::styled(
                if *paused { " (PAUSED)" } else { "" },
                Style::default().fg(Color::Yellow),
            ),
        ]),
        Line::from("j/k: Scroll | /: Search | c: Clear | q: Quit"),
    ];

    let status_block = Block::default()
        .title(" STATUS ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(mode_color));

    let status_widget = Paragraph::new(status_text).block(status_block);
    f.render_widget(status_widget, main_chunks[1]);
}
