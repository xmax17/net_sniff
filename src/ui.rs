use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};
use crate::InputMode;

pub fn draw(
    f: &mut Frame,
    captured_packets: &[Line],
    paused: &bool,
    filter: String,
    mode: InputMode,
    list_state: &mut ListState, // Added ListState for scrolling
) {
    // Layout remains the same
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(80),
            Constraint::Percentage(20),
        ])
        .split(f.area());

    // --- 1. THE PACKET LIST (Replaces Paragraph) ---
    let items: Vec<ListItem> = captured_packets
        .iter()
        .map(|line| ListItem::new(line.clone()))
        .collect();

    let top_block = Block::default()
        .title(" LIVE PACKET FEED ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    let list_widget = List::new(items)
        .block(top_block)
        .highlight_style(Style::default().bg(Color::Rgb(50, 50, 50)).bold())
        .highlight_symbol(">> ");

    // We use render_stateful_widget so Ratatui knows the scroll offset
    f.render_stateful_widget(list_widget, chunks[0], list_state);

    // --- 2. THE STATUS BLOCK ---
    let (mode_text, mode_color) = match mode {
        InputMode::Normal => (" NORMAL MODE (s: search) ", Color::Green),
        InputMode::Search => (" SEARCH MODE (Enter: save) ", Color::Cyan),
    };

    let bottom_block = Block::default()
        .title(" STATUS ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(mode_color));

    let status_text = vec![
        Line::from(mode_text).style(Style::default().fg(mode_color).bold()),
        Line::from(format!("Filter: [{}]", filter)),
        Line::from(format!("Paused: {}", paused)),
        Line::from(""),
        Line::from("↑/↓ or j/k: Scroll"),
        Line::from("q: Quit | Space: Pause"),
    ];

    let status_widget = Paragraph::new(status_text).block(bottom_block);
    f.render_widget(status_widget, chunks[1]);
}
