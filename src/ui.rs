use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Style},
    text::{Line,Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

pub fn draw(f: &mut Frame, captured_packets: &[Line],paused:&bool) {
    // 1. Define the layout (Top 80%, Bottom 20%)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(80),
            Constraint::Percentage(20),
        ])
        .split(f.area());

    // 2. Build the Top Block (Feed)
    let top_block = Block::default()
        .title(" LIVE PACKET FEED ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    // We clone the slice into the widget
    let feed_widget = Paragraph::new(captured_packets.to_vec())
        .block(top_block);
    
    f.render_widget(feed_widget, chunks[0]);

    // 3. Build the Bottom Block (Status)
    let bottom_block = Block::default()
        .title(" STATUS ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));
    let status_text = vec![
    Line::from("Press 'q' to quit"),
    Line::from("Press Space to pause"),
    Line::from(Span::styled(
        format!("Paused: {}", paused),
        Style::default().fg(if *paused { Color::Yellow } else { Color::Gray })
    )),
];
    let status_widget = Paragraph::new(status_text)
    .block(bottom_block);
    f.render_widget(status_widget, chunks[1]);
    
}
