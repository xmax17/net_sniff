use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Frame,
};
use crate::capture::PacketData;
use crate::InputMode;

pub fn draw(
    f: &mut Frame,
    captured_packets: &[&PacketData],
    paused: &bool,
    filter: &str,
    mode: &InputMode,
    list_state: &mut ListState,
) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(3)])
        .split(f.area());

    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(main_chunks[0]);

    // --- PACKET FEED ---
    let items: Vec<ListItem> = captured_packets.iter().map(|p| {
        let parts: Vec<&str> = p.summary.split('|').collect();
        let addresses = parts.get(0).unwrap_or(&"").to_string();
        let protocol = parts.get(1).unwrap_or(&" DATA ").to_string();
        let app_color = if p.app_name == "Unknown" { Color::DarkGray } else { Color::Rgb(0, 255, 127) };

        ListItem::new(Line::from(vec![
            Span::styled(addresses, Style::default().fg(Color::White)),
            Span::styled(" │ ", Style::default().fg(Color::Rgb(60, 60, 60))),
            Span::styled(protocol, Style::default().fg(Color::Magenta).bold()),
            Span::styled(" │ ", Style::default().fg(Color::Rgb(60, 60, 60))),
            Span::styled(format!("({})", p.app_name), Style::default().fg(app_color).italic()),
        ]))
    }).collect();

    f.render_stateful_widget(
        List::new(items)
            .block(Block::default().title(" 📡 LIVE FEED ").borders(Borders::ALL).green())
            .highlight_style(Style::default().bg(Color::Rgb(30, 30, 30)).bold())
            .highlight_symbol("⚡ "),
        top_chunks[0],
        list_state,
    );

    // --- ENHANCED INSPECTOR ---
    let insp_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(12)])
        .split(top_chunks[1]);

    if let Some(idx) = list_state.selected() {
        if let Some(packet) = captured_packets.get(idx) {
            let mut details_lines = Vec::new();
            
            // Header: App Info
            details_lines.push(Line::from(vec![
                Span::styled(" ● ", Style::default().fg(Color::Rgb(0, 255, 127))),
                Span::styled("APPLICATION CONTEXT", Style::default().bold().underlined())
            ]));
            details_lines.push(Line::from(format!("   Process: {}", packet.app_name).white()));
            details_lines.push(Line::from(""));

            // Parse layer strings into styled blocks
// Layer 2: Protocol Specifics
            // Explicitly tell Rust 'line' is a &str
            for line in packet.full_details.lines() {
                let line: &str = line; // Type hint
                if line.contains("---") {
                    let section_name = line.replace("-", "").trim().to_string();
                    details_lines.push(Line::from(vec![
                        Span::styled(" ● ", Style::default().fg(Color::Yellow)),
                        Span::styled(section_name, Style::default().bold().yellow().underlined())
                    ]));
                } else if !line.is_empty() {
                    details_lines.push(Line::from(format!("   {}", line).white()));
                }
            }

            f.render_widget(
                Paragraph::new(details_lines)
                    .block(Block::default().title(" 🔍 DETAILS ").borders(Borders::ALL).yellow())
                    .wrap(Wrap { trim: false }),
                insp_chunks[0]
            );

            f.render_widget(
                Paragraph::new(packet.hex_dump.as_str())
                    .block(Block::default().title(" 🔢 RAW PAYLOAD ").borders(Borders::ALL).blue())
                    .style(Style::default().fg(Color::Rgb(140, 140, 140))),
                insp_chunks[1]
            );
        }
    }

    // --- STATUS BAR ---
    let is_at_bottom = list_state.selected().map_or(true, |i| i >= captured_packets.len().saturating_sub(1));
    let status_line = Line::from(vec![
        Span::styled(match mode { InputMode::Normal => " NORMAL ", InputMode::Search => " SEARCH " }, Style::default().bg(Color::Green).fg(Color::Black).bold()),
        " ".into(),
        if *paused { " PAUSED ".on_red().white().bold() } else { " LIVE ".on_green().white().bold() },
        " │ Filter: ".dark_gray().into(),
        filter.yellow().underlined(),
        " │ ".dark_gray().into(),
        if is_at_bottom && !*paused { " AUTO-SCROLL ".on_blue().white().bold() } else { " STATIC ".dark_gray() },
    ]);

    f.render_widget(
        Paragraph::new(status_line).block(Block::default().borders(Borders::ALL).title_bottom(Line::from(" [j/k] Scroll [g/G] Top/End [/] Search [Space] Pause [q] Quit ").centered().dark_gray())),
        main_chunks[1]
    );
}
