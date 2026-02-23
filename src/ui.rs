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
    // 1. Vertical Split: Main App Area vs Bottom Status Bar
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),    // Feed and Inspector
            Constraint::Length(3), // Status Bar
        ])
        .split(f.area());

    // 2. Horizontal Split: Left (Packet Feed) vs Right (Inspector)
    let top_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(60), // Feed
            Constraint::Percentage(40), // Inspector
        ])
        .split(main_chunks[0]);

    // --- PACKET FEED (LEFT) ---
    let items: Vec<ListItem> = captured_packets
        .iter()
        .map(|p| {
            // We split the summary string to colorize the protocol part
            let parts: Vec<&str> = p.summary.split('|').collect();
            let addresses = parts.get(0).unwrap_or(&"").to_string();
            let protocol = parts.get(1).unwrap_or(&"").to_string();

            ListItem::new(Line::from(vec![
                Span::styled(addresses, Style::default().fg(Color::White)),
                Span::styled(" | ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    protocol,
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                ),
            ]))
        })
        .collect();

    let feed_block = Block::default()
        .title(" 📡 LIVE PACKET FEED ".bold().green())
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green));

    let list_widget = List::new(items)
        .block(feed_block)
        .highlight_style(Style::default().bg(Color::Rgb(40, 40, 40)).add_modifier(Modifier::BOLD))
        .highlight_symbol(">> ");

    f.render_stateful_widget(list_widget, top_chunks[0], list_state);

    // --- INSPECTOR AREA (RIGHT) ---
    // Sub-layout for the Inspector: Top (Details) vs Bottom (Hex)
    let inspector_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(45), // Details
            Constraint::Percentage(55), // Hex Dump
        ])
        .split(top_chunks[1]);

    if let Some(idx) = list_state.selected() {
        if let Some(packet) = captured_packets.get(idx) {
            // Top: Protocol Details Pane
            let details_paragraph = Paragraph::new(packet.full_details.as_str())
                .block(
                    Block::default()
                        .title(" 🔍 DETAILS ".bold().yellow())
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Yellow)),
                )
                .wrap(Wrap { trim: true });
            f.render_widget(details_paragraph, inspector_chunks[0]);

            // Bottom: Hex Dump Pane
            let hex_paragraph = Paragraph::new(packet.hex_dump.as_str())
                .block(
                    Block::default()
                        .title(" 🔢 HEX DUMP ".bold().blue())
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Blue)),
                );
            f.render_widget(hex_paragraph, inspector_chunks[1]);
        }
    } else {
        // Placeholder when no packet is selected
        let empty_block = Block::default()
            .title(" INSPECTOR ".bold().dark_gray())
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray));
        f.render_widget(
            Paragraph::new("Select a packet to inspect...").block(empty_block),
            top_chunks[1],
        );
    }

    // --- STATUS BAR (BOTTOM) ---
    let (mode_text, mode_color) = match mode {
        InputMode::Normal => (" NORMAL ", Color::Green),
        InputMode::Search => (" SEARCH ", Color::Cyan),
    };

    let pause_status = if *paused {
        Span::styled(" PAUSED ", Style::default().bg(Color::Red).fg(Color::White).bold())
    } else {
        Span::styled(" LIVE ", Style::default().fg(Color::Green))
    };

    let status_line = Line::from(vec![
        Span::styled(mode_text, Style::default().bg(mode_color).fg(Color::Black).bold()),
        " │ ".dark_gray().into(),
        "Filter: ".into(),
        filter.yellow().underlined(),
        " │ ".dark_gray().into(),
        "Total: ".into(),
        captured_packets.len().to_string().magenta(),
        " │ ".dark_gray().into(),
        pause_status,
    ]);

    let footer_help = " [j/k] Scroll  [/] Search  [c] Clear  [Space] Pause  [q] Quit ";

    let status_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(mode_color))
        .title_bottom(Line::from(footer_help).centered().dark_gray());

    let status_widget = Paragraph::new(status_line).block(status_block);
    f.render_widget(status_widget, main_chunks[1]);
}
