use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize, Modifier},
    text::{Line, Span},
    widgets::{BarChart, Block, Borders, List, ListItem, ListState, Paragraph, Tabs, Wrap},
    Frame,
    symbols::bar,
};
use std::collections::HashMap;
use crate::capture::PacketData;
use crate::{InputMode, Tab};

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

pub fn draw(
    f: &mut Frame,
    active_tab: Tab,
    local_packets: &[PacketData],
    connections: &HashMap<(String, String, String, String), u64>,
    throughput_history: &[u64],
    paused: &bool,
    is_saving: &bool,
    filter: &str,
    mode: &InputMode,
    feed_list_state: &mut ListState,
    connections_list_state: &mut ListState,
) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(f.area());

    // --- TABS (Styled with Borders) ---
    let titles = vec![" 📡 [1] FEED ", " 🌐 [2] CONNECTIONS "];
    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title(" NET-SNIFF-RS "))
        .select(active_tab as usize)
        .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
        .divider(Span::raw("|").dark_gray());
    f.render_widget(tabs, main_chunks[0]);

    match active_tab {
        Tab::Feed => draw_feed_tab(f, main_chunks[1], local_packets, filter, feed_list_state),
        Tab::Connections => draw_connections_tab(f, main_chunks[1], connections, throughput_history, filter, connections_list_state),
    }

    // --- STATUS BAR (Enhanced High-Visibility) ---
    let mut status_line = vec![
        Span::styled(
            match mode { InputMode::Normal => " NORMAL ", InputMode::Search => " SEARCH " },
            Style::default().bg(if *mode == InputMode::Normal { Color::Blue } else { Color::Magenta }).fg(Color::Black).bold()
        ),
        " ".into(),
        if *paused { " PAUSED ".on_red().white().bold() } else { " LIVE ".on_green().white().bold() },
        " ".into(),
    ];

    if *is_saving {
        status_line.push(Span::styled(" ● RECORDING ", Style::default().bg(Color::Red).fg(Color::White).bold()));
    }

    status_line.push(" │ ".dark_gray().into());
    status_line.push("Filter: ".gray());
    status_line.push(if filter.is_empty() { "none".dark_gray() } else { filter.yellow().underlined() });

    let footer = Paragraph::new(Line::from(status_line))
        .block(Block::default().borders(Borders::ALL)
            .title_bottom(Line::from(" [w] Rec [Space] Pause [/] Search [1/2] Tabs [q] Quit ").centered().dark_gray()));
    f.render_widget(footer, main_chunks[2]);
}

fn draw_feed_tab(f: &mut Frame, area: Rect, packets: &[PacketData], filter: &str, list_state: &mut ListState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let filtered: Vec<&PacketData> = packets.iter()
        .filter(|p| filter.is_empty() || p.summary.to_lowercase().contains(&filter.to_lowercase()) || p.app_name.to_lowercase().contains(&filter.to_lowercase()))
        .collect();
    
    let items: Vec<ListItem> = filtered.iter().map(|p| {
        let color = if p.app_name == "Unknown" { Color::DarkGray } else { Color::Green };
        ListItem::new(Line::from(vec![
            Span::styled(format!("{:<12}", p.app_name), Style::default().fg(color)),
            Span::raw(format!(" │ {}", p.summary)).white(),
        ]))
    }).collect();

    f.render_stateful_widget(
        List::new(items)
            .block(Block::default().title(" STREAM ").borders(Borders::ALL).border_style(Style::default().fg(Color::Green)))
            .highlight_style(Style::default().bg(Color::Rgb(30, 30, 30)).add_modifier(Modifier::BOLD))
            .highlight_symbol(">> "),
        chunks[0],
        list_state,
    );

    if let Some(idx) = list_state.selected() {
        if let Some(packet) = filtered.get(idx) {
            let details_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
                .split(chunks[1]);

            f.render_widget(
                Paragraph::new(packet.full_details.as_str())
                    .block(Block::default().title(" INSPECTOR ").borders(Borders::ALL).yellow())
                    .wrap(Wrap { trim: false }),
                details_chunks[0]
            );

            f.render_widget(
                Paragraph::new(packet.hex_dump.as_str())
                    .block(Block::default().title(" HEX ").borders(Borders::ALL).blue())
                    .style(Style::default().fg(Color::Rgb(100, 100, 100))),
                details_chunks[1]
            );
        }
    }
}

fn draw_connections_tab(f: &mut Frame, area: Rect, connections: &HashMap<(String, String, String, String), u64>, throughput_history: &[u64], filter: &str, list_state: &mut ListState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(0)])
        .split(area);

    // --- FIXED CHART LOGIC ---
    // BarChart needs data that fits the visible width. We slice the history to fit.
    let chart_width = chunks[0].width.saturating_sub(2);
    let bar_width = 3; 
    let gap = 1;
    let max_bars = (chart_width as usize) / (bar_width + gap);
    
    let history_slice = if throughput_history.len() > max_bars {
        &throughput_history[throughput_history.len() - max_bars..]
    } else {
        throughput_history
    };

    // Normalize or cap the data if it's too large for the widget to render bars effectively
    let barchart_data: Vec<(&str, u64)> = history_slice.iter().map(|&v| ("", v)).collect();

    let barchart = BarChart::default()
        .block(Block::default()
            .title(format!(" THROUGHPUT: {}/s ", format_bytes(*throughput_history.last().unwrap_or(&0))))
            .borders(Borders::ALL).cyan())
        .data(&barchart_data)
        .bar_width(bar_width as u16)
        .bar_gap(gap as u16)
        .bar_style(Style::default().fg(Color::Cyan))
        .bar_set(bar::NINE_LEVELS);
    
    f.render_widget(barchart, chunks[0]);

    // --- CONNECTION LIST ---
    let mut sorted: Vec<_> = connections.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));

    let items: Vec<ListItem> = sorted.into_iter()
        .filter(|(key, _)| filter.is_empty() || format!("{:?}", key).to_lowercase().contains(&filter.to_lowercase()))
        .map(|(key, &bytes)| {
            let (src, dst, proto, app) = key;
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:<15}", app), Style::default().fg(Color::Green)),
                format!(" │ {} -> {} │ {} │ ", src, dst, proto).into(),
                Span::styled(format_bytes(bytes), Style::default().fg(Color::Cyan).bold()),
            ]))
        }).collect();

    f.render_stateful_widget(
        List::new(items)
            .block(Block::default().title(" SESSIONS ").borders(Borders::ALL).border_style(Style::default().fg(Color::Cyan)))
            .highlight_style(Style::default().bg(Color::Rgb(30, 30, 30))),
        chunks[1],
        list_state,
    );
}
