use crate::capture::{GlobalStats, PacketData};
use crate::{InputMode, Tab};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style, Stylize},
    text::{Line, Span},
    widgets::{
        BarChart, Block, Borders, List, ListItem, ListState, Paragraph, Sparkline, Tabs, Wrap,
    },
};
use std::collections::HashMap;
use std::time::Instant;

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

pub fn draw(
    f: &mut Frame,
    active_tab: Tab,
    local_packets: &[PacketData],
    connections: &HashMap<(String, String, String, String, String), u64>,
    throughput_history: &[u64],
    rx_history: &[u64],
    tx_history: &[u64],
    paused: &bool,
    is_saving: &bool,
    filter: &str,
    mode: &InputMode,
    feed_list_state: &mut ListState,
    connections_list_state: &mut ListState,
    selected_spike_idx: Option<usize>,
    pause_time: Option<Instant>,
    global_stats: &GlobalStats,
) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
            Constraint::Length(3),
        ])
        .split(f.area());

    // --- TABS ---
    let titles = vec!["🌐 [1] CONNECTIONS ", " 📡 [2] FEED "];
    f.render_widget(
        Tabs::new(titles)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" NET-SNIFF-RS "),
            )
            .select(active_tab as usize)
            .highlight_style(Style::default().fg(Color::Yellow).bold()),
        main_chunks[0],
    );

    match active_tab {
        Tab::Connections => draw_connections_tab(
            f,
            main_chunks[1],
            connections,
            rx_history,
            tx_history,
            throughput_history,
            filter,
            connections_list_state,
            selected_spike_idx,
            &global_stats,
        ),
        Tab::Feed => draw_feed_tab(
            f,
            main_chunks[1],
            local_packets,
            filter,
            feed_list_state,
            selected_spike_idx,
            throughput_history,
            pause_time,
            global_stats,
        ),
    }
    let filter_style = if *mode == InputMode::Search {
        Style::default().fg(Color::Yellow).bold() // Highlight when typing
    } else {
        Style::default().fg(Color::DarkGray) // Dim when just viewing
    };

    let filter_display = if filter.is_empty() && *mode != InputMode::Search {
        " (Press '/' to filter results)".to_string()
    } else {
        format!(" {}", filter)
    };

    f.render_widget(
        Paragraph::new(filter_display).block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(filter_style)
                .title(Span::styled(" 🔍 FILTER ", filter_style)),
        ),
        main_chunks[2],
    );

    // --- DYNAMIC FOOTER ---
    let mut status_line = vec![
        Span::styled(
            format!(" {:?} ", mode),
            Style::default()
                .bg(if *mode == InputMode::Normal {
                    Color::Blue
                } else {
                    Color::Magenta
                })
                .fg(Color::Black)
                .bold(),
        ),
        " ".into(),
    ];

    if let Some(_idx) = selected_spike_idx {
        status_line.push(Span::styled(
            " INSPECTOR MODE ",
            Style::default().bg(Color::Yellow).fg(Color::Black).bold(),
        ));
    } else if *is_saving {
        status_line.push(Span::styled(
            " RECORDING ",
            Style::default().bg(Color::Red).fg(Color::Black).bold(),
        ))
    } else {
        status_line.push(if *paused {
            Span::styled(
                " PAUSED ",
                Style::default().bg(Color::Black).fg(Color::White).bold(),
            )
        } else {
            Span::styled(
                " LIVE ",
                Style::default().bg(Color::Cyan).fg(Color::White).bold(),
            )
        });
    }

    let mut hints = vec!["[q] Quit", "[1/2] Tabs"];
    if *mode == InputMode::Normal {
        hints.push("[/] Search");
        hints.push("[Space] Pause");
        if *paused {
            hints.push("[←/→] Scrub Spike");
        }
    }

    f.render_widget(
        Paragraph::new(Line::from(status_line)).block(
            Block::default().borders(Borders::ALL).title_bottom(
                Line::from(format!(" {} ", hints.join(" | ")))
                    .centered()
                    .dark_gray()
                    .italic(),
            ),
        ),
        main_chunks[3],
    );
}

fn draw_feed_tab(
    f: &mut Frame,
    area: Rect,
    packets: &[PacketData],
    filter: &str,
    list_state: &mut ListState,
    spike_idx: Option<usize>,
    history: &[u64],
    pause_time: Option<Instant>,
    global_stats: &GlobalStats, // Added to match the graph's data source
) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let filter_low = filter.to_lowercase();

    // --- FILTERING LOGIC ---
    let filtered: Vec<&PacketData> = packets
        .iter()
        .filter(|p| {
            if let Some(idx) = spike_idx {
                if let Some(ref_time) = pause_time {
                    let seconds_before_pause = (history.len().saturating_sub(1 + idx)) as u64;
                    if p.timestamp > ref_time {
                        return false;
                    }
                    let packet_age_at_pause = ref_time.duration_since(p.timestamp).as_secs();
                    packet_age_at_pause == seconds_before_pause
                } else {
                    false
                }
            } else {
                filter.is_empty()
                    || p.summary.to_lowercase().contains(&filter_low)
                    || p.app_name.to_lowercase().contains(&filter_low)
            }
        })
        .collect();

    // --- LEFT: PACKET STREAM RENDERING ---
    let items: Vec<ListItem> = filtered
        .iter()
        .map(|p| {
            ListItem::new(Line::from(vec![
                // App Name in Green
                Span::styled(
                    format!("{:<12}", p.app_name),
                    Style::default().fg(Color::Green),
                ),
                // Fixed-width Country Badge in Yellow
                Span::styled(
                    format!(" {} ", p.country_code),
                    Style::default().fg(Color::Yellow).bold(),
                ),
                Span::styled(
                    format!("  |  {}", p.summary),
                    Style::default().fg(Color::Cyan),
                ),
            ]))
        })
        .collect();

    f.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(" 📡 LIVE PACKET STREAM ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Green)),
            )
            .highlight_style(Style::default().bg(Color::Rgb(40, 40, 40)).bold()),
        chunks[0],
        list_state,
    );

    // --- RIGHT: DYNAMIC INSPECTOR ---

    // 1. If a packet is selected: Show Hex/Details
    if let Some(p_idx) = list_state.selected() {
        if let Some(packet) = filtered.get(p_idx) {
            let display_text = format!(
                "{}\n\n--- RAW PAYLOAD (HEX) ---\n{}",
                packet.full_details, packet.hex_dump
            );

            f.render_widget(
                Paragraph::new(display_text)
                    .block(
                        Block::default()
                            .title(" 🔍 PACKET INSPECTOR ")
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::Yellow)),
                    )
                    .wrap(Wrap { trim: false }),
                chunks[1],
            );
        }
    }
    // 2. If scrubbing through a spike: Show Spike Analysis
    else if let Some(s_idx) = spike_idx {
        let mut app_counts = std::collections::HashMap::new();
        for p in &filtered {
            *app_counts.entry(&p.app_name).or_insert(0) += 1;
        }
        let top_app = app_counts
            .iter()
            .max_by_key(|&(_, count)| count)
            .map(|(name, _)| name.as_str())
            .unwrap_or("None");

        let val = history.get(s_idx).cloned().unwrap_or(0);
        let info = format!(
            "\n  --- 🔎 SPIKE ANALYSIS ---\n\n\
              Target Window:   {}s ago\n\
              Total Load:      {}\n\
              Packet Count:    {}\n\n\
              --- 🏆 TOP TALKER ---\n\
              Primary App:      {}\n\n\
              --- ⌨️  NAVIGATION ---\n\
              [↑/↓] Browse specific packets\n\
              [←/→] Shift time window",
            history.len().saturating_sub(1 + s_idx),
            format_bytes(val), // Use your specific formatter
            filtered.len(),
            top_app
        );

        f.render_widget(
            Paragraph::new(info)
                .block(
                    Block::default()
                        .title(" SPIKE SUMMARY ")
                        .borders(Borders::ALL)
                        .border_style(
                            Style::default()
                                .fg(Color::Cyan)
                                .add_modifier(Modifier::BOLD),
                        ),
                )
                .wrap(Wrap { trim: false }),
            chunks[1],
        );
    }
    // 3. Default state: Show Session Totals (Matches Graph Style)
    else {
        let stats_summary = format!(
            "\n\n   --- 📊 SESSION TRAFFIC ---\n\n\n\
               ▼ DOWNLOADED:   {}\n\
               ▲ UPLOADED:     {}\n\n\
               Captured:      {} packets\n\n\n\
",
            format_bytes(global_stats.total_rx),
            format_bytes(global_stats.total_tx),
            packets.len()
        );

        f.render_widget(
            Paragraph::new(stats_summary)
                .block(
                    Block::default()
                        .title(" 📈 GLOBAL STATS ")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Cyan)),
                )
                .wrap(Wrap { trim: false }),
            chunks[1],
        );
    }
}

fn draw_connections_tab(
    f: &mut Frame,
    area: Rect,
    connections: &HashMap<(String, String, String, String, String), u64>,
    rx_history: &[u64],
    tx_history: &[u64],
    throughput: &[u64],
    filter: &str,
    list_state: &mut ListState,
    selected_idx: Option<usize>,
    global_stats: &GlobalStats,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(15), Constraint::Min(0)]) // 15 is usually enough for 3 sparklines
        .split(area);

    let graph_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(chunks[0]);

    // 1. TOTAL THROUGHPUT
    let total_max = *throughput.iter().max().unwrap_or(&100);
    f.render_widget(
        Sparkline::default()
            .block(
                Block::default()
                    .title(format!(" 📊 TOTAL (Peak: {}) ", format_bytes(total_max)))
                    .borders(Borders::ALL)
                    .cyan(),
            )
            .data(throughput)
            .max(total_max)
            .style(Style::default().fg(Color::Cyan)),
        graph_chunks[0],
    );

    // 2. RX SPARKLINE
    let rx_max = *rx_history.iter().max().unwrap_or(&100);
    f.render_widget(
        Sparkline::default()
            .block(
                Block::default()
                    .title(format!(" ▼ RX ({}) ", format_bytes(rx_max)))
                    .borders(Borders::ALL)
                    .green(),
            )
            .data(rx_history) // Use the slice passed as argument
            .max(rx_max)
            .style(Style::default().fg(Color::Green)),
        graph_chunks[1],
    );

    // 3. TX SPARKLINE
    let tx_max = *tx_history.iter().max().unwrap_or(&100);
    f.render_widget(
        Sparkline::default()
            .block(
                Block::default()
                    .title(format!(" ▲ TX ({}) ", format_bytes(tx_max)))
                    .borders(Borders::ALL)
                    .magenta(),
            )
            .data(tx_history) // Use the slice passed as argument
            .max(tx_max)
            .style(Style::default().fg(Color::Magenta)),
        graph_chunks[2],
    );

    // --- BOTTOM SECTION (SESSIONS) ---
    let bottom_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(chunks[1]);

    let mut sorted: Vec<_> = connections.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    let filtered_conns: Vec<_> = sorted
        .into_iter()
        .filter(|(key, _)| {
            filter.is_empty()
                || format!("{:?}", key)
                    .to_lowercase()
                    .contains(&filter.to_lowercase())
        })
        .collect();

    let items: Vec<ListItem> = filtered_conns
        .iter()
        .map(|(key, bytes)| {
            let (_src, _dst, proto, app, country) = key;
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{:<10} | {}", app, country),
                    Style::default().fg(Color::Green),
                ),
                format!(" │ {} │ ", proto).into(),
                Span::styled(format_bytes(**bytes), Style::default().fg(Color::Cyan)),
            ]))
        })
        .collect();

    f.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(" SESSIONS ")
                    .borders(Borders::ALL)
                    .cyan(),
            )
            .highlight_style(Style::default().bg(Color::Rgb(40, 40, 40))),
        bottom_chunks[0],
        list_state,
    );

    if let Some(idx) = list_state.selected() {
        if let Some((key, bytes)) = filtered_conns.get(idx) {
            let (src, dst, proto, app, country) = key;
            let info = format!(
                "Application: {}\nCountry code: {}\nProtocol:    {}\nSource:      {}\nDestination: {}\nTotal Data:  {}",
                app,
                country,
                proto,
                src,
                dst,
                format_bytes(**bytes),
            );
            f.render_widget(
                Paragraph::new(info)
                    .block(
                        Block::default()
                            .title(" SESSION DETAIL ")
                            .borders(Borders::ALL)
                            .yellow(),
                    )
                    .wrap(Wrap { trim: false }),
                bottom_chunks[1],
            );
        }
    } else if let Some(s_idx) = selected_idx {
        let val = throughput.get(s_idx).cloned().unwrap_or(0);
        let info = format!(
            "\n  --- 📊 SNAPSHOT OVERVIEW ---\n\n  Load:      {}\n  Index:     {}\n\n  This represents a cumulative\n  total for all connections\n  during this 1s interval.",
            format_bytes(val),
            s_idx
        );
        f.render_widget(
            Paragraph::new(info).block(
                Block::default()
                    .title(" SPIKE INFO ")
                    .borders(Borders::ALL)
                    .cyan(),
            ),
            bottom_chunks[1],
        );
    }
}
