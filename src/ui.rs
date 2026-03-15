use crate::capture::{GlobalStats, PacketData};
use crate::{InputMode, Tab};
use crate::theme::Theme; 
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{
        Block, Borders, List, ListItem, ListState, Paragraph, Sparkline, Tabs, Wrap,
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
                    .title(" NET-SNIFF-RS ")
                    .border_style(Theme::get("border_inactive")),
            )
            .select(active_tab as usize)
            .highlight_style(Theme::get("tab_selected")),
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

    // --- FILTER BOX LOGIC ---
    let filter_style = if *mode == InputMode::Search {
        Theme::get("search_typing")
    } else {
        Theme::get("search_idle")
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
            if *mode == InputMode::Normal {
                Theme::get("status_mode_normal")
            } else {
                Theme::get("status_mode_search")
            }
        ),
        " ".into(),
    ];

    if let Some(_idx) = selected_spike_idx {
        status_line.push(Span::styled(" INSPECTOR MODE ", Theme::get("status_inspector")));
    } else if *is_saving {
        status_line.push(Span::styled(" RECORDING ", Theme::get("status_recording")));
    } else {
        status_line.push(if *paused {
            Span::styled(" PAUSED ", Theme::get("status_paused"))
        } else {
            Span::styled(" LIVE ", Theme::get("status_live"))
        });
    }

    let mut hints = vec!["[q] Quit", "[1/2] Tabs"];
    if *mode == InputMode::Normal {
        hints.push("[/] Search");
        hints.push("[Space] Pause");
        if *paused {
            hints.push("[←/→] Scrub Spike");
        }
        if active_tab == Tab::Feed {
            hints.push("[c] Clear");
        }
    }

    f.render_widget(
        Paragraph::new(Line::from(status_line)).block(
            Block::default().borders(Borders::ALL)
                .border_style(Theme::get("border_inactive"))
                .title_bottom(
                Line::from(format!(" {} ", hints.join(" | ")))
                    .centered()
                    .style(Theme::get("dim")),
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
    global_stats: &GlobalStats,
) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let filter_low = filter.to_lowercase();

    let filtered: Vec<&PacketData> = packets
        .iter()
        .filter(|p| {
            let matches_text = filter.is_empty() 
                || p.summary.to_lowercase().contains(&filter_low)
                || p.app_name.to_lowercase().contains(&filter_low);
            if !filter.is_empty(){
                return matches_text;
            }
            if let Some(idx) = spike_idx {
                if let Some(ref_time) = pause_time {
                    let seconds_before_pause = (history.len().saturating_sub(1 + idx)) as u64;
                    if p.timestamp > ref_time { return false; }
                    let packet_age_at_pause = ref_time.duration_since(p.timestamp).as_secs();
                    return packet_age_at_pause == seconds_before_pause;
                }
            }
            true
        })
        .collect();

    let items: Vec<ListItem> = filtered
        .iter()
        .map(|p| {
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:<12}", p.app_name), Theme::get("app_name")),
                Span::styled(format!(" {} ", p.country_code), Theme::get("country")),
                Span::styled(format!("  |  {}", p.summary), Theme::get("payload")),
            ]))
        })
        .collect();

    f.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(" 📡 LIVE PACKET STREAM ")
                    .borders(Borders::ALL)
                    .border_style(Theme::get("border_active")),
            )
            .highlight_style(Theme::get("highlight")),
        chunks[0],
        list_state,
    );

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
                            .border_style(Theme::get("border_focus")),
                    )
                    .wrap(Wrap { trim: false }),
                chunks[1],
            );
        }
    } else if let Some(s_idx) = spike_idx {
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
            format_bytes(val),
            filtered.len(),
            top_app
        );

        f.render_widget(
            Paragraph::new(info)
                .block(
                    Block::default()
                        .title(" SPIKE SUMMARY ")
                        .borders(Borders::ALL)
                        .border_style(Theme::get("total").add_modifier(Modifier::BOLD)),
                )
                .wrap(Wrap { trim: false }),
            chunks[1],
        );
    } else {
        let stats_summary = format!(
            "\n\n    --- 📊 SESSION TRAFFIC ---\n\n\n\
                ▼ DOWNLOADED:   {}\n\
                ▲ UPLOADED:     {}\n\n\
                Captured:      {} packets\n\n\n",
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
                        .border_style(Theme::get("total")),
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
        .constraints([Constraint::Length(15), Constraint::Min(0)])
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
                    .border_style(Theme::get("total")),
            )
            .data(throughput)
            .max(total_max)
            .style(Theme::get("total")),
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
                    .border_style(Theme::get("rx")),
            )
            .data(rx_history)
            .max(rx_max)
            .style(Theme::get("rx")),
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
                    .border_style(Theme::get("tx")),
            )
            .data(tx_history)
            .max(tx_max)
            .style(Theme::get("tx")),
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
                    Theme::get("app_name"),
                ),
                format!(" │ {} │ ", proto).into(),
                Span::styled(format_bytes(**bytes), Theme::get("total")),
            ]))
        })
        .collect();

    f.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(" SESSIONS ")
                    .borders(Borders::ALL)
                    .border_style(Theme::get("total")),
            )
            .highlight_style(Theme::get("highlight")),
        bottom_chunks[0],
        list_state,
    );

    if let Some(idx) = list_state.selected() {
        if let Some((key, bytes)) = filtered_conns.get(idx) {
            let (src, dst, proto, app, country) = key;
            let info = format!(
                "Application: {}\nCountry code: {}\nProtocol:    {}\nSource:      {}\nDestination: {}\nTotal Data:  {}",
                app, country, proto, src, dst, format_bytes(**bytes),
            );
            f.render_widget(
                Paragraph::new(info)
                    .block(
                        Block::default()
                            .title(" SESSION DETAIL ")
                            .borders(Borders::ALL)
                            .border_style(Theme::get("border_focus")),
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
                    .border_style(Theme::get("total")),
            ),
            bottom_chunks[1],
        );
    }
}
