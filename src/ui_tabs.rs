use crate::capture::{GlobalStats, PacketData};
use crate::App;
use crate::theme::Theme;
use crate::SearchScope;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::Modifier,
    text::{Line, Span},
    widgets::{
        Block, Borders, List, ListItem, ListState, Paragraph, Sparkline, Wrap
    },
};
use std::collections::HashMap;
use std::time::Instant;
use crate::ui_utils::format_bytes;

pub fn draw_feed_tab(
    f: &mut Frame,
    area: Rect,
    packets: &[PacketData],
    filter: &str,
    list_state: &mut ListState,
    spike_idx: Option<usize>,
    history: &[u64],
    pause_time: Option<Instant>,
    global_stats: &GlobalStats,
    app:&App
) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let filter_low = filter.to_lowercase();

let filtered: Vec<&PacketData> = packets
    .iter()
    .filter(|p| {
        let filter_low = filter.to_lowercase();
        
        // 1. Check Search Match based on Scope
        let matches_search = if filter.is_empty() {
            true
        } else {
            match app.search_scope {
                SearchScope::AppName => p.app_name.to_lowercase().contains(&filter_low),
                SearchScope::Summary => p.summary.to_lowercase().contains(&filter_low),
                SearchScope::Hex => p.hex_dump.to_lowercase().contains(&filter_low),
            }
        };

        // If it doesn't match the search text, discard it immediately
        if !matches_search {
            return false;
        }

        // 2. Check Spike/Time Match (only if we aren't searching globally)
        // Note: If you want search to work *within* a spike, keep this. 
        // If you want search to be global, you'd skip this when filter is active.
        if let Some(idx) = spike_idx {
            if let Some(ref_time) = pause_time {
                let seconds_before_pause = (history.len().saturating_sub(1 + idx)) as u64;
                if p.timestamp > ref_time { return false; }
                let packet_age_at_pause = ref_time.duration_since(p.timestamp).as_secs();
                
                // Only return true if it belongs to this specific second of the spike
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

pub fn draw_connections_tab(
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
