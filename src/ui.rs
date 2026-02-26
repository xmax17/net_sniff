use crate::capture::PacketData;
use crate::{InputMode, Tab};
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style, Stylize},
    text::{Line, Span},
    widgets::{BarChart, Block, Borders, List, ListItem, ListState, Paragraph, Tabs, Wrap},
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
    connections: &HashMap<(String, String, String, String), u64>,
    throughput_history: &[u64],
    paused: &bool,
    is_saving: &bool,
    filter: &str,
    mode: &InputMode,
    feed_list_state: &mut ListState,
    connections_list_state: &mut ListState,
    selected_spike_idx: Option<usize>,
    pause_time: Option<Instant>,
) {
    let main_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(5),
            Constraint::Length(3),
        ])
        .split(f.area());

    // --- TABS ---
    let titles = vec![" 📡 [1] FEED ", " 🌐 [2] CONNECTIONS "];
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
        Tab::Feed => draw_feed_tab(
            f,
            main_chunks[1],
            local_packets,
            filter,
            feed_list_state,
            selected_spike_idx,
            throughput_history,
            pause_time,
        ),
        Tab::Connections => draw_connections_tab(
            f,
            main_chunks[1],
            connections,
            throughput_history,
            filter,
            connections_list_state,
            selected_spike_idx,
        ),
    }

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
    } else {
        status_line.push(if *paused {
            " PAUSED ".on_red().white().bold()
        } else {
            " LIVE ".on_green().white().bold()
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
        main_chunks[2],
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
) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    // Filter packets to the specific spike window
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
                filter.is_empty() || p.summary.to_lowercase().contains(&filter.to_lowercase())
            }
        })
        .collect();

    // LEFT: List rendering
    let items: Vec<ListItem> = filtered
        .iter()
        .map(|p| {
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{:<12}", p.app_name),
                    Style::default().fg(Color::Green),
                ),
                Span::raw(format!(" │ {}", p.summary)).white(),
            ]))
        })
        .collect();

    f.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(" PACKET STREAM ")
                    .borders(Borders::ALL)
                    .green(),
            )
            .highlight_style(Style::default().bg(Color::Rgb(40, 40, 40)).bold()),
        chunks[0],
        list_state,
    );

    // RIGHT: DYNAMIC INSPECTOR WITH TOP TALKERS
    if let Some(p_idx) = list_state.selected() {
        if let Some(packet) = filtered.get(p_idx) {
            f.render_widget(
                Paragraph::new(packet.full_details.clone())
                    .block(
                        Block::default()
                            .title(" PACKET DETAIL ")
                            .borders(Borders::ALL)
                            .yellow(),
                    )
                    .wrap(Wrap { trim: false }),
                chunks[1],
            );
        }
    } else if let Some(s_idx) = spike_idx {
        // Calculate Top Talker for this specific spike
        let mut app_counts = HashMap::new();
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
              Primary App:     {}\n\n\
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
                        .cyan()
                        .bold(),
                )
                .wrap(Wrap { trim: false }),
            chunks[1],
        );
    }
}

fn draw_connections_tab(
    f: &mut Frame,
    area: Rect,
    connections: &HashMap<(String, String, String, String), u64>,
    throughput: &[u64],
    filter: &str,
    list_state: &mut ListState,
    selected_idx: Option<usize>,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(0)])
        .split(area);

    let chart_width = chunks[0].width.saturating_sub(2);
    let max_bars = (chart_width as usize) / 4;
    let visible_history = if throughput.len() > max_bars {
        &throughput[throughput.len() - max_bars..]
    } else {
        throughput
    };

    let visible_selected = selected_idx.and_then(|idx| {
        let start = throughput.len().saturating_sub(max_bars);
        if idx >= start {
            Some(idx - start)
        } else {
            None
        }
    });

    let barchart_data: Vec<(&str, u64)> = visible_history
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            if Some(i) == visible_selected {
                ("SEL", v)
            } else {
                ("", v)
            }
        })
        .collect();

    f.render_widget(
        BarChart::default()
            .block(
                Block::default()
                    .title(" THROUGHPUT ")
                    .borders(Borders::ALL)
                    .cyan(),
            )
            .data(&barchart_data)
            .bar_width(3)
            .bar_gap(1)
            .bar_style(Style::default().fg(Color::Cyan))
            .value_style(Style::default().fg(Color::Yellow)),
        chunks[0],
    );

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
            let (_src, _dst, proto, app) = key;
            ListItem::new(Line::from(vec![
                Span::styled(format!("{:<10}", app), Style::default().fg(Color::Green)),
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
            let (src, dst, proto, app) = key;
            let info = format!(
                "Application: {}\nProtocol:    {}\nSource:      {}\nDestination: {}\nTotal Data:  {}",
                app,
                proto,
                src,
                dst,
                format_bytes(**bytes)
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
