use crate::capture::{GlobalStats, PacketData};
use crate::{App, InputMode, Tab};
use crate::theme::Theme;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    text::{Line, Span},
    widgets::{
        Block, Borders, ListState, Paragraph, Tabs,
    },
};
use std::collections::HashMap;
use std::time::Instant;
use crate::ui_popup::{draw_help_popup,draw_theme_popup};
use crate::ui_tabs::{draw_feed_tab,draw_connections_tab};



pub fn draw(
    f: &mut Frame,
    active_tab: Tab,
    local_packets: &[PacketData],
    connections: &HashMap<(String, String, String, String, String), u64>,
    throughput_history: &[u64],
    rx_history: &[u64],
    tx_history: &[u64],
    app:&App,
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
            &app
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
let filter_title = format!(" 🔍 SEARCHING IN: {} (Tab to cycle) ", app.search_scope.label());

f.render_widget(
    Paragraph::new(filter_display).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(filter_style)
            .title(Span::styled(filter_title, filter_style)),
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
    } else if app.is_saving {
        status_line.push(Span::styled(" RECORDING ", Theme::get("status_recording")));
    } else {
        status_line.push(if app.is_paused {
            Span::styled(" PAUSED ", Theme::get("status_paused"))
        } else {
            Span::styled(" LIVE ", Theme::get("status_live"))
        });
    }

    let mut hints = vec!["[q] Quit", "[1/2] Tabs"];
    if *mode == InputMode::Normal {
        hints.push("[/] Search");
        hints.push("[Space] Pause");
        if app.is_paused {
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
    if app.show_shortcuts {
        draw_help_popup(f,&app.search_scope);
    }
    if app.show_theme{
        draw_theme_popup(f, app.theme_index);
    }
}

