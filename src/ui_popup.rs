use crate::theme::Theme;
use crate::SearchScope;
use ratatui::{
    Frame,
    layout::Constraint,
    style::Modifier,
    widgets::{
        Block, Borders, List, ListItem, Clear,Row,Table
    },
};
use crate::ui_utils::centered_rect;

pub fn draw_help_popup(f: &mut Frame, search_scope: &SearchScope) {
    let area = centered_rect(70, 70, f.area());
    f.render_widget(Clear, area);

    let key_style = Theme::get("border_focus").add_modifier(Modifier::BOLD);
    let desc_style = Theme::get("dim");
let scope_label = format!("Cycle Scope (Now: {})", search_scope.label());
    let rows = vec![
        // --- NAVIGATION ---
        Row::new(vec![" NAVIGATION", ""]).style(Theme::get("total").add_modifier(Modifier::BOLD)),
        Row::new(vec!["  [1 / 2]", "Switch Tabs (Connections / Feed)"]).style(desc_style),
        Row::new(vec!["  [j / k] or [↑ / ↓]", "Scroll List Items"]).style(desc_style),
        Row::new(vec!["  [← / →]", "Scrub spikes (In Inspector Mode)"]).style(desc_style),
        
        // --- SEARCH MODE ---
        Row::new(vec!["", ""]), 
        Row::new(vec![" SEARCH MODE", ""]).style(Theme::get("rx").add_modifier(Modifier::BOLD)),
        Row::new(vec!["  [/]", "Enter Filter Mode"]).style(desc_style),
Row::new(vec![
        "  [Tab]".to_string(), 
        scope_label 
    ]).style(key_style),
        Row::new(vec!["  [Enter / ESC]", "Confirm / Clear and Exit"]).style(desc_style),

        // --- SYSTEM & RECORDING ---
        Row::new(vec!["", ""]), 
        Row::new(vec![" SYSTEM & TOOLS", ""]).style(Theme::get("tx").add_modifier(Modifier::BOLD)),
        Row::new(vec!["  [Space]", "Pause / Resume Live Feed"]).style(desc_style),
        Row::new(vec!["  [w]", "Toggle PCAP Recording"]).style(desc_style),
        Row::new(vec!["  [t]", "Open Theme Browser"]).style(desc_style),
        Row::new(vec!["  [c]", "Clear Session History"]).style(desc_style),
        Row::new(vec!["  [h / ESC]", "Close Help / Popups"]).style(desc_style),
        Row::new(vec!["  [q]", "Quit Net-Sniff-Rs"]).style(desc_style),
    ];

    let table = Table::new(rows, [Constraint::Length(25), Constraint::Min(20)])
        .block(
            Block::default()
                .title(" ⌨️ COMMAND PALETTE ")
                .borders(Borders::ALL)
                .border_style(Theme::get("border_focus")),
        )
        .header(Row::new(vec!["  COMMAND", "FUNCTION"]).style(key_style).bottom_margin(1));

    f.render_widget(table, area);
}
pub fn draw_theme_popup(f: &mut Frame, selected_index: usize) {
    let area = centered_rect(30, 50, f.area());
    f.render_widget(Clear, area);

    // Get the dynamic list from the folder
    let available_themes = Theme::list_themes();
    
    let items: Vec<ListItem> = if available_themes.is_empty() {
        vec![ListItem::new(" No themes found in ./themes ").style(Theme::get("dim"))]
    } else {
        available_themes
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let style = if i == selected_index {
                    Theme::get("highlight")
                } else {
                    Theme::get("dim")
                };
                // Capitalize first letter for the UI
                let display_name = format!("  {}  ", name.to_uppercase());
                ListItem::new(display_name).style(style)
            })
            .collect()
    };

    let list = List::new(items)
        .block(
            Block::default()
                .title(" 🎨 THEME BROWSER ")
                .borders(Borders::ALL)
                .border_style(Theme::get("border_focus")),
        );

    f.render_widget(list, area);
}
