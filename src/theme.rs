use ratatui::style::{Color, Modifier, Style};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::sync::OnceLock;

// Simple container for our TOML structure
#[derive(Deserialize)]
struct Config {
    colors: HashMap<String, (u8, u8, u8)>,
}

pub struct Theme;

static THEME_CACHE: OnceLock<Config> = OnceLock::new();

impl Theme {
    /// Loads the theme.toml from disk
    fn config() -> &'static Config {
        THEME_CACHE.get_or_init(|| {
            let content = fs::read_to_string("theme.toml").expect("Failed to read theme.toml");
            toml::from_str(&content).expect("Failed to parse theme.toml")
        })
    }

    pub fn get(class: &str) -> Style {
        let colors = &Self::config().colors;

        // Helper to convert (u8, u8, u8) to ratatui Color
        let to_color = |key: &str| {
            colors.get(key)
                .map(|&(r, g, b)| Color::Rgb(r, g, b))
                .unwrap_or(Color::Rgb(200, 200, 200)) // Fallback Gray
        };

        match class {
            "rx" => Style::default().fg(to_color("rx")),
            "tx" => Style::default().fg(to_color("tx")),
            "total" => Style::default().fg(to_color("total")),
            
            "border_active" => Style::default().fg(to_color("border_active")),
            "border_inactive" => Style::default().fg(to_color("border_inactive")),
            "border_focus" => Style::default().fg(to_color("border_focus")),

            "highlight" => Style::default()
                .bg(to_color("highlight_bg"))
                .fg(to_color("highlight_fg"))
                .add_modifier(Modifier::BOLD),

            "search_typing" => Style::default().fg(to_color("border_focus")).add_modifier(Modifier::BOLD),
            "tab_selected" => Style::default().fg(to_color("border_focus")).add_modifier(Modifier::BOLD),
            
            "app_name" => Style::default().fg(to_color("app_name")),
            "dim" => Style::default().fg(to_color("dim")).add_modifier(Modifier::ITALIC),

            // Fallback for everything else
            _ => Style::default().fg(to_color("dim")),
        }
    }
}
