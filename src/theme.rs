use notify::{Config as NotifyConfig, RecursiveMode, Watcher};
use ratatui::style::{Color, Modifier, Style};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Once, RwLock};
#[derive(Deserialize, Clone, Default)]
struct ThemeConfig {
    colors: HashMap<String, (u8, u8, u8)>,
}

pub struct Theme;

static THEME_DATA: RwLock<Option<ThemeConfig>> = RwLock::new(None);
static START_WATCHER: Once = Once::new();

impl Theme {
    fn load_and_apply() {
        let path = "theme.toml";

        // Try to read the file; if it fails, use a hardcoded default so the UI doesn't break
        let config = fs::read_to_string(path)
            .and_then(|content| {
                toml::from_str::<ThemeConfig>(&content)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
            })
            .unwrap_or_else(|_| {
                // Fallback default colors if file is missing or broken
                let mut fallback = HashMap::new();
                fallback.insert("rx".to_string(), (0, 255, 127));
                fallback.insert("tx".to_string(), (255, 0, 255));
                fallback.insert("total".to_string(), (0, 210, 255));
                ThemeConfig { colors: fallback }
            });

        let mut data = THEME_DATA.write().unwrap();
        *data = Some(config);
    }

    pub fn init() {
        START_WATCHER.call_once(|| {
            Self::load_and_apply();

            // Background thread to watch for changes
            std::thread::spawn(|| {
                let (tx, rx) = std::sync::mpsc::channel();
                // Use default config for watcher
                let mut watcher = notify::recommended_watcher(tx).unwrap();

                if watcher
                    .watch(
                        std::path::Path::new("theme.toml"),
                        RecursiveMode::NonRecursive,
                    )
                    .is_ok()
                {
                    for res in rx {
                        match res {
                            Ok(_) => Self::load_and_apply(),
                            Err(e) => eprintln!("watch error: {:?}", e),
                        }
                    }
                }
            });
        });
    }

    pub fn get(class: &str) -> Style {
        // Ensure data is loaded
        if THEME_DATA.read().unwrap().is_none() {
            Self::load_and_apply();
        }

        let guard = THEME_DATA.read().unwrap();
        let colors = &guard.as_ref().unwrap().colors;

        let to_color = |key: &str| {
            colors
                .get(key)
                .map(|&(r, g, b)| Color::Rgb(r, g, b))
                .unwrap_or(Color::Rgb(150, 150, 150)) // Fallback gray
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
            "app_name" => Style::default().fg(to_color("app_name")),
            "country" => Style::default()
                .fg(to_color("country"))
                .add_modifier(Modifier::BOLD),
            "payload" => Style::default().fg(to_color("payload")),
            "dim" => Style::default()
                .fg(to_color("dim"))
                .add_modifier(Modifier::ITALIC),
            _ => Style::default().fg(to_color("dim")),
        }
    }
    pub fn list_themes() -> Vec<String> {
        let mut themes = Vec::new();
        let path = std::path::Path::new("./themes");

        // Create directory if it doesn't exist
        if !path.exists() {
            let _ = std::fs::create_dir_all(path);
            return themes;
        }

        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                    if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                        themes.push(name.to_string());
                    }
                }
            }
        }
        themes.sort();
        themes
    }
    pub fn apply_theme_file(name: &str) {
        let source = format!("./themes/{}.toml", name);
        let destination = "theme.toml";

        if let Err(e) = std::fs::copy(&source, destination) {
            eprintln!("Error applying theme {}: {}", name, e);
        }
        // The file watcher we built earlier will see theme.toml change
        // and trigger the reload automatically!
    }
}
