use ratatui::style::{Color,Modifier,Style};

pub struct Theme;

impl Theme {

    pub fn get(class:&str) -> Style {
        match class {
            "rx" => Style::default().fg(Color::Rgb(0, 255, 127)),      // Spring Green
            "tx" => Style::default().fg(Color::Rgb(255, 0, 255)),    // Fuchsia
            "total" => Style::default().fg(Color::Rgb(0, 210, 255)),  // Deep Sky Blue

            // --- BORDERS & TITLES ---
            "border_active" => Style::default().fg(Color::Rgb(0, 255, 127)), 
            "border_inactive" => Style::default().fg(Color::Rgb(60, 60, 60)),
            "border_focus" => Style::default().fg(Color::Rgb(255, 255, 0)), // Yellow for focus

            // --- UI INTERACTION ---
            "highlight" => Style::default().bg(Color::Rgb(45, 45, 45)).fg(Color::Rgb(255, 255, 0)).add_modifier(Modifier::BOLD),
            "search_typing" => Style::default().fg(Color::Rgb(255, 255, 0)).add_modifier(Modifier::BOLD),
            "search_idle" => Style::default().fg(Color::Rgb(100, 100, 100)),
            "tab_selected" => Style::default().fg(Color::Rgb(255, 255, 0)).add_modifier(Modifier::BOLD),

            // --- SYSTEM STATUS BADGES ---
            "status_live" => Style::default().bg(Color::Rgb(0, 210, 255)).fg(Color::Rgb(0, 0, 0)).add_modifier(Modifier::BOLD),
            "status_paused" => Style::default().bg(Color::Rgb(200, 200, 200)).fg(Color::Rgb(0, 0, 0)).add_modifier(Modifier::BOLD),
            "status_recording" => Style::default().bg(Color::Rgb(255, 50, 50)).fg(Color::Rgb(255, 255, 255)).add_modifier(Modifier::BOLD),
            "status_inspector" => Style::default().bg(Color::Rgb(255, 255, 0)).fg(Color::Rgb(0, 0, 0)).add_modifier(Modifier::BOLD),
            "status_mode_normal" => Style::default().bg(Color::Rgb(0, 100, 255)).fg(Color::Rgb(255, 255, 255)).add_modifier(Modifier::BOLD),
            "status_mode_search" => Style::default().bg(Color::Rgb(255, 0, 150)).fg(Color::Rgb(255, 255, 255)).add_modifier(Modifier::BOLD),

            // --- LIST CONTENT ---
            "app_name" => Style::default().fg(Color::Rgb(0, 255, 127)),
            "country" => Style::default().fg(Color::Rgb(255, 215, 0)).add_modifier(Modifier::BOLD), // Gold
            "payload" => Style::default().fg(Color::Rgb(0, 180, 255)),
            "dim" => Style::default().fg(Color::Rgb(120, 120, 120)).add_modifier(Modifier::ITALIC),

            // --- FALLBACK ---
            _ => Style::default().fg(Color::Rgb(200, 200, 200)),
        }
    }
}


