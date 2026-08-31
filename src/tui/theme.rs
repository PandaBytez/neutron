//! Terminal theme presets and color palette definitions.

use ratatui::style::{Color, Modifier, Style};

use crate::config::ThemeConfig;

#[derive(Debug, Clone)]
pub struct Theme {
    pub name: &'static str,
    pub backdrop_grid: Style,
    pub border: Style,
    pub active_border: Style,
    pub title: Style,
    pub header: Style,
    pub selected_item: Style,
    pub active_profile: Style,
    pub inactive_profile: Style,
    pub status_connected: Style,
    pub status_disconnected: Style,
    pub status_pill_connected: Style,
    pub status_pill_disconnected: Style,
    pub label_dim: Style,
    pub text_primary: Style,
    pub text_secondary: Style,
    pub accent: Style,
    pub warning: Style,
    pub keybinding: Style,
    pub key_badge: Style,
    pub key_badge_accent: Style,
    pub toast_bg: Color,
    pub toast_error_bg: Color,
}

impl Theme {
    pub fn from_config(config: &ThemeConfig) -> Self {
        let mut theme = match config.preset.to_lowercase().as_str() {
            "catppuccin" | "catppuccin-mocha" => Self::catppuccin_mocha(),
            "nord" => Self::nord(),
            "gruvbox" => Self::gruvbox(),
            "monochrome" | "mono" => Self::monochrome(),
            _ => Self::osaka_jade(),
        };

        if let Some(ref hex) = config.active_border
            && let Some(c) = parse_color(hex)
        {
            theme.active_border = Style::default().fg(c).add_modifier(Modifier::BOLD);
        }
        if let Some(ref hex) = config.status_connected
            && let Some(c) = parse_color(hex)
        {
            theme.status_connected = Style::default().fg(c).add_modifier(Modifier::BOLD);
        }
        if let Some(ref hex) = config.status_disconnected
            && let Some(c) = parse_color(hex)
        {
            theme.status_disconnected = Style::default().fg(c).add_modifier(Modifier::BOLD);
        }

        theme
    }

    pub fn osaka_jade() -> Self {
        Self {
            name: "osaka-jade",
            backdrop_grid: Style::default().fg(Color::Rgb(25, 42, 36)),
            border: Style::default().fg(Color::Rgb(83, 104, 91)),
            active_border: Style::default()
                .fg(Color::Rgb(45, 213, 183))
                .add_modifier(Modifier::BOLD),
            title: Style::default()
                .fg(Color::Rgb(246, 245, 221))
                .add_modifier(Modifier::BOLD),
            header: Style::default()
                .fg(Color::Rgb(45, 213, 183))
                .add_modifier(Modifier::BOLD),
            selected_item: Style::default()
                .bg(Color::Rgb(35, 55, 43))
                .fg(Color::Rgb(246, 245, 221))
                .add_modifier(Modifier::BOLD),
            active_profile: Style::default()
                .fg(Color::Rgb(99, 176, 122))
                .add_modifier(Modifier::BOLD),
            inactive_profile: Style::default().fg(Color::Rgb(193, 196, 151)),
            status_connected: Style::default()
                .fg(Color::Rgb(99, 176, 122))
                .add_modifier(Modifier::BOLD),
            status_disconnected: Style::default()
                .fg(Color::Rgb(255, 83, 69))
                .add_modifier(Modifier::BOLD),
            status_pill_connected: Style::default()
                .bg(Color::Rgb(35, 55, 43))
                .fg(Color::Rgb(158, 235, 179))
                .add_modifier(Modifier::BOLD),
            status_pill_disconnected: Style::default()
                .bg(Color::Rgb(62, 36, 34))
                .fg(Color::Rgb(255, 83, 69))
                .add_modifier(Modifier::BOLD),
            label_dim: Style::default().fg(Color::Rgb(83, 104, 91)),
            text_primary: Style::default().fg(Color::Rgb(193, 196, 151)),
            text_secondary: Style::default().fg(Color::Rgb(172, 212, 207)),
            accent: Style::default().fg(Color::Rgb(45, 213, 183)),
            warning: Style::default().fg(Color::Rgb(229, 199, 54)),
            keybinding: Style::default()
                .fg(Color::Rgb(229, 199, 54))
                .add_modifier(Modifier::BOLD),
            key_badge: Style::default()
                .bg(Color::Rgb(35, 55, 43))
                .fg(Color::Rgb(229, 199, 54))
                .add_modifier(Modifier::BOLD),
            key_badge_accent: Style::default()
                .bg(Color::Rgb(45, 213, 183))
                .fg(Color::Rgb(17, 28, 24))
                .add_modifier(Modifier::BOLD),
            toast_bg: Color::Rgb(28, 48, 38),
            toast_error_bg: Color::Rgb(58, 32, 30),
        }
    }

    pub fn catppuccin_mocha() -> Self {
        Self {
            name: "catppuccin-mocha",
            backdrop_grid: Style::default().fg(Color::Rgb(49, 50, 68)),
            border: Style::default().fg(Color::Rgb(88, 91, 112)),
            active_border: Style::default()
                .fg(Color::Rgb(203, 166, 247))
                .add_modifier(Modifier::BOLD),
            title: Style::default()
                .fg(Color::Rgb(205, 214, 244))
                .add_modifier(Modifier::BOLD),
            header: Style::default()
                .fg(Color::Rgb(203, 166, 247))
                .add_modifier(Modifier::BOLD),
            selected_item: Style::default()
                .bg(Color::Rgb(69, 71, 90))
                .fg(Color::Rgb(205, 214, 244))
                .add_modifier(Modifier::BOLD),
            active_profile: Style::default()
                .fg(Color::Rgb(166, 227, 161))
                .add_modifier(Modifier::BOLD),
            inactive_profile: Style::default().fg(Color::Rgb(166, 173, 200)),
            status_connected: Style::default()
                .fg(Color::Rgb(166, 227, 161))
                .add_modifier(Modifier::BOLD),
            status_disconnected: Style::default()
                .fg(Color::Rgb(243, 139, 168))
                .add_modifier(Modifier::BOLD),
            status_pill_connected: Style::default()
                .bg(Color::Rgb(40, 80, 60))
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
            status_pill_disconnected: Style::default()
                .bg(Color::Rgb(90, 40, 50))
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
            label_dim: Style::default().fg(Color::Rgb(108, 112, 134)),
            text_primary: Style::default().fg(Color::Rgb(205, 214, 244)),
            text_secondary: Style::default().fg(Color::Rgb(186, 194, 222)),
            accent: Style::default().fg(Color::Rgb(137, 180, 250)),
            warning: Style::default().fg(Color::Rgb(250, 179, 135)),
            keybinding: Style::default()
                .fg(Color::Rgb(249, 226, 175))
                .add_modifier(Modifier::BOLD),
            key_badge: Style::default()
                .bg(Color::Rgb(69, 71, 90))
                .fg(Color::Rgb(249, 226, 175))
                .add_modifier(Modifier::BOLD),
            key_badge_accent: Style::default()
                .bg(Color::Rgb(203, 166, 247))
                .fg(Color::Rgb(17, 17, 27))
                .add_modifier(Modifier::BOLD),
            toast_bg: Color::Rgb(49, 50, 68),
            toast_error_bg: Color::Rgb(69, 40, 50),
        }
    }

    pub fn nord() -> Self {
        Self {
            name: "nord",
            backdrop_grid: Style::default().fg(Color::Rgb(59, 66, 82)),
            border: Style::default().fg(Color::Rgb(76, 86, 106)),
            active_border: Style::default()
                .fg(Color::Rgb(136, 192, 208))
                .add_modifier(Modifier::BOLD),
            title: Style::default()
                .fg(Color::Rgb(236, 239, 244))
                .add_modifier(Modifier::BOLD),
            header: Style::default()
                .fg(Color::Rgb(136, 192, 208))
                .add_modifier(Modifier::BOLD),
            selected_item: Style::default()
                .bg(Color::Rgb(67, 76, 94))
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
            active_profile: Style::default()
                .fg(Color::Rgb(163, 190, 140))
                .add_modifier(Modifier::BOLD),
            inactive_profile: Style::default().fg(Color::Rgb(216, 222, 233)),
            status_connected: Style::default()
                .fg(Color::Rgb(163, 190, 140))
                .add_modifier(Modifier::BOLD),
            status_disconnected: Style::default()
                .fg(Color::Rgb(191, 97, 106))
                .add_modifier(Modifier::BOLD),
            status_pill_connected: Style::default()
                .bg(Color::Rgb(46, 76, 60))
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
            status_pill_disconnected: Style::default()
                .bg(Color::Rgb(90, 40, 50))
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
            label_dim: Style::default().fg(Color::Rgb(94, 129, 172)),
            text_primary: Style::default().fg(Color::Rgb(236, 239, 244)),
            text_secondary: Style::default().fg(Color::Rgb(216, 222, 233)),
            accent: Style::default().fg(Color::Rgb(129, 161, 193)),
            warning: Style::default().fg(Color::Rgb(208, 135, 112)),
            keybinding: Style::default()
                .fg(Color::Rgb(235, 203, 139))
                .add_modifier(Modifier::BOLD),
            key_badge: Style::default()
                .bg(Color::Rgb(67, 76, 94))
                .fg(Color::Rgb(235, 203, 139))
                .add_modifier(Modifier::BOLD),
            key_badge_accent: Style::default()
                .bg(Color::Rgb(136, 192, 208))
                .fg(Color::Rgb(46, 52, 64))
                .add_modifier(Modifier::BOLD),
            toast_bg: Color::Rgb(59, 66, 82),
            toast_error_bg: Color::Rgb(76, 48, 56),
        }
    }

    pub fn gruvbox() -> Self {
        Self {
            name: "gruvbox",
            backdrop_grid: Style::default().fg(Color::Rgb(55, 52, 50)),
            border: Style::default().fg(Color::Rgb(124, 111, 100)),
            active_border: Style::default()
                .fg(Color::Rgb(254, 128, 25))
                .add_modifier(Modifier::BOLD),
            title: Style::default()
                .fg(Color::Rgb(235, 219, 178))
                .add_modifier(Modifier::BOLD),
            header: Style::default()
                .fg(Color::Rgb(254, 128, 25))
                .add_modifier(Modifier::BOLD),
            selected_item: Style::default()
                .bg(Color::Rgb(60, 56, 54))
                .fg(Color::Rgb(251, 241, 199))
                .add_modifier(Modifier::BOLD),
            active_profile: Style::default()
                .fg(Color::Rgb(184, 187, 38))
                .add_modifier(Modifier::BOLD),
            inactive_profile: Style::default().fg(Color::Rgb(213, 196, 161)),
            status_connected: Style::default()
                .fg(Color::Rgb(184, 187, 38))
                .add_modifier(Modifier::BOLD),
            status_disconnected: Style::default()
                .fg(Color::Rgb(251, 73, 52))
                .add_modifier(Modifier::BOLD),
            status_pill_connected: Style::default()
                .bg(Color::Rgb(60, 80, 30))
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
            status_pill_disconnected: Style::default()
                .bg(Color::Rgb(90, 30, 30))
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
            label_dim: Style::default().fg(Color::Rgb(168, 153, 132)),
            text_primary: Style::default().fg(Color::Rgb(235, 219, 178)),
            text_secondary: Style::default().fg(Color::Rgb(213, 196, 161)),
            accent: Style::default().fg(Color::Rgb(131, 165, 152)),
            warning: Style::default().fg(Color::Rgb(254, 128, 25)),
            keybinding: Style::default()
                .fg(Color::Rgb(250, 189, 47))
                .add_modifier(Modifier::BOLD),
            key_badge: Style::default()
                .bg(Color::Rgb(60, 56, 54))
                .fg(Color::Rgb(250, 189, 47))
                .add_modifier(Modifier::BOLD),
            key_badge_accent: Style::default()
                .bg(Color::Rgb(254, 128, 25))
                .fg(Color::Rgb(29, 32, 33))
                .add_modifier(Modifier::BOLD),
            toast_bg: Color::Rgb(60, 56, 54),
            toast_error_bg: Color::Rgb(76, 42, 40),
        }
    }

    pub fn monochrome() -> Self {
        let soft_white = Color::Rgb(225, 225, 225);
        let light_gray = Color::Rgb(190, 190, 190);
        let mid_gray = Color::Rgb(150, 150, 150);
        let dark_gray = Color::Rgb(100, 100, 100);
        let surface_gray = Color::Rgb(50, 50, 50);

        Self {
            name: "monochrome",
            backdrop_grid: Style::default().fg(Color::Rgb(35, 35, 35)),
            border: Style::default().fg(dark_gray),
            active_border: Style::default().fg(soft_white).add_modifier(Modifier::BOLD),
            title: Style::default().fg(soft_white).add_modifier(Modifier::BOLD),
            header: Style::default().fg(soft_white).add_modifier(Modifier::BOLD),
            selected_item: Style::default()
                .bg(surface_gray)
                .fg(soft_white)
                .add_modifier(Modifier::BOLD),
            active_profile: Style::default().fg(soft_white).add_modifier(Modifier::BOLD),
            inactive_profile: Style::default().fg(mid_gray),
            status_connected: Style::default().fg(soft_white).add_modifier(Modifier::BOLD),
            status_disconnected: Style::default().fg(dark_gray),
            status_pill_connected: Style::default()
                .bg(surface_gray)
                .fg(soft_white)
                .add_modifier(Modifier::BOLD),
            status_pill_disconnected: Style::default()
                .bg(Color::Rgb(35, 35, 35))
                .fg(dark_gray)
                .add_modifier(Modifier::BOLD),
            label_dim: Style::default().fg(dark_gray),
            text_primary: Style::default().fg(soft_white),
            text_secondary: Style::default().fg(mid_gray),
            accent: Style::default().fg(light_gray),
            warning: Style::default()
                .fg(soft_white)
                .add_modifier(Modifier::UNDERLINED),
            keybinding: Style::default().fg(soft_white).add_modifier(Modifier::BOLD),
            key_badge: Style::default()
                .bg(surface_gray)
                .fg(soft_white)
                .add_modifier(Modifier::BOLD),
            key_badge_accent: Style::default()
                .bg(light_gray)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
            toast_bg: Color::Rgb(38, 38, 38),
            toast_error_bg: Color::Rgb(50, 30, 30),
        }
    }
}

fn parse_color(hex: &str) -> Option<Color> {
    let s = hex.trim().trim_start_matches('#');
    if s.len() == 6 && s.is_ascii() {
        let r = u8::from_str_radix(&s[0..2], 16).ok()?;
        let g = u8::from_str_radix(&s[2..4], 16).ok()?;
        let b = u8::from_str_radix(&s[4..6], 16).ok()?;
        Some(Color::Rgb(r, g, b))
    } else {
        match s.to_lowercase().as_str() {
            "red" => Some(Color::Red),
            "green" => Some(Color::Green),
            "yellow" => Some(Color::Yellow),
            "blue" => Some(Color::Blue),
            "magenta" | "purple" => Some(Color::Magenta),
            "cyan" => Some(Color::Cyan),
            "white" => Some(Color::White),
            "black" => Some(Color::Black),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_and_named_colors() {
        assert_eq!(parse_color("#ff0000"), Some(Color::Rgb(255, 0, 0)));
        assert_eq!(parse_color("00ff00"), Some(Color::Rgb(0, 255, 0)));
        assert_eq!(parse_color("blue"), Some(Color::Blue));
        assert_eq!(parse_color("invalid"), None);
        assert_eq!(parse_color("日本"), None);
        assert_eq!(parse_color("#日本"), None);
    }

    #[test]
    fn theme_presets_instantiate() {
        let _ = Theme::osaka_jade();
        let _ = Theme::catppuccin_mocha();
        let _ = Theme::nord();
        let _ = Theme::gruvbox();
        let mono = Theme::monochrome();
        assert_ne!(mono.selected_item.bg, Some(Color::White));
        assert_eq!(mono.title.fg, Some(Color::Rgb(225, 225, 225)));
    }
}
