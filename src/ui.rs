//! All drawing. Each screen gets a header, a bordered body, and a dim footer of
//! key hints, so the wizard feels consistent as you move through it.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{App, Field, Flow, Step};
use crate::backend::Backend;
use crate::browser::Row;

const ACCENT: Color = Color::Cyan;
const OK: Color = Color::Green;
const WARN: Color = Color::Yellow;
const ERR: Color = Color::Red;
const DIM: Color = Color::DarkGray;

const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub fn render(frame: &mut Frame, app: &mut App) {
    let [header, body, footer] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Fill(1),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    render_header(frame, header);

    match app.step {
        Step::Welcome => welcome(frame, body, app),
        Step::ChooseBackend => choose_backend(frame, body, app),
        Step::Compression => compression(frame, body, app),
        Step::Browse => browse(frame, body, app),
        Step::Passphrase => passphrase(frame, body, app),
        Step::Review => review(frame, body, app),
        Step::Working => working(frame, body, app),
        Step::Finished => finished(frame, body, app),
    }

    render_footer(frame, footer, app);
}

fn render_header(frame: &mut Frame, area: Rect) {
    let line = Line::from(vec![
        Span::styled(
            "zipline",
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "  —  lock your files with one password",
            Style::new().fg(DIM),
        ),
    ]);
    frame.render_widget(Paragraph::new(line), pad(area));
}

fn render_footer(frame: &mut Frame, area: Rect, app: &App) {
    let hint = match app.step {
        Step::Welcome => "↑↓ choose · Enter select · q quit",
        Step::ChooseBackend => "↑↓ choose · Enter select · Esc back",
        Step::Compression => {
            if app.backend == Backend::Age {
                "↑↓ choose · Enter select · Esc back"
            } else {
                "type 0–9 · Enter continue · Esc back"
            }
        }
        Step::Browse => "type to filter · paste a path · ↑↓ move · Enter open · ← up · Esc back",
        Step::Passphrase => match app.flow {
            Flow::Encrypt => "type password · Tab switch field · Enter continue · Esc back",
            Flow::Decrypt => "type password · Enter continue · Esc back",
        },
        Step::Review => "Enter confirm · Esc back",
        Step::Working => "please wait…",
        Step::Finished => "Enter do another · q quit",
    };
    frame.render_widget(
        Paragraph::new(Span::styled(hint, Style::new().fg(DIM))),
        pad(area),
    );
}

fn body_block(title: &str) -> Block<'_> {
    Block::bordered()
        .border_type(BorderType::Rounded)
        .border_style(Style::new().fg(ACCENT))
        .title(Span::styled(
            format!(" {title} "),
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
        ))
}

fn welcome(frame: &mut Frame, area: Rect, app: &App) {
    let options = [
        "Protect or compress a file or folder",
        "Open an archive",
        "Quit",
    ];
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  What would you like to do?",
            Style::new().fg(Color::Gray),
        )),
        Line::from(""),
    ];
    lines.extend(menu_lines(&options, app.menu));
    frame.render_widget(Paragraph::new(lines).block(body_block("Welcome")), area);
}

fn choose_backend(frame: &mut Frame, area: Rect, app: &App) {
    let options = [
        "Lock with a password — age (strongest)",
        "Lock with a password — 7z (portable)",
        "Compress only — zip (opens anywhere)",
    ];
    let taglines = [
        "ChaCha20-Poly1305. Opens with zipline. Hides file names.",
        "AES-256. Opens in 7-Zip / WinZip / Keka. Hides file names.",
        "No password. Double-click on any OS. File names are visible.",
    ];
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Choose a method",
            Style::new().fg(Color::Gray),
        )),
        Line::from(""),
    ];
    for (i, (opt, tag)) in options.iter().zip(taglines).enumerate() {
        let selected = i == app.menu;
        let marker = if selected { "  ▸ " } else { "    " };
        let style = if selected {
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(Color::Gray)
        };
        lines.push(Line::from(vec![
            Span::styled(marker, style),
            Span::styled(*opt, style),
        ]));
        lines.push(Line::from(Span::styled(
            format!("       {tag}"),
            Style::new().fg(DIM),
        )));
        lines.push(Line::from(""));
    }
    if let Some(note) = &app.note {
        lines.push(Line::from(Span::styled(
            format!("  {note}"),
            Style::new().fg(WARN),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(body_block("Method"))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn compression(frame: &mut Frame, area: Rect, app: &App) {
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  How small should it be?",
            Style::new().fg(Color::Gray),
        )),
        Line::from(""),
    ];
    if app.backend == Backend::Age {
        // age: three presets chosen with the arrow keys.
        let options = [
            "None — fastest, no shrinking",
            "Normal",
            "Maximum — smallest, slowest",
        ];
        lines.extend(menu_lines(&options, app.menu));
    } else {
        // 7z / zip: type a level 0–9.
        let shown = if app.level_input.is_empty() {
            "_".to_string()
        } else {
            app.level_input.clone()
        };
        lines.push(Line::from(vec![
            Span::styled("  Level: ", Style::new().fg(Color::Gray)),
            Span::styled(shown, Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)),
        ]));
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "  0 = none (fastest)   5 = normal   9 = smallest (slowest)",
            Style::new().fg(DIM),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(body_block("Compression"))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn browse(frame: &mut Frame, area: Rect, app: &mut App) {
    let title = app.browser.cwd().to_string_lossy().into_owned();
    let items: Vec<ListItem> = app
        .browser
        .rows()
        .iter()
        .map(|row| {
            let label = app.browser.label(row);
            let style = match row {
                Row::UseCurrent => Style::new().fg(OK).add_modifier(Modifier::BOLD),
                Row::Up => Style::new().fg(DIM),
                Row::Dir(_) => Style::new().fg(ACCENT),
                Row::File(_) => Style::new().fg(Color::Gray),
            };
            ListItem::new(Line::from(Span::styled(format!("  {label}"), style)))
        })
        .collect();

    let prompt = match app.flow {
        Flow::Encrypt => "Choose what to lock",
        Flow::Decrypt => "Choose a file to open",
    };

    let block =
        body_block(&title).title_bottom(Span::styled(format!(" {prompt} "), Style::new().fg(DIM)));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    // A query line above the list: a typed path to jump to, or a live filter.
    let [query_area, list_area] =
        Layout::vertical([Constraint::Length(1), Constraint::Fill(1)]).areas(inner);
    let query = app.browser.query();
    let query_line = if query.is_empty() {
        Line::from(Span::styled(
            "  Type to filter, or paste a path",
            Style::new().fg(DIM),
        ))
    } else {
        let (tag, color) = if app.browser.is_path_query() {
            ("Go to", OK)
        } else {
            ("Filter", ACCENT)
        };
        Line::from(vec![
            Span::styled(format!("  {tag}: "), Style::new().fg(DIM)),
            Span::styled(query.to_string(), Style::new().fg(color)),
            Span::styled("▏", Style::new().fg(color)),
        ])
    };
    frame.render_widget(Paragraph::new(query_line), query_area);

    let list = List::new(items)
        .highlight_style(
            Style::new()
                .bg(ACCENT)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("");
    frame.render_stateful_widget(list, list_area, app.browser.state());

    if let Some(note) = &app.note {
        note_overlay(frame, area, note);
    }
}

fn passphrase(frame: &mut Frame, area: Rect, app: &App) {
    let name = app
        .source
        .as_ref()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut lines = vec![Line::from("")];
    match app.flow {
        Flow::Encrypt => {
            lines.push(heading(format!("Set a password for \"{name}\"")));
            lines.push(Line::from(""));
            lines.push(field_line(
                "Password",
                &mask(&app.password),
                app.field == Field::Password,
            ));
            lines.push(field_line(
                "Repeat ",
                &mask(&app.confirm),
                app.field == Field::Confirm,
            ));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  Keep this password safe. Without it, the file can never be opened.",
                Style::new().fg(WARN),
            )));
        }
        Flow::Decrypt => {
            lines.push(heading(format!("Enter the password for \"{name}\"")));
            lines.push(Line::from(""));
            lines.push(field_line("Password", &mask(&app.password), true));
        }
    }
    if let Some(note) = &app.note {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {note}"),
            Style::new().fg(ERR),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(body_block("Password"))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn review(frame: &mut Frame, area: Rect, app: &App) {
    let source = path_str(&app.source);
    let output = path_str(&app.output);
    let mut lines = vec![Line::from("")];
    match app.flow {
        Flow::Encrypt => {
            let is_zip = app.backend == Backend::Zip;
            lines.push(heading(if is_zip {
                "Ready to pack".into()
            } else {
                "Ready to lock".into()
            }));
            lines.push(Line::from(""));
            lines.push(kv("From ", &source));
            lines.push(kv("To   ", &output));
            lines.push(kv("Using", app.backend.title()));
            lines.push(kv("Squeeze", &compression_label(app.level)));
            lines.push(Line::from(""));
            if is_zip {
                lines.push(Line::from(Span::styled(
                    "  No password — anyone can open this file.",
                    Style::new().fg(WARN),
                )));
            }
            lines.push(Line::from(Span::styled(
                if is_zip {
                    "  Press Enter to create the zip."
                } else {
                    "  Press Enter to encrypt."
                },
                Style::new().fg(OK).add_modifier(Modifier::BOLD),
            )));
        }
        Flow::Decrypt => {
            lines.push(heading("Ready to open".into()));
            lines.push(Line::from(""));
            lines.push(kv("File", &source));
            lines.push(kv("Into", &output));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  Press Enter to open.",
                Style::new().fg(OK).add_modifier(Modifier::BOLD),
            )));
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(body_block("Review"))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn working(frame: &mut Frame, area: Rect, app: &App) {
    let spin = SPINNER[((app.tick / 2) % SPINNER.len() as u64) as usize];
    let verb = match app.flow {
        Flow::Encrypt => "Encrypting your files",
        Flow::Decrypt => "Opening your file",
    };
    let lines = vec![
        Line::from(""),
        Line::from(""),
        Line::from(Span::styled(
            format!("   {spin}  {verb}…"),
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "   This can take a moment for large folders.",
            Style::new().fg(DIM),
        )),
    ];
    frame.render_widget(Paragraph::new(lines).block(body_block("Working")), area);
}

fn finished(frame: &mut Frame, area: Rect, app: &App) {
    let mut lines = vec![Line::from("")];
    match &app.outcome {
        Some(Ok(path)) => {
            let (head, label) = match app.flow {
                Flow::Encrypt => ("Done — your file is locked.", "Saved to"),
                Flow::Decrypt => ("Done — your file is open.", "Unpacked into"),
            };
            lines.push(Line::from(Span::styled(
                format!("  ✓ {head}"),
                Style::new().fg(OK).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));
            lines.push(kv(label, &path.to_string_lossy()));
        }
        Some(Err(msg)) => {
            lines.push(Line::from(Span::styled(
                "  ✗ Something went wrong.",
                Style::new().fg(ERR).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                format!("  {msg}"),
                Style::new().fg(Color::Gray),
            )));
        }
        None => {}
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Enter: do another    q: quit",
        Style::new().fg(DIM),
    )));
    frame.render_widget(
        Paragraph::new(lines)
            .block(body_block("Finished"))
            .wrap(Wrap { trim: true }),
        area,
    );
}

// -- small helpers --------------------------------------------------------

fn menu_lines<'a>(options: &[&'a str], selected: usize) -> Vec<Line<'a>> {
    options
        .iter()
        .enumerate()
        .map(|(i, opt)| {
            let chosen = i == selected;
            let (marker, style) = if chosen {
                ("  ▸ ", Style::new().fg(ACCENT).add_modifier(Modifier::BOLD))
            } else {
                ("    ", Style::new().fg(Color::Gray))
            };
            Line::from(vec![Span::styled(marker, style), Span::styled(*opt, style)])
        })
        .collect()
}

fn heading(text: String) -> Line<'static> {
    Line::from(Span::styled(
        format!("  {text}"),
        Style::new().fg(Color::White).add_modifier(Modifier::BOLD),
    ))
}

fn field_line<'a>(label: &'a str, value: &str, focused: bool) -> Line<'a> {
    let value_style = if focused {
        Style::new()
            .fg(ACCENT)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
    } else {
        Style::new().fg(Color::Gray)
    };
    let caret = if focused { "▸ " } else { "  " };
    Line::from(vec![
        Span::styled(format!("  {caret}"), Style::new().fg(ACCENT)),
        Span::styled(format!("{label}  "), Style::new().fg(Color::Gray)),
        Span::styled(format!("{value:<24}"), value_style),
    ])
}

fn kv(key: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {key}   "), Style::new().fg(DIM)),
        Span::styled(value.to_string(), Style::new().fg(Color::White)),
    ])
}

fn mask(s: &str) -> String {
    "•".repeat(s.chars().count())
}

/// A plain-language name for a compression level, with the raw number.
fn compression_label(level: u8) -> String {
    let word = match level {
        0 => "None",
        1..=4 => "Faster",
        5 => "Normal",
        6..=8 => "Smaller",
        _ => "Maximum",
    };
    format!("{word} ({level})")
}

fn path_str(p: &Option<std::path::PathBuf>) -> String {
    p.as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Shrink a rect by one cell of horizontal padding.
fn pad(area: Rect) -> Rect {
    Rect {
        x: area.x + 1,
        width: area.width.saturating_sub(2),
        ..area
    }
}

/// Draw a one-line warning near the bottom of `area` (used over the browser).
fn note_overlay(frame: &mut Frame, area: Rect, note: &str) {
    if area.height < 3 {
        return;
    }
    let line = Rect {
        x: area.x + 2,
        y: area.y + area.height - 2,
        width: area.width.saturating_sub(4),
        height: 1,
    };
    frame.render_widget(
        Paragraph::new(Span::styled(
            note,
            Style::new().fg(WARN).add_modifier(Modifier::BOLD),
        ))
        .wrap(Wrap { trim: true }),
        line,
    );
}
