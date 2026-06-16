//! All drawing. Each screen gets a header, a bordered body, and a dim footer of
//! key hints, so the wizard feels consistent as you move through it.

use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

use crate::app::{AgeMethod, App, Field, Flow, Step};
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
        Step::AgeMethod => age_method(frame, body, app),
        Step::Compression => compression(frame, body, app),
        Step::Browse => browse(frame, body, app),
        Step::Recipient => text_entry(
            frame,
            body,
            app,
            "Recipient",
            "Who is this file for?",
            "Paste their age public key (age1…), or a path to their key file.",
        ),
        Step::Passphrase => passphrase(frame, body, app),
        Step::Identity => text_entry(
            frame,
            body,
            app,
            "Key file",
            "Open with your age key",
            "Type the path to your age key file (e.g. ~/key.txt).",
        ),
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
        Step::AgeMethod => "↑↓ choose · Enter select · Esc back",
        Step::Recipient => "paste a key or path · Enter continue · Esc back",
        Step::Identity => "type a path · Enter continue · Esc back",
        Step::Compression => {
            if app.backend == Backend::Age {
                "↑↓ choose · Enter select · Esc back"
            } else {
                "type 0–9 · Enter continue · Esc back"
            }
        }
        Step::Browse => {
            "type to filter · paste a path · Tab hidden · ↑↓ move · Enter open · ← up · Esc back"
        }
        Step::Passphrase => match app.flow {
            Flow::Encrypt => {
                "type password · Tab switch field · Ctrl-R show · Enter continue · Esc back"
            }
            Flow::Decrypt if app.backend == Backend::Age => {
                "type password · Ctrl-R show · Ctrl-K key file · Enter continue · Esc back"
            }
            Flow::Decrypt => "type password · Ctrl-R show · Enter continue · Esc back",
        },
        Step::Review => {
            if app.editing_output {
                "type a path · Enter save · Esc cancel"
            } else {
                "Enter confirm · e change destination · Esc back"
            }
        }
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
    let options = ["Lock or compress a file", "Open a locked file", "Quit"];
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
    // (method name, rest of the title, tagline). The name is rendered bold on
    // every row so the format — age / 7z / zip — is what the eye lands on.
    let methods = [
        (
            "age",
            " — Encrypt · strongest",
            "ChaCha20-Poly1305. Opens with zipline. Hides file names.",
        ),
        (
            "7z",
            " — Encrypt · portable",
            "AES-256. Opens in 7-Zip / WinZip / Keka. Hides file names.",
        ),
        (
            "zip",
            " — No encryption · opens anywhere",
            "No password. Double-click on any OS. File names are visible.",
        ),
    ];
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  Choose a method",
            Style::new().fg(Color::Gray),
        )),
        Line::from(""),
    ];
    for (i, (name, rest, tag)) in methods.iter().enumerate() {
        let selected = i == app.menu;
        let marker = if selected { "  ▸ " } else { "    " };
        let line_style = if selected {
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(Color::Gray)
        };
        // Off-row, the name stands out from the gray rest by going white-bold;
        // on the selected row the whole line is already accent-bold.
        let name_style = if selected {
            line_style
        } else {
            Style::new().fg(Color::White).add_modifier(Modifier::BOLD)
        };
        lines.push(Line::from(vec![
            Span::styled(marker, line_style),
            Span::styled(format!("{name:<3}"), name_style),
            Span::styled(*rest, line_style),
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

fn age_method(frame: &mut Frame, area: Rect, app: &App) {
    let options = [
        "Lock with a password",
        "Lock for a person (their age public key)",
    ];
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  How should age lock it?",
            Style::new().fg(Color::Gray),
        )),
        Line::from(""),
    ];
    lines.extend(menu_lines(&options, app.menu));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  A password is shared by both people. A recipient key locks the file for",
        Style::new().fg(DIM),
    )));
    lines.push(Line::from(Span::styled(
        "  one person — only their key opens it, with no shared password.",
        Style::new().fg(DIM),
    )));
    frame.render_widget(
        Paragraph::new(lines)
            .block(body_block("age"))
            .wrap(Wrap { trim: true }),
        area,
    );
}

/// A single-line text entry screen (used for the recipient key and the identity
/// file path). `prompt` is the bold heading; `hint` the dim explainer below.
fn text_entry(frame: &mut Frame, area: Rect, app: &App, title: &str, prompt: &str, hint: &str) {
    let mut lines = vec![
        Line::from(""),
        heading(prompt.to_string()),
        Line::from(""),
        Line::from(vec![
            Span::styled("  ", Style::new().fg(DIM)),
            Span::styled(
                app.text_input.clone(),
                Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
            ),
            Span::styled("▏", Style::new().fg(ACCENT)),
        ]),
        Line::from(""),
        Line::from(Span::styled(format!("  {hint}"), Style::new().fg(DIM))),
    ];
    if let Some(note) = &app.note {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            format!("  {note}"),
            Style::new().fg(ERR),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(body_block(title))
            .wrap(Wrap { trim: true }),
        area,
    );
}

fn compression(frame: &mut Frame, area: Rect, app: &App) {
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  How hard should we try to shrink it?",
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
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Already-compressed files (photos, video) won't get much smaller.",
        Style::new().fg(DIM),
    )));
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
        Flow::Decrypt => "Choose a file to extract",
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
                &field_value(app, &app.password),
                app.field == Field::Password,
            ));
            lines.push(field_line(
                "Repeat ",
                &field_value(app, &app.confirm),
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
            lines.push(field_line(
                "Password",
                &field_value(app, &app.password),
                true,
            ));
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
            if app.editing_output {
                lines.push(edit_line("To   ", &app.output_input));
            } else {
                lines.push(kv("To   ", &output));
            }
            lines.push(kv("Using", app.backend.title()));
            if app.backend == Backend::Age && app.age_method == AgeMethod::Recipients {
                let n = app.recipients.len();
                let who = if n == 1 { "recipient" } else { "recipients" };
                lines.push(kv("For", &format!("{n} {who} (their age key)")));
            }
            lines.push(kv("Compression", &compression_label(app.level)));
            lines.push(Line::from(""));
            if app.will_overwrite {
                lines.push(Line::from(Span::styled(
                    format!("  This replaces the existing {}.", name_of(&app.output)),
                    Style::new().fg(WARN),
                )));
            }
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
            lines.push(heading("Ready to extract".into()));
            lines.push(Line::from(""));
            lines.push(kv("File", &source));
            if app.editing_output {
                lines.push(edit_line("Into", &app.output_input));
            } else {
                lines.push(kv("Into", &output));
            }
            if let Some(id) = &app.identity {
                lines.push(kv("Key", &id.to_string_lossy()));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                "  Press Enter to extract.",
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
        Line::from(""),
        Line::from(Span::styled(
            format!("   Elapsed: {}s", app.elapsed_secs()),
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

/// Like `kv`, but for the editable destination field: the value is accented and
/// followed by a cursor bar.
fn edit_line(key: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("  {key}   "), Style::new().fg(DIM)),
        Span::styled(
            value.to_string(),
            Style::new().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
        Span::styled("▏", Style::new().fg(ACCENT)),
    ])
}

fn mask(s: &str) -> String {
    "•".repeat(s.chars().count())
}

/// The password as shown on screen: clear text when revealed, else bullets.
fn field_value(app: &App, s: &str) -> String {
    if app.reveal {
        s.to_string()
    } else {
        mask(s)
    }
}

/// The file name of an optional path, for plain-language messages.
fn name_of(p: &Option<std::path::PathBuf>) -> String {
    p.as_ref()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
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

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn draw(step: Step, prep: impl FnOnce(&mut App)) {
        let mut app = App::new();
        app.step = step;
        prep(&mut app);
        let mut term = Terminal::new(TestBackend::new(80, 24)).unwrap();
        term.draw(|f| render(f, &mut app)).unwrap();
    }

    #[test]
    fn every_screen_renders_without_panicking() {
        let steps = [
            Step::Welcome,
            Step::ChooseBackend,
            Step::AgeMethod,
            Step::Compression,
            Step::Browse,
            Step::Recipient,
            Step::Passphrase,
            Step::Identity,
            Step::Review,
            Step::Working,
            Step::Finished,
        ];
        for step in steps {
            draw(step, |_| {});
        }
    }

    #[test]
    fn review_renders_recipient_and_overwrite_details() {
        draw(Step::Review, |app| {
            app.flow = Flow::Encrypt;
            app.backend = Backend::Age;
            app.age_method = AgeMethod::Recipients;
            app.recipients = vec!["age1example".into()];
            app.will_overwrite = true;
            app.output = Some(std::path::PathBuf::from("/tmp/thing.age"));
        });
        draw(Step::Finished, |app| {
            app.outcome = Some(Err("wrong password, or the file is damaged".into()));
        });
    }
}
