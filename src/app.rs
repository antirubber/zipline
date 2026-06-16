//! The wizard: a small state machine over a handful of screens, plus a worker
//! thread so encryption never freezes the interface.

use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;
use zeroize::{Zeroize, Zeroizing};

use crate::backend::{self, Backend};
use crate::browser::{Action, Browser};

const ARCHIVE_EXTS: &[&str] = &["age", "7z", "zip"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Encrypt,
    Decrypt,
}

pub enum Step {
    Welcome,
    ChooseBackend,
    /// age only: lock with a password, or for a recipient (their public key).
    AgeMethod,
    /// Pick the compression level for the chosen method.
    Compression,
    Browse,
    /// age recipient mode: type/paste the recipient's public key or a key file.
    Recipient,
    Passphrase,
    /// age decrypt: type/paste the path to your identity (key) file.
    Identity,
    Review,
    Working,
    Finished,
}

/// How an age archive will be locked.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AgeMethod {
    Password,
    Recipients,
}

/// Which passphrase field is focused while encrypting.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Password,
    Confirm,
}

pub struct App {
    pub step: Step,
    pub flow: Flow,
    pub backend: Backend,
    /// Compression level 0–9 the job will use, fixed when leaving the
    /// compression step.
    pub level: u8,
    /// The digit being typed on the compression step for 7z/zip (age uses a
    /// preset menu via `menu` instead).
    pub level_input: String,
    pub menu: usize,
    pub browser: Browser,
    pub password: String,
    pub confirm: String,
    pub field: Field,
    pub source: Option<PathBuf>,
    pub output: Option<PathBuf>,
    /// age lock method (password vs recipients), chosen on the AgeMethod step.
    pub age_method: AgeMethod,
    /// Recipients (age public keys) collected for a recipient-mode encrypt.
    pub recipients: Vec<String>,
    /// An age identity (key) file chosen to open a recipient-encrypted archive.
    pub identity: Option<PathBuf>,
    /// Shared text buffer for the Recipient and Identity entry screens.
    pub text_input: String,
    /// A transient, plain-language note shown in red (e.g. passwords differ).
    pub note: Option<String>,
    /// True when confirming on Review would overwrite an existing output file.
    pub will_overwrite: bool,
    /// True while the user is editing the destination path on the Review screen.
    pub editing_output: bool,
    /// The destination path being typed in the Review editor.
    pub output_input: String,
    /// Show the typed password in clear text (toggled on the passphrase screen).
    pub reveal: bool,
    pub tick: u64,
    /// The `tick` when the current job started, for the elapsed-time display.
    job_start: u64,
    pub outcome: Option<std::result::Result<PathBuf, String>>,
    job: Option<Receiver<std::result::Result<PathBuf, String>>>,
    quit: bool,
}

impl App {
    pub fn new() -> Self {
        App {
            step: Step::Welcome,
            flow: Flow::Encrypt,
            backend: Backend::Age,
            level: 5,
            level_input: String::from("5"),
            menu: 0,
            browser: Browser::new(home_dir(), None),
            password: String::new(),
            confirm: String::new(),
            field: Field::Password,
            source: None,
            output: None,
            age_method: AgeMethod::Password,
            recipients: Vec::new(),
            identity: None,
            text_input: String::new(),
            note: None,
            will_overwrite: false,
            editing_output: false,
            output_input: String::new(),
            reveal: false,
            tick: 0,
            job_start: 0,
            outcome: None,
            job: None,
            quit: false,
        }
    }

    /// Seconds elapsed since the current job started (for the Working screen).
    pub fn elapsed_secs(&self) -> u64 {
        self.tick.saturating_sub(self.job_start) / 10
    }

    /// Move to the Review screen, flagging whether confirming would overwrite an
    /// existing output. Only the encrypt flow can overwrite — decrypt relocates
    /// under a non-colliding name and never clobbers.
    fn enter_review(&mut self) {
        self.reveal = false;
        self.editing_output = false;
        self.recompute_overwrite();
        self.step = Step::Review;
    }

    /// Flag whether the chosen output already exists (encrypt only — decrypt
    /// relocates under a non-colliding name and never clobbers).
    fn recompute_overwrite(&mut self) {
        self.will_overwrite =
            self.flow == Flow::Encrypt && self.output.as_ref().is_some_and(|p| p.exists());
    }

    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        while !self.quit {
            terminal.draw(|frame| crate::ui::render(frame, self))?;
            if event::poll(Duration::from_millis(100))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        self.on_key(key);
                    }
                }
            }
            self.poll_job();
            self.tick = self.tick.wrapping_add(1);
        }
        Ok(())
    }

    fn on_key(&mut self, key: KeyEvent) {
        // Ctrl-C always quits.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            return;
        }
        self.note = None;
        match self.step {
            Step::Welcome => self.on_welcome(key.code),
            Step::ChooseBackend => self.on_choose_backend(key.code),
            Step::AgeMethod => self.on_age_method(key.code),
            Step::Compression => self.on_compression(key.code),
            Step::Browse => self.on_browse(key),
            Step::Recipient => self.on_recipient(key.code),
            Step::Passphrase => self.on_passphrase(key),
            Step::Identity => self.on_identity(key.code),
            Step::Review => self.on_review(key.code),
            Step::Working => {}
            Step::Finished => self.on_finished(key.code),
        }
    }

    // -- screens ----------------------------------------------------------

    fn on_welcome(&mut self, code: KeyCode) {
        match code {
            KeyCode::Up => self.menu = self.menu.saturating_sub(1),
            KeyCode::Down => self.menu = (self.menu + 1).min(2),
            // Esc is "go back" everywhere else, so on Welcome it does nothing
            // rather than surprising the user by quitting; 'q' is the exit.
            KeyCode::Char('q') => self.quit = true,
            KeyCode::Enter => match self.menu {
                0 => {
                    self.flow = Flow::Encrypt;
                    self.menu = 0;
                    self.reset_lock_state();
                    self.step = Step::ChooseBackend;
                }
                1 => {
                    self.flow = Flow::Decrypt;
                    self.reset_lock_state();
                    self.browser = Browser::new(home_dir(), Some(ARCHIVE_EXTS));
                    self.step = Step::Browse;
                }
                _ => self.quit = true,
            },
            _ => {}
        }
    }

    fn on_choose_backend(&mut self, code: KeyCode) {
        match code {
            KeyCode::Up => self.menu = self.menu.saturating_sub(1),
            KeyCode::Down => self.menu = (self.menu + 1).min(2),
            KeyCode::Esc => self.back_to_welcome(),
            KeyCode::Enter => {
                let backend = match self.menu {
                    0 => Backend::Age,
                    1 => Backend::SevenZip,
                    _ => Backend::Zip,
                };
                if backend.locate().is_none() {
                    self.note = Some(format!(
                        "{} is not installed yet. {}",
                        backend.title(),
                        backend.install_hint()
                    ));
                    return;
                }
                self.backend = backend;
                // age can also lock for a recipient; other backends go straight
                // to the compression step.
                if backend == Backend::Age {
                    self.menu = 0;
                    self.step = Step::AgeMethod;
                } else {
                    self.enter_compression();
                }
            }
            _ => {}
        }
    }

    fn on_age_method(&mut self, code: KeyCode) {
        match code {
            KeyCode::Up => self.menu = self.menu.saturating_sub(1),
            KeyCode::Down => self.menu = (self.menu + 1).min(1),
            KeyCode::Esc => self.step = Step::ChooseBackend,
            KeyCode::Enter => {
                self.age_method = if self.menu == 0 {
                    AgeMethod::Password
                } else {
                    AgeMethod::Recipients
                };
                self.enter_compression();
            }
            _ => {}
        }
    }

    /// Set up the compression step: age picks from presets via `menu`, 7z/zip
    /// type a level into `level_input`.
    fn enter_compression(&mut self) {
        self.menu = 0; // age: "None" preset highlighted
        self.level_input = String::from("5"); // 7z/zip: "Normal"
        self.step = Step::Compression;
    }

    fn on_compression(&mut self, code: KeyCode) {
        if self.backend == Backend::Age {
            match code {
                KeyCode::Up => self.menu = self.menu.saturating_sub(1),
                KeyCode::Down => self.menu = (self.menu + 1).min(2),
                KeyCode::Esc => self.step = Step::AgeMethod,
                KeyCode::Enter => self.confirm_compression(),
                _ => {}
            }
        } else {
            // 7z / zip: type a single 0–9 digit (last one wins).
            match code {
                KeyCode::Char(c) if c.is_ascii_digit() => self.level_input = c.to_string(),
                KeyCode::Backspace => self.level_input.clear(),
                KeyCode::Esc => self.step = Step::ChooseBackend,
                KeyCode::Enter => self.confirm_compression(),
                _ => {}
            }
        }
    }

    /// Fix the compression level from the step's state and move on to browsing.
    fn confirm_compression(&mut self) {
        self.level = match self.backend {
            // age presets: None / Normal / Maximum -> gzip 0 / 6 / 9.
            Backend::Age => [0u8, 6, 9][self.menu.min(2)],
            _ => self.level_input.trim().parse::<u8>().unwrap_or(5).min(9),
        };
        self.browser = Browser::new(home_dir(), None);
        self.step = Step::Browse;
    }

    fn on_browse(&mut self, key: KeyEvent) {
        // Tab toggles hidden (dot) files; the footer advertises it.
        if key.code == KeyCode::Tab {
            self.browser.toggle_hidden();
            return;
        }
        match key.code {
            KeyCode::Up => self.browser.move_up(),
            KeyCode::Down => self.browser.move_down(),
            KeyCode::Left => self.browser.go_up(),
            KeyCode::Char(c) => self.browser.push_query(c),
            KeyCode::Backspace => {
                if self.browser.query().is_empty() {
                    self.browser.go_up();
                } else {
                    self.browser.pop_query();
                }
            }
            KeyCode::Esc => {
                if !self.browser.query().is_empty() {
                    self.browser.clear_query();
                } else {
                    match self.flow {
                        Flow::Encrypt => self.step = Step::Compression,
                        Flow::Decrypt => self.back_to_welcome(),
                    }
                }
            }
            KeyCode::Enter | KeyCode::Right => {
                let action = if self.browser.is_path_query() {
                    self.browser.resolve_query()
                } else {
                    self.browser.activate()
                };
                match action {
                    Action::Chosen(path) => self.choose_path(path),
                    Action::None if self.browser.is_path_query() => {
                        self.note = Some("No file or folder at that path.".into());
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }

    fn choose_path(&mut self, path: PathBuf) {
        self.password.zeroize();
        self.confirm.zeroize();
        self.field = Field::Password;

        match self.flow {
            Flow::Encrypt => {
                self.output = Some(backend::suggested_output(&path, self.backend));
                self.source = Some(path);
                if self.backend == Backend::Age && self.age_method == AgeMethod::Recipients {
                    // No passphrase — collect the recipient's public key next.
                    self.text_input.clear();
                    self.step = Step::Recipient;
                } else if self.backend == Backend::Zip {
                    self.enter_review(); // compress-only, no password
                } else {
                    self.step = Step::Passphrase;
                }
            }
            Flow::Decrypt => {
                match backend::backend_for(&path) {
                    Ok(b) => {
                        if b.locate().is_none() {
                            self.note = Some(format!(
                                "Opening this file needs {}. {}",
                                b.title(),
                                b.install_hint()
                            ));
                            return;
                        }
                        self.backend = b;
                    }
                    Err(e) => {
                        self.note = Some(e.to_string());
                        return;
                    }
                }
                self.output = path.parent().map(|p| p.to_path_buf());
                // A plain (unencrypted) zip opens without asking for a password.
                let encrypted = backend::is_encrypted(&path).unwrap_or(true);
                self.source = Some(path);
                if encrypted {
                    self.step = Step::Passphrase;
                } else {
                    self.enter_review();
                }
            }
        }
    }

    fn on_passphrase(&mut self, key: KeyEvent) {
        // Ctrl-R reveals/hides the typed password so a user can check it.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('r') {
            self.reveal = !self.reveal;
            return;
        }
        // Ctrl-K: open a recipient-encrypted age archive with a key file instead.
        if self.flow == Flow::Decrypt
            && self.backend == Backend::Age
            && key.modifiers.contains(KeyModifiers::CONTROL)
            && key.code == KeyCode::Char('k')
        {
            self.text_input.clear();
            self.step = Step::Identity;
            return;
        }
        match key.code {
            KeyCode::Esc => {
                self.password.zeroize();
                self.confirm.zeroize();
                self.reveal = false;
                self.step = Step::Browse;
            }
            KeyCode::Char(c) => self.current_field().push(c),
            KeyCode::Backspace => {
                self.current_field().pop();
            }
            KeyCode::Tab | KeyCode::Down | KeyCode::Up if self.flow == Flow::Encrypt => {
                self.field = match self.field {
                    Field::Password => Field::Confirm,
                    Field::Confirm => Field::Password,
                };
            }
            KeyCode::Enter => self.submit_passphrase(),
            _ => {}
        }
    }

    fn current_field(&mut self) -> &mut String {
        match self.field {
            Field::Password => &mut self.password,
            Field::Confirm => &mut self.confirm,
        }
    }

    // -- age recipient / identity entry -----------------------------------

    fn on_recipient(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => {
                self.text_input.clear();
                self.step = Step::Browse;
            }
            KeyCode::Char(c) => self.text_input.push(c),
            KeyCode::Backspace => {
                self.text_input.pop();
            }
            KeyCode::Enter => self.submit_recipient(),
            _ => {}
        }
    }

    fn submit_recipient(&mut self) {
        let raw = self.text_input.trim().to_string();
        if raw.is_empty() {
            self.note = Some("Paste the recipient's public key, or a key file path.".into());
            return;
        }
        // A path to a key file lists its recipients; otherwise it's a literal key.
        let path = crate::browser::expand_path(&raw, &home_dir());
        let recipients = if path.is_file() {
            match std::fs::read_to_string(&path) {
                Ok(text) => {
                    let v: Vec<String> = text
                        .lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty() && !l.starts_with('#'))
                        .map(str::to_string)
                        .collect();
                    if v.is_empty() {
                        self.note = Some("That key file has no recipients in it.".into());
                        return;
                    }
                    v
                }
                Err(_) => {
                    self.note = Some("Could not read that key file.".into());
                    return;
                }
            }
        } else {
            vec![raw]
        };
        self.recipients = recipients;
        self.enter_review();
    }

    fn on_identity(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => {
                self.text_input.clear();
                self.step = Step::Passphrase;
            }
            KeyCode::Char(c) => self.text_input.push(c),
            KeyCode::Backspace => {
                self.text_input.pop();
            }
            KeyCode::Enter => self.submit_identity(),
            _ => {}
        }
    }

    fn submit_identity(&mut self) {
        let raw = self.text_input.trim();
        if raw.is_empty() {
            self.note = Some("Enter the path to your age key file.".into());
            return;
        }
        let path = crate::browser::expand_path(raw, &home_dir());
        if !path.is_file() {
            self.note = Some("No key file at that path.".into());
            return;
        }
        self.identity = Some(path);
        self.enter_review();
    }

    /// Forget any age recipients/identity and reset to password mode (called
    /// when starting a fresh encrypt or decrypt).
    fn reset_lock_state(&mut self) {
        self.age_method = AgeMethod::Password;
        self.recipients.clear();
        self.identity = None;
        self.text_input.clear();
    }

    fn submit_passphrase(&mut self) {
        if self.password.is_empty() {
            self.note = Some("Please type a password.".into());
            return;
        }
        if self.flow == Flow::Encrypt {
            // Let the first Enter move from the password field to confirm.
            if self.field == Field::Password && self.confirm.is_empty() {
                self.field = Field::Confirm;
                return;
            }
            if self.password != self.confirm {
                self.note = Some("The two passwords don't match. Try again.".into());
                self.confirm.zeroize();
                self.field = Field::Confirm;
                return;
            }
        }
        self.enter_review();
    }

    fn on_review(&mut self, code: KeyCode) {
        if self.editing_output {
            match code {
                KeyCode::Esc => self.editing_output = false,
                KeyCode::Enter => self.commit_output_edit(),
                KeyCode::Char(c) => self.output_input.push(c),
                KeyCode::Backspace => {
                    self.output_input.pop();
                }
                _ => {}
            }
            return;
        }
        match code {
            KeyCode::Char('e') => self.begin_output_edit(),
            KeyCode::Esc => self.review_back(),
            KeyCode::Enter => self.start_job(),
            _ => {}
        }
    }

    /// Step back from Review to whichever screen led here.
    fn review_back(&mut self) {
        self.step = match self.flow {
            Flow::Encrypt => {
                if self.backend == Backend::Age && self.age_method == AgeMethod::Recipients {
                    Step::Recipient
                } else if self.backend == Backend::Zip {
                    Step::Browse
                } else {
                    Step::Passphrase
                }
            }
            Flow::Decrypt if self.identity.is_some() => Step::Identity,
            Flow::Decrypt => Step::Passphrase,
        };
    }

    /// Start editing the destination on Review, seeded with the current path.
    fn begin_output_edit(&mut self) {
        self.output_input = self
            .output
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        self.editing_output = true;
    }

    /// Apply the typed destination. A relative path resolves against the folder
    /// the file/extraction was already headed for (encrypt: the output's parent;
    /// decrypt: the destination folder itself); `~` and absolute paths override.
    fn commit_output_edit(&mut self) {
        self.editing_output = false;
        let raw = self.output_input.trim();
        if raw.is_empty() {
            return;
        }
        let base = match self.flow {
            Flow::Encrypt => self
                .output
                .as_ref()
                .and_then(|p| p.parent())
                .map(Path::to_path_buf),
            Flow::Decrypt => self.output.clone(),
        }
        .unwrap_or_else(home_dir);
        self.output = Some(crate::browser::expand_path(raw, &base));
        self.recompute_overwrite();
    }

    fn on_finished(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Enter => {
                self.outcome = None;
                self.source = None;
                self.output = None;
                self.menu = 0;
                self.reset_lock_state();
                self.step = Step::Welcome;
            }
            _ => {}
        }
    }

    // -- worker -----------------------------------------------------------

    fn start_job(&mut self) {
        let (Some(source), Some(output)) = (self.source.clone(), self.output.clone()) else {
            return;
        };
        let backend = self.backend;
        let flow = self.flow;
        let level = self.level;
        let age_method = self.age_method;
        let recipients = self.recipients.clone();
        let identity = self.identity.clone();
        // Hand the worker a copy that wipes itself on drop. (String zeroization
        // is best-effort: chars typed earlier may have left reallocated copies.)
        let password = Zeroizing::new(std::mem::take(&mut self.password));
        self.confirm.zeroize();

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let result = match flow {
                Flow::Encrypt => {
                    let r = if backend == Backend::Age && age_method == AgeMethod::Recipients {
                        backend::encrypt_for_recipients(&source, &output, &recipients, level)
                    } else {
                        backend::encrypt(backend, &source, &output, &password, level)
                    };
                    r.map(|()| output.clone())
                }
                Flow::Decrypt => match &identity {
                    Some(id) => backend::decrypt_with_identity(&source, &output, id),
                    None => backend::decrypt(&source, &output, &password),
                },
            };
            let _ = tx.send(result.map_err(|e| e.to_string()));
        });

        self.job = Some(rx);
        self.job_start = self.tick;
        self.step = Step::Working;
    }

    fn poll_job(&mut self) {
        if let Some(rx) = &self.job {
            if let Ok(result) = rx.try_recv() {
                self.outcome = Some(result);
                self.job = None;
                self.step = Step::Finished;
            }
        }
    }

    // -- helpers ----------------------------------------------------------

    fn back_to_welcome(&mut self) {
        self.menu = 0;
        self.step = Step::Welcome;
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Instant;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn typed(app: &mut App, text: &str) {
        for c in text.chars() {
            app.on_key(press(KeyCode::Char(c)));
        }
    }

    fn run_job_to_completion(app: &mut App) {
        let deadline = Instant::now() + Duration::from_secs(30);
        while app.outcome.is_none() && Instant::now() < deadline {
            app.poll_job();
            thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn welcome_enter_starts_encrypt_flow() {
        let mut app = App::new();
        assert!(matches!(app.step, Step::Welcome));
        app.on_key(press(KeyCode::Enter));
        assert!(matches!(app.step, Step::ChooseBackend));
        assert_eq!(app.flow, Flow::Encrypt);
    }

    #[test]
    fn welcome_down_to_open_flow() {
        let mut app = App::new();
        app.on_key(press(KeyCode::Down));
        app.on_key(press(KeyCode::Enter));
        assert!(matches!(app.step, Step::Browse));
        assert_eq!(app.flow, Flow::Decrypt);
    }

    #[test]
    fn browse_typing_builds_a_query_and_esc_clears_it() {
        let mut app = App::new();
        app.step = Step::Browse;
        typed(&mut app, "ab");
        assert_eq!(app.browser.query(), "ab");
        app.on_key(press(KeyCode::Esc));
        assert_eq!(app.browser.query(), "", "esc empties the query first");
        assert!(
            matches!(app.step, Step::Browse),
            "esc with a query stays on the browse screen"
        );
    }

    #[test]
    fn browse_backspace_edits_query_before_leaving_folder() {
        let mut app = App::new();
        app.step = Step::Browse;
        typed(&mut app, "ab");
        app.on_key(press(KeyCode::Backspace));
        assert_eq!(app.browser.query(), "a");
    }

    #[test]
    fn choosing_a_backend_advances_the_wizard() {
        for (downs, backend) in [
            (0usize, Backend::Age),
            (1, Backend::SevenZip),
            (2, Backend::Zip),
        ] {
            if backend.locate().is_none() {
                continue; // skip an uninstalled backend
            }
            let mut app = App::new();
            app.flow = Flow::Encrypt;
            app.step = Step::ChooseBackend;
            for _ in 0..downs {
                app.on_key(press(KeyCode::Down));
            }
            app.on_key(press(KeyCode::Enter));
            if backend == Backend::Age {
                // age first asks how to lock (password vs recipient).
                assert!(
                    matches!(app.step, Step::AgeMethod),
                    "age should lead to the method step"
                );
            } else {
                assert!(
                    matches!(app.step, Step::Compression),
                    "{backend:?} should lead to the compression step"
                );
            }
        }
    }

    #[test]
    fn seven_zip_compression_accepts_a_typed_level() {
        let mut app = App::new();
        app.backend = Backend::SevenZip;
        app.step = Step::Compression;
        app.level_input = "5".into();
        app.on_key(press(KeyCode::Char('9')));
        app.confirm_compression();
        assert_eq!(app.level, 9);
        assert!(matches!(app.step, Step::Browse));
    }

    #[test]
    fn seven_zip_compression_defaults_to_normal_when_blank() {
        let mut app = App::new();
        app.backend = Backend::SevenZip;
        app.step = Step::Compression;
        app.on_key(press(KeyCode::Backspace)); // clear the "5"
        app.confirm_compression();
        assert_eq!(app.level, 5, "blank entry falls back to Normal (5)");
    }

    #[test]
    fn age_compression_presets_map_to_gzip_levels() {
        for (menu, expected) in [(0u8, 0u8), (1, 6), (2, 9)] {
            let mut app = App::new();
            app.backend = Backend::Age;
            app.step = Step::Compression;
            app.menu = menu as usize;
            app.confirm_compression();
            assert_eq!(app.level, expected, "age preset {menu}");
        }
    }

    #[test]
    fn zip_skips_the_password_step() {
        let mut app = App::new();
        app.flow = Flow::Encrypt;
        app.backend = Backend::Zip;
        app.choose_path(PathBuf::from("/tmp/docs"));
        assert!(
            matches!(app.step, Step::Review),
            "zip is compress-only — straight to review"
        );
        assert!(app.password.is_empty());
    }

    #[test]
    fn age_asks_for_a_password() {
        let mut app = App::new();
        app.flow = Flow::Encrypt;
        app.backend = Backend::Age;
        app.choose_path(PathBuf::from("/tmp/docs"));
        assert!(matches!(app.step, Step::Passphrase));
    }

    #[test]
    fn opening_a_plain_zip_skips_the_password_step() {
        if Backend::Zip.locate().is_none() {
            eprintln!("skipping: 7z backend not installed");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("docs");
        fs::create_dir(&src).unwrap();
        fs::write(src.join("a.txt"), b"hi").unwrap();
        let zip = dir.path().join("docs.zip");
        backend::encrypt(Backend::Zip, &src, &zip, "", 5).unwrap();

        let mut app = App::new();
        app.flow = Flow::Decrypt;
        app.choose_path(zip);
        assert!(
            matches!(app.step, Step::Review),
            "a plain zip opens without a password"
        );
    }

    #[test]
    fn quit_from_welcome() {
        let mut app = App::new();
        app.on_key(press(KeyCode::Char('q')));
        assert!(app.quit);
    }

    #[test]
    fn mismatched_passwords_are_rejected() {
        let mut app = App::new();
        app.flow = Flow::Encrypt;
        app.source = Some(PathBuf::from("/tmp/whatever"));
        app.step = Step::Passphrase;
        app.field = Field::Password;

        typed(&mut app, "hunter2");
        app.on_key(press(KeyCode::Tab));
        typed(&mut app, "hunterX");
        app.on_key(press(KeyCode::Enter));

        assert!(
            matches!(app.step, Step::Passphrase),
            "should stay on the password screen"
        );
        assert!(app.note.is_some(), "should explain the mismatch");
    }

    #[test]
    fn matching_passwords_advance_to_review() {
        let mut app = App::new();
        app.flow = Flow::Encrypt;
        app.source = Some(PathBuf::from("/tmp/whatever"));
        app.step = Step::Passphrase;

        typed(&mut app, "hunter2");
        app.on_key(press(KeyCode::Tab));
        typed(&mut app, "hunter2");
        app.on_key(press(KeyCode::Enter));

        assert!(matches!(app.step, Step::Review));
    }

    #[test]
    fn wizard_encrypts_and_decrypts_through_the_worker() {
        if Backend::Age.locate().is_none() {
            eprintln!("skipping: age backend not installed");
            return;
        }
        let ws = tempfile::tempdir().unwrap();
        let src = ws.path().join("memo");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("note.txt"), b"wizard end to end\n").unwrap();
        let out = backend::suggested_output(&src, Backend::Age);

        // Encrypt through Review -> Working -> Finished.
        let mut app = App::new();
        app.flow = Flow::Encrypt;
        app.backend = Backend::Age;
        app.source = Some(src.clone());
        app.output = Some(out.clone());
        app.password = "s3cret".into();
        app.step = Step::Review;
        app.on_key(press(KeyCode::Enter));
        assert!(matches!(app.step, Step::Working));
        run_job_to_completion(&mut app);
        assert!(matches!(app.step, Step::Finished));
        assert!(
            matches!(app.outcome, Some(Ok(_))),
            "encrypt outcome: {:?}",
            app.outcome
        );
        assert!(out.exists());
        assert!(
            app.password.is_empty(),
            "password should be cleared after the job starts"
        );

        // Decrypt the result back.
        let dest = ws.path().join("restored");
        let mut app = App::new();
        app.flow = Flow::Decrypt;
        app.source = Some(out.clone());
        app.output = Some(dest.clone());
        app.password = "s3cret".into();
        app.step = Step::Review;
        app.on_key(press(KeyCode::Enter));
        run_job_to_completion(&mut app);
        assert!(
            matches!(app.outcome, Some(Ok(_))),
            "decrypt outcome: {:?}",
            app.outcome
        );
        assert_eq!(
            fs::read(dest.join("memo/note.txt")).unwrap(),
            b"wizard end to end\n"
        );
    }

    #[test]
    fn wizard_zip_flow_produces_a_plain_archive() {
        if Backend::Zip.locate().is_none() {
            eprintln!("skipping: 7z backend not installed");
            return;
        }
        let ws = tempfile::tempdir().unwrap();
        let src = ws.path().join("docs");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("a.txt"), b"plain data\n").unwrap();
        let out = backend::suggested_output(&src, Backend::Zip);

        let mut app = App::new();
        app.flow = Flow::Encrypt;
        app.step = Step::ChooseBackend;
        app.on_key(press(KeyCode::Down));
        app.on_key(press(KeyCode::Down));
        app.on_key(press(KeyCode::Enter)); // zip -> Compression
        assert!(matches!(app.step, Step::Compression));
        app.on_key(press(KeyCode::Enter)); // accept default level -> Browse
        assert!(matches!(app.step, Step::Browse));

        app.choose_path(src.clone());
        assert!(
            matches!(app.step, Step::Review),
            "zip needs no password — straight to review"
        );
        app.on_key(press(KeyCode::Enter)); // start_job
        run_job_to_completion(&mut app);
        assert!(
            matches!(app.outcome, Some(Ok(_))),
            "outcome: {:?}",
            app.outcome
        );
        assert!(out.exists());
        assert!(
            !backend::is_encrypted(&out).unwrap(),
            "zip must never be encrypted"
        );
    }

    #[test]
    fn age_recipient_wizard_routes_through_recipient_step() {
        if Backend::Age.locate().is_none() {
            eprintln!("skipping: age backend not installed");
            return;
        }
        let mut app = App::new();
        app.flow = Flow::Encrypt;
        app.step = Step::ChooseBackend; // age is menu 0
        app.on_key(press(KeyCode::Enter)); // choose age -> AgeMethod
        assert!(matches!(app.step, Step::AgeMethod));

        app.on_key(press(KeyCode::Down)); // highlight "for a recipient"
        app.on_key(press(KeyCode::Enter)); // -> Compression
        assert!(matches!(app.step, Step::Compression));
        assert_eq!(app.age_method, AgeMethod::Recipients);

        app.on_key(press(KeyCode::Enter)); // accept compression -> Browse
        assert!(matches!(app.step, Step::Browse));

        app.choose_path(PathBuf::from("/tmp/docs")); // -> Recipient (no password)
        assert!(matches!(app.step, Step::Recipient));

        typed(&mut app, "age1qqqexamplekey");
        app.on_key(press(KeyCode::Enter)); // -> Review
        assert!(matches!(app.step, Step::Review));
        assert_eq!(app.recipients, vec!["age1qqqexamplekey".to_string()]);
        // Esc from Review goes back to the recipient step, not the password one.
        app.on_key(press(KeyCode::Esc));
        assert!(matches!(app.step, Step::Recipient));
    }

    #[test]
    fn decrypt_age_ctrl_k_opens_identity_entry_and_validates() {
        let mut app = App::new();
        app.flow = Flow::Decrypt;
        app.backend = Backend::Age;
        app.step = Step::Passphrase;
        app.on_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL));
        assert!(matches!(app.step, Step::Identity));

        typed(&mut app, "/no/such/key");
        app.on_key(press(KeyCode::Enter));
        assert!(
            matches!(app.step, Step::Identity),
            "a missing key file keeps us on the entry screen"
        );
        assert!(app.note.is_some());
        assert!(app.identity.is_none());
    }

    #[test]
    fn decrypt_age_identity_accepts_an_existing_key_file() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id.txt");
        fs::write(&key, b"AGE-SECRET-KEY-EXAMPLE").unwrap();

        let mut app = App::new();
        app.flow = Flow::Decrypt;
        app.backend = Backend::Age;
        app.source = Some(dir.path().join("x.age"));
        app.output = Some(dir.path().to_path_buf());
        app.step = Step::Identity;
        typed(&mut app, key.to_str().unwrap());
        app.on_key(press(KeyCode::Enter));

        assert!(matches!(app.step, Step::Review));
        assert_eq!(app.identity.as_deref(), Some(key.as_path()));
    }

    #[test]
    fn finished_enter_returns_to_welcome() {
        let mut app = App::new();
        app.step = Step::Finished;
        app.outcome = Some(Ok(PathBuf::from("/tmp/x.age")));
        app.on_key(press(KeyCode::Enter));
        assert!(matches!(app.step, Step::Welcome));
        assert!(app.outcome.is_none());
    }

    #[test]
    fn esc_on_welcome_does_not_quit() {
        let mut app = App::new();
        app.on_key(press(KeyCode::Esc));
        assert!(!app.quit, "Esc on Welcome should be a no-op, not an exit");
        assert!(matches!(app.step, Step::Welcome));
    }

    #[test]
    fn ctrl_r_toggles_password_reveal() {
        let mut app = App::new();
        app.step = Step::Passphrase;
        assert!(!app.reveal);
        app.on_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
        assert!(app.reveal, "Ctrl-R should reveal");
        app.on_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::CONTROL));
        assert!(!app.reveal, "Ctrl-R again should hide");
        // A plain 'r' is still a password character, not a toggle.
        app.on_key(press(KeyCode::Char('r')));
        assert_eq!(app.password, "r");
        assert!(!app.reveal);
    }

    #[test]
    fn review_flags_an_existing_output_for_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("thing.age");
        fs::write(&out, b"old").unwrap();

        let mut app = App::new();
        app.flow = Flow::Encrypt;
        app.source = Some(dir.path().join("thing"));
        app.output = Some(out);
        app.step = Step::Passphrase;
        typed(&mut app, "hunter2");
        app.on_key(press(KeyCode::Tab));
        typed(&mut app, "hunter2");
        app.on_key(press(KeyCode::Enter));

        assert!(matches!(app.step, Step::Review));
        assert!(app.will_overwrite, "an existing output must be flagged");
    }

    #[test]
    fn editing_the_destination_retargets_output_and_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let existing = dir.path().join("existing.age");
        fs::write(&existing, b"x").unwrap();

        let mut app = App::new();
        app.flow = Flow::Encrypt;
        app.source = Some(dir.path().join("thing"));
        app.output = Some(dir.path().join("thing.age")); // fresh, no overwrite
        app.step = Step::Review;

        app.on_key(press(KeyCode::Char('e'))); // begin edit
        assert!(app.editing_output);
        let seeded = app.output_input.len();
        for _ in 0..seeded {
            app.on_key(press(KeyCode::Backspace));
        }
        typed(&mut app, existing.to_str().unwrap());
        app.on_key(press(KeyCode::Enter)); // commit

        assert!(!app.editing_output);
        assert_eq!(app.output.as_deref(), Some(existing.as_path()));
        assert!(
            app.will_overwrite,
            "retargeting onto an existing file must flag the overwrite"
        );
    }

    #[test]
    fn editing_the_destination_accepts_a_bare_name_beside_the_original() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new();
        app.flow = Flow::Encrypt;
        app.source = Some(dir.path().join("thing"));
        app.output = Some(dir.path().join("thing.age"));
        app.step = Step::Review;

        app.on_key(press(KeyCode::Char('e')));
        let seeded = app.output_input.len();
        for _ in 0..seeded {
            app.on_key(press(KeyCode::Backspace));
        }
        typed(&mut app, "backup.age"); // bare name -> same folder as the original
        app.on_key(press(KeyCode::Enter));

        assert_eq!(
            app.output.as_deref(),
            Some(dir.path().join("backup.age").as_path())
        );
    }

    #[test]
    fn review_does_not_flag_a_fresh_output() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = App::new();
        app.flow = Flow::Encrypt;
        app.source = Some(dir.path().join("thing"));
        app.output = Some(dir.path().join("thing.age")); // does not exist
        app.step = Step::Passphrase;
        typed(&mut app, "pw");
        app.on_key(press(KeyCode::Tab));
        typed(&mut app, "pw");
        app.on_key(press(KeyCode::Enter));

        assert!(matches!(app.step, Step::Review));
        assert!(!app.will_overwrite);
    }
}
