//! The wizard: a small state machine over a handful of screens, plus a worker
//! thread so encryption never freezes the interface.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::DefaultTerminal;

use crate::backend::{self, Backend};
use crate::browser::{Action, Browser};

const ARCHIVE_EXTS: &[&str] = &["age", "7z"];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flow {
    Encrypt,
    Decrypt,
}

pub enum Step {
    Welcome,
    ChooseBackend,
    Browse,
    Passphrase,
    Review,
    Working,
    Finished,
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
    pub menu: usize,
    pub browser: Browser,
    pub password: String,
    pub confirm: String,
    pub field: Field,
    pub source: Option<PathBuf>,
    pub output: Option<PathBuf>,
    /// A transient, plain-language note shown in red (e.g. passwords differ).
    pub note: Option<String>,
    pub tick: u64,
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
            menu: 0,
            browser: Browser::new(home_dir(), None),
            password: String::new(),
            confirm: String::new(),
            field: Field::Password,
            source: None,
            output: None,
            note: None,
            tick: 0,
            outcome: None,
            job: None,
            quit: false,
        }
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
            Step::Browse => self.on_browse(key.code),
            Step::Passphrase => self.on_passphrase(key),
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
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Enter => match self.menu {
                0 => {
                    self.flow = Flow::Encrypt;
                    self.menu = 0;
                    self.step = Step::ChooseBackend;
                }
                1 => {
                    self.flow = Flow::Decrypt;
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
            KeyCode::Down => self.menu = (self.menu + 1).min(1),
            KeyCode::Esc => self.back_to_welcome(),
            KeyCode::Enter => {
                let backend = if self.menu == 0 {
                    Backend::Age
                } else {
                    Backend::SevenZip
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
                self.browser = Browser::new(home_dir(), None);
                self.step = Step::Browse;
            }
            _ => {}
        }
    }

    fn on_browse(&mut self, code: KeyCode) {
        match code {
            KeyCode::Up => self.browser.move_up(),
            KeyCode::Down => self.browser.move_down(),
            KeyCode::Left | KeyCode::Backspace => self.browser.go_up(),
            KeyCode::Esc => match self.flow {
                Flow::Encrypt => {
                    self.menu = 0;
                    self.step = Step::ChooseBackend;
                }
                Flow::Decrypt => self.back_to_welcome(),
            },
            KeyCode::Enter | KeyCode::Right => {
                if let Action::Chosen(path) = self.browser.activate() {
                    self.choose_path(path);
                }
            }
            _ => {}
        }
    }

    fn choose_path(&mut self, path: PathBuf) {
        match self.flow {
            Flow::Encrypt => {
                self.output = Some(backend::suggested_output(&path, self.backend));
                self.source = Some(path);
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
                self.source = Some(path);
            }
        }
        self.password.clear();
        self.confirm.clear();
        self.field = Field::Password;
        self.step = Step::Passphrase;
    }

    fn on_passphrase(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.password.clear();
                self.confirm.clear();
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
                self.confirm.clear();
                self.field = Field::Confirm;
                return;
            }
        }
        self.step = Step::Review;
    }

    fn on_review(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => self.step = Step::Passphrase,
            KeyCode::Enter => self.start_job(),
            _ => {}
        }
    }

    fn on_finished(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => self.quit = true,
            KeyCode::Enter => {
                self.outcome = None;
                self.source = None;
                self.output = None;
                self.menu = 0;
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
        let password = std::mem::take(&mut self.password);
        self.confirm.clear();

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let result = match flow {
                Flow::Encrypt => {
                    backend::encrypt(backend, &source, &output, &password).map(|()| output.clone())
                }
                Flow::Decrypt => backend::decrypt(&source, &output, &password),
            };
            let _ = tx.send(result.map_err(|e| e.to_string()));
        });

        self.job = Some(rx);
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
    fn finished_enter_returns_to_welcome() {
        let mut app = App::new();
        app.step = Step::Finished;
        app.outcome = Some(Ok(PathBuf::from("/tmp/x.age")));
        app.on_key(press(KeyCode::Enter));
        assert!(matches!(app.step, Step::Welcome));
        assert!(app.outcome.is_none());
    }
}
