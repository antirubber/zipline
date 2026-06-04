pub mod app;
pub mod backend;
pub mod browser;
pub mod pty;
pub mod ui;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Start the wizard: set up the terminal, run the event loop, restore on exit.
pub fn run() -> anyhow::Result<()> {
    let mut terminal = ratatui::init();
    let mut app = app::App::new();
    let result = app.run(&mut terminal);
    ratatui::restore();
    result
}
