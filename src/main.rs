use std::process::ExitCode;

const HELP: &str = "\
zipline — lock your files with one password

Usage:
  zipline                 Start the wizard (encrypt or open a file/folder)
  zipline lock <path>     Lock/compress a file or folder (for scripts)
                          [--out FILE] [--backend age|7z|zip] [--level 0-9]
  zipline open <file>     Extract an archive (for scripts) [--out DIR]
  zipline doctor          Check which helper tools (age, 7z, tar, gzip) exist
  zipline update          Update to the latest release
  zipline --version       Print the version
  zipline --help          Show this message

With no arguments, the wizard walks you through everything: pick a file or
folder, choose a password, and zipline encrypts it. `lock`/`open` do the same
non-interactively, prompting for the password on the terminal (never a flag).";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("--version" | "-V") => {
            println!("zipline {}", zipline::VERSION);
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        Some("doctor") => {
            print!("{}", zipline::backend::doctor());
            ExitCode::SUCCESS
        }
        Some("lock") => report(zipline::cli::lock(&args[1..])),
        Some("open") => report(zipline::cli::open(&args[1..])),
        Some("update") => report(zipline::update::run()),
        Some(other) => {
            eprintln!("zipline: unknown option '{other}'\nTry 'zipline --help'.");
            ExitCode::FAILURE
        }
        None => report(zipline::run()),
    }
}

/// Map a fallible command to an exit code, printing any error.
fn report(result: anyhow::Result<()>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("zipline: {e}");
            ExitCode::FAILURE
        }
    }
}
