use std::process::ExitCode;

const HELP: &str = "\
zipline — lock your files with one password

Usage:
  zipline            Start the wizard (encrypt or open a file/folder)
  zipline update     Update to the latest release
  zipline --version  Print the version
  zipline --help     Show this message

The wizard walks you through everything: pick a file or folder, choose a
password, and zipline encrypts it. To unpack a file later, run zipline again
and choose \"Extract\".";

fn main() -> ExitCode {
    match std::env::args().nth(1).as_deref() {
        Some("--version" | "-V") => {
            println!("zipline {}", zipline::VERSION);
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") => {
            println!("{HELP}");
            ExitCode::SUCCESS
        }
        Some("update") => match zipline::update::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("zipline: {e}");
                ExitCode::FAILURE
            }
        },
        Some(other) => {
            eprintln!("zipline: unknown option '{other}'\nTry 'zipline --help'.");
            ExitCode::FAILURE
        }
        None => match zipline::run() {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("zipline: {e}");
                ExitCode::FAILURE
            }
        },
    }
}
