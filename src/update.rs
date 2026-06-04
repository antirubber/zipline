//! `zipline update` — re-run the published installer to upgrade in place.
//!
//! The installer already knows how to resolve the latest release, verify the
//! checksum, replace the binary, and skip when nothing changed, so `update`
//! stays a thin wrapper rather than a second copy of that logic. Pinning still
//! works: `ZIPLINE_VERSION` is read by the installer and we pass the
//! environment straight through.

use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::backend::which;

const INSTALLER_URL: &str = "https://raw.githubusercontent.com/antirubber/zipline/main/install.sh";

/// The shell pipeline that downloads and runs the installer. `pipefail` makes a
/// failed download surface as a failure instead of feeding `bash` empty input
/// (which would otherwise exit 0 and look like success).
fn installer_pipeline() -> String {
    format!("set -o pipefail; curl -fsSL {INSTALLER_URL} | bash")
}

pub fn run() -> Result<()> {
    if which("curl").is_none() {
        bail!("curl is required to update; install it and try again");
    }
    if which("bash").is_none() {
        bail!("bash is required to update; install it and try again");
    }

    println!("Updating zipline from {INSTALLER_URL}\n");
    let status = Command::new("bash")
        .arg("-c")
        .arg(installer_pipeline())
        .status()
        .context("could not launch the updater")?;

    if !status.success() {
        bail!("the updater did not finish successfully");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pipeline_pulls_the_repo_installer_with_pipefail() {
        let p = installer_pipeline();
        assert!(p.contains("set -o pipefail"), "missing pipefail guard: {p}");
        assert!(
            p.contains("raw.githubusercontent.com/antirubber/zipline/main/install.sh"),
            "wrong installer URL: {p}"
        );
        assert!(p.contains("| bash"), "installer is not piped to bash: {p}");
    }
}
