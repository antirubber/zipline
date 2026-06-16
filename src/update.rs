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

/// The installer is fetched at the *installed* version's immutable release tag
/// rather than the mutable `main` branch, so tampering with `main` can't hijack
/// an `update`. That tagged installer still resolves and installs the latest
/// release (the binary it downloads is checksum-verified separately).
fn installer_url() -> String {
    format!(
        "https://raw.githubusercontent.com/antirubber/zipline/v{}/install.sh",
        crate::VERSION
    )
}

/// The shell pipeline that downloads and runs the installer. `pipefail` makes a
/// failed download surface as a failure instead of feeding `bash` empty input
/// (which would otherwise exit 0 and look like success).
fn installer_pipeline() -> String {
    format!("set -o pipefail; curl -fsSL {} | bash", installer_url())
}

pub fn run() -> Result<()> {
    if which("curl").is_none() {
        bail!("curl is required to update; install it and try again");
    }
    if which("bash").is_none() {
        bail!("bash is required to update; install it and try again");
    }

    println!("Updating zipline from {}\n", installer_url());
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
    fn pipeline_pins_the_installer_to_the_release_tag() {
        let p = installer_pipeline();
        assert!(p.contains("set -o pipefail"), "missing pipefail guard: {p}");
        assert!(
            p.contains(&format!(
                "raw.githubusercontent.com/antirubber/zipline/v{}/install.sh",
                crate::VERSION
            )),
            "installer not pinned to the release tag: {p}"
        );
        assert!(
            !p.contains("/main/"),
            "installer must not be pulled from mutable main: {p}"
        );
        assert!(p.contains("| bash"), "installer is not piped to bash: {p}");
    }
}
