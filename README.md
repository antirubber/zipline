# zipline

> Lock your files with one password — a friendly terminal wizard.

zipline encrypts a file or folder behind a single password, with a simple
step-by-step wizard. No flags to remember, no crypto jargon. It wraps the
trusted [`age`](https://github.com/FiloSottile/age) and
[`7-Zip`](https://www.7-zip.org/) tools that ship in your distribution's
package repositories, so there is no home-grown cryptography to trust.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/antirubber/zipline/main/install.sh | bash
```

The installer detects `apt` or `dnf`, installs the encryption backends, and
drops a single `zipline` binary in place (verifying its published SHA-256
checksum first). **Re-run it any time to upgrade** — when the installed version
already matches the latest release and the backends are present, it does
nothing; otherwise it fetches the latest binary. To pin a version, set
`ZIPLINE_VERSION=0.1.0` before the command.

## Usage

Just run it:

```sh
zipline
```

The wizard does the rest:

**To lock something**
1. Choose **Encrypt a file or folder**.
2. Pick **Secure** (strongest) or **Portable** (opens on Windows & Mac).
3. Browse to the file or folder with the arrow keys.
4. Type a password (twice).
5. Done — you get one encrypted file next to the original.

**To open it again**
1. Run `zipline` and choose **Open an encrypted file**.
2. Browse to the `.age` or `.7z` file.
3. Type the password. Your files are unpacked back out.

> **Keep your password safe.** There is no recovery — without it, the file can
> never be opened. That is the point.

## Which protection should I pick?

| | Secure (age) | Portable (7z) |
|---|---|---|
| Strength | ChaCha20-Poly1305, authenticated | AES-256 |
| Detects tampering / wrong password | yes | yes |
| Hides file names | yes | yes |
| Opens on Windows / macOS without zipline | no | yes (7-Zip, Keka) |

**Secure (age)** is the default and the strongest. It uses authenticated
encryption, so a corrupted or tampered file is detected and reported in plain
language instead of producing garbage. To keep file names and folder structure
private, zipline streams everything through `tar` into a single `age` file —
you only ever pick a folder; the plumbing stays hidden.

Pick **Portable (7z)** when you need to send the file to someone on Windows or
macOS who does not have zipline: a `.7z` opens in 7-Zip or Keka.

## Building from source

```sh
git clone https://github.com/antirubber/zipline
cd zipline
cargo build --release
# binary at target/release/zipline
```

Requirements: a recent Rust toolchain, plus `age` and/or `7zip` on your `PATH`
to actually encrypt. The test suite (`cargo test`) runs against the real
binaries and skips a backend that is not installed.

## License

MIT — see [LICENSE](LICENSE).
