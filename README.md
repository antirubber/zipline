# zipline

> Lock your files with one password — a friendly terminal wizard.

zipline encrypts a file or folder behind a single password, with a simple
step-by-step wizard. No flags to remember, no crypto jargon. It wraps the
trusted [`age`](https://github.com/FiloSottile/age) and
[`7-Zip`](https://www.7-zip.org/) tools that ship in your distribution's
package repositories, so there is no home-grown cryptography to trust. It can
also write a plain or AES-256 `.zip` when you need a file that opens anywhere.

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
2. Pick **Secure** (strongest), **Portable** (opens on Windows & Mac), or
   **Compatible** (a `.zip` anyone can open). For a zip, choose whether to set
   an AES-256 password or leave it open.
3. Find the file or folder: arrow through the list, **type to filter** it, or
   **paste a full path** and press Enter to jump straight there.
4. Type a password (twice) — skipped for a no-password zip.
5. Done — you get one file next to the original.

**To open it again**
1. Run `zipline` and choose **Open an encrypted file**.
2. Browse to the `.age`, `.7z`, or `.zip` file (same filter / paste-a-path
   picker).
3. Type the password. Your files are unpacked back out. A plain zip opens with
   no password at all.

> **Keep your password safe.** There is no recovery — without it, the file can
> never be opened. That is the point.

## Which protection should I pick?

| | Secure (age) | Portable (7z) | Compatible (zip) |
|---|---|---|---|
| Strength | ChaCha20-Poly1305, authenticated | AES-256 | AES-256, or none |
| Detects tampering / wrong password | yes | yes | wrong password, yes |
| Hides file names | yes | yes | **no** |
| Opens on Windows / macOS without zipline | no | yes (7-Zip, Keka) | yes |
| Opens by double-click, no extra software | no | no | yes (plain zip) |

**Secure (age)** is the default and the strongest. It uses authenticated
encryption, so a corrupted or tampered file is detected and reported in plain
language instead of producing garbage. To keep file names and folder structure
private, zipline streams everything through `tar` into a single `age` file —
you only ever pick a folder; the plumbing stays hidden.

Pick **Portable (7z)** when you need to send the file to someone on Windows or
macOS who does not have zipline: a `.7z` opens in 7-Zip or Keka.

Pick **Compatible (zip)** for the widest reach — every operating system opens a
`.zip` by double-clicking. You choose whether to set a password:

- **No password** — just a plain, convenient archive. Not protected; anyone can
  open it.
- **AES-256 password** — the contents are scrambled. Opening it needs 7-Zip,
  WinZip, or Keka and the password (the same reach as `.7z`, not Windows'
  built-in unzip).

> **The zip format cannot hide file names.** Even with a password, the list of
> files inside stays readable. When names are sensitive, choose **Secure** or
> **Portable**.

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
