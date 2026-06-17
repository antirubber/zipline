# zipline

> Lock your files with one password — a friendly terminal wizard.

zipline encrypts a file or folder behind a single password, with a simple
step-by-step wizard. No flags to remember, no crypto jargon. It wraps the
trusted [`age`](https://github.com/FiloSottile/age) and
[`7-Zip`](https://www.7-zip.org/) tools that ship in your distribution's
package repositories, so there is no home-grown cryptography to trust. It can
also write a plain `.zip` when you just need a compressed file that opens
anywhere.

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

**To protect or compress something**
1. Choose **Lock or compress a file**.
2. Pick a method:
   - **Lock with a password — age** (strongest, opens with zipline),
   - **Lock with a password — 7z** (opens in 7-Zip / WinZip / Keka), or
   - **Compress only — zip** (no password, opens anywhere).
3. Choose a **compression level** (age offers None / Normal / Maximum; 7z and
   zip take a level 0–9).
4. Find the file or folder: arrow through the list, **type to filter** it,
   **paste a full path** and press Enter to jump straight there, or press
   **Tab** to show hidden (dot) files. To bundle several items from the same
   folder into one archive, press **Space** to mark each one, then **Enter** to
   lock them all together.
5. Type a password (twice) — skipped for zip, which never has one. Press
   **Ctrl-R** to reveal what you typed, and you'll be warned before replacing an
   existing file.
6. Done — you get one file next to the original (named after the folder when you
   marked several items).

**To open it again**
1. Run `zipline` and choose **Open a locked file**.
2. Browse to the `.age`, `.7z`, or `.zip` file (same filter / paste-a-path
   picker).
3. Type the password if it needs one. Your files are unpacked back out. A
   password-free zip opens with no prompt at all.

> **Keep your password safe.** There is no recovery — without it, the file can
> never be opened. That is the point.

### Lock for a person (no shared password)

When you pick **age**, you can choose **Lock for a person** instead of a
password. Paste the recipient's age public key (`age1…`) or point at their key
file, and only their matching key opens the file — there is no password to share
over the phone. To open one sent to you, browse to it, then press **Ctrl-K** on
the password screen to choose your own key file.

### From a script

`lock` and `open` do the same thing without the wizard, prompting for the
password on the terminal (never a flag, so it stays out of `ps` and your shell
history):

```sh
zipline lock ~/Photos --backend age --level 9      # writes ~/Photos.age
zipline open ~/Photos.age --out ~/Restored

# Bundle several items from one folder into a single archive:
zipline lock ~/taxes/w2.pdf ~/taxes/receipts --backend 7z   # writes ~/taxes/taxes.7z
```

The items you lock together must live in the same folder; the archive is named
after it unless you pass `--out`.

`zipline doctor` reports which helper tools are installed.

## Which method should I pick?

| | age (strongest) | 7z (portable) | zip (compress only) |
|---|---|---|---|
| Password | yes | yes | **no** |
| Strength | ChaCha20-Poly1305, authenticated | AES-256 | none |
| Detects tampering / wrong password | yes | yes | n/a |
| Hides file names | yes | yes | no |
| Opens without zipline | no | yes (7-Zip / WinZip / Keka) | yes (anything) |
| Opens by double-click, no extra software | no | no | **yes** |

**age** is the default and the strongest. It uses authenticated encryption, so a
corrupted or tampered file is detected and reported in plain language instead of
producing garbage. To keep file names and folder structure private, zipline
streams everything through `tar` into a single `age` file — you only ever pick a
folder; the plumbing stays hidden.

Pick **7z** when you need to send a *password-protected* file to someone on
Windows or macOS who does not have zipline: a `.7z` opens in 7-Zip, WinZip, or
Keka.

Pick **zip** for the widest reach — every operating system opens a `.zip` by
double-clicking, no extra software. A zip is **compress-only**: it has no
password and does not protect the contents. If you need a password, use **age**
or **7z**.

> **Why no password-protected zip?** A zip's only universally-readable
> encryption (ZipCrypto) is cryptographically broken, and strong AES-256 zips
> only open in 7-Zip / WinZip / Keka — the same reach as `.7z`, but with file
> names left visible. So zipline keeps zip for compatibility and sends
> protection through age or 7z.

Every method also asks for a **compression level**. Higher = smaller file but
slower; lower = faster. age offers None / Normal / Maximum; 7z and zip take a
number from 0 (store, no compression) to 9 (smallest).

## Troubleshooting

**Check your setup.** Run `zipline doctor` to see which helper tools
(`age`, `7z`, `tar`, `gzip`) zipline can find, with the install command for any
that are missing.

**A password-protected `.7z` lists in xarchiver but won't extract.** This is a
bug in **xarchiver** (the default archive manager on Debian/XFCE), not in the
file. xarchiver passes `-spd` to suppress 7-Zip's password prompt but fails to
forward your password to the extract command, so it dies silently. xarchiver is
only thinly maintained (one volunteer), and this bug is open and unfixed;
header-encrypted (`-mhe=on`) 7z archives are
[acknowledged as broken upstream](https://bugs.debian.org/959914).

The archive itself is standard `LZMA2 + AES-256` and extracts everywhere else.
On Linux, open it with any of:

```sh
7z x archive.7z      # the 7-Zip CLI prompts for the password
```

or a working GUI — **Ark** (`sudo apt install ark`) or **file-roller**
(`sudo apt install file-roller`), both of which prompt correctly. On Windows
(7-Zip / WinRAR) and macOS (Keka) it just works. For Linux-to-Linux transfers,
**age** sidesteps the whole issue.

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
