#!/usr/bin/env bash
# zipline installer — safe to re-run; upgrades in place when a newer release exists.
#
#   curl -fsSL https://raw.githubusercontent.com/antirubber/zipline/main/install.sh | bash
#
set -euo pipefail

REPO="antirubber/zipline"
BIN="zipline"

# --- output helpers -------------------------------------------------------
if [ -t 1 ]; then
  C_STEP=$'\033[36m'; C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'; C_OFF=$'\033[0m'
else
  C_STEP=""; C_OK=""; C_WARN=""; C_ERR=""; C_OFF=""
fi
step() { printf '%s==>%s %s\n' "$C_STEP" "$C_OFF" "$*"; }
ok()   { printf '%s ok%s  %s\n' "$C_OK" "$C_OFF" "$*"; }
warn() { printf '%swarning:%s %s\n' "$C_WARN" "$C_OFF" "$*" >&2; }
die()  { printf '%serror:%s %s\n' "$C_ERR" "$C_OFF" "$*" >&2; exit 1; }

# --- detection ------------------------------------------------------------
detect_arch() {
  case "$(uname -m)" in
    x86_64 | amd64) echo "amd64" ;;
    aarch64 | arm64) echo "arm64" ;;
    *) die "unsupported CPU architecture: $(uname -m)" ;;
  esac
}

# Echo the system package manager, or nothing if none is recognised.
detect_pm() {
  for pm in apt-get dnf yum zypper pacman; do
    if command -v "$pm" >/dev/null 2>&1; then
      echo "$pm"
      return 0
    fi
  done
  return 0
}

# Run a privileged command via sudo when not already root.
as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    die "this step needs root; install sudo or re-run as root"
  fi
}

# Install one package, trying each candidate name until one succeeds.
pm_install() {
  local pm="$1"; shift
  local pkg
  for pkg in "$@"; do
    case "$pm" in
      apt-get) as_root apt-get install -y "$pkg" >/dev/null 2>&1 && return 0 ;;
      dnf | yum) as_root "$pm" install -y "$pkg" >/dev/null 2>&1 && return 0 ;;
      zypper) as_root zypper --non-interactive install "$pkg" >/dev/null 2>&1 && return 0 ;;
      pacman) as_root pacman -S --noconfirm "$pkg" >/dev/null 2>&1 && return 0 ;;
    esac
  done
  return 1
}

install_backends() {
  local pm="$1"
  if [ -z "$pm" ]; then
    warn "no known package manager found; install 'age' yourself for the secure backend"
    return 0
  fi
  if [ "$pm" = "apt-get" ]; then
    step "Refreshing package lists"
    as_root apt-get update -y >/dev/null 2>&1 || true
  fi

  step "Installing the secure backend (age)"
  if command -v age >/dev/null 2>&1; then
    ok "age already installed"
  elif pm_install "$pm" age; then
    ok "age installed"
  else
    warn "could not install 'age' automatically — the secure backend may be unavailable"
  fi

  step "Installing the portable backend (7-Zip)"
  if command -v 7zz >/dev/null 2>&1 || command -v 7z >/dev/null 2>&1 || command -v 7za >/dev/null 2>&1; then
    ok "7-Zip already installed"
  elif pm_install "$pm" 7zip p7zip-full p7zip; then
    ok "7-Zip installed"
  else
    warn "could not install 7-Zip — the portable backend will be unavailable (secure mode still works)"
  fi
}

# --- versions -------------------------------------------------------------
latest_version() {
  # An explicit pin skips the API entirely (handy behind a rate limit).
  if [ -n "${ZIPLINE_VERSION:-}" ]; then
    printf '%s' "${ZIPLINE_VERSION#v}"
    return 0
  fi
  # Resolve the newest release tag (e.g. v0.1.0 -> 0.1.0) via the GitHub API.
  local body code
  body="$(curl -sSL -w $'\n%{http_code}' "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null || true)"
  code="$(printf '%s' "$body" | tail -n1)"
  body="$(printf '%s' "$body" | sed '$d')"
  if [ "$code" = "403" ] || printf '%s' "$body" | grep -q "rate limit"; then
    die "GitHub API rate limit reached. Try again later, or pin a version:
  ZIPLINE_VERSION=0.1.0 curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | bash"
  fi
  printf '%s' "$body" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/p' | head -n1
}

installed_version() {
  if command -v "$BIN" >/dev/null 2>&1; then
    "$BIN" --version 2>/dev/null | awk '{print $2}'
  fi
}

# --- install --------------------------------------------------------------
choose_bindir() {
  # Upgrade the copy already on PATH in place, so the binary the user actually
  # runs is the one we replace. Installing elsewhere (e.g. always /usr/local/bin)
  # leaves an older copy earlier on PATH shadowing the update — `zipline` keeps
  # reporting the old version even though the new one installed fine.
  local existing
  existing="$(command -v "$BIN" 2>/dev/null || true)"
  if [ -n "$existing" ]; then
    dirname "$existing"
    return 0
  fi
  if [ -w /usr/local/bin ] 2>/dev/null; then
    echo "/usr/local/bin"
  elif [ "$(id -u)" -eq 0 ] || command -v sudo >/dev/null 2>&1; then
    echo "/usr/local/bin"
  else
    echo "$HOME/.local/bin"
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

verify_checksum() {
  local file="$1" url="$2"
  local sums expected actual
  sums="$(curl -fsSL "${url}.sha256" 2>/dev/null || true)"
  if [ -z "$sums" ]; then
    die "no published checksum for this release — refusing to install unverified"
  fi
  expected="$(printf '%s' "$sums" | awk '{print $1}')"
  actual="$(sha256_of "$file")"
  if [ -z "$actual" ]; then
    die "no sha256 tool found (install coreutils) — refusing to install unverified"
  fi
  [ "$expected" = "$actual" ] || die "checksum mismatch — refusing to install (expected $expected, got $actual)"
  ok "checksum verified"
}

install_binary() {
  local version="$1" arch="$2" bindir="$3"
  local url="https://github.com/$REPO/releases/download/v${version}/${BIN}-linux-${arch}"
  local tmp
  tmp="$(mktemp)"
  step "Downloading $BIN v$version ($arch)"
  curl -fSL --progress-bar -o "$tmp" "$url" || die "download failed: $url"
  verify_checksum "$tmp" "$url"
  chmod +x "$tmp"

  mkdir -p "$bindir" 2>/dev/null || true
  if [ -w "$bindir" ]; then
    mv "$tmp" "$bindir/$BIN"
  else
    as_root mv "$tmp" "$bindir/$BIN"
    as_root chmod +x "$bindir/$BIN"
  fi
  ok "installed to $bindir/$BIN"

  case ":$PATH:" in
    *":$bindir:"*) ;;
    *) warn "$bindir is not on your PATH — add it with:  export PATH=\"$bindir:\$PATH\"" ;;
  esac
}

backends_present() {
  command -v age >/dev/null 2>&1 &&
    { command -v 7zz >/dev/null 2>&1 || command -v 7z >/dev/null 2>&1 || command -v 7za >/dev/null 2>&1; }
}

main() {
  command -v curl >/dev/null 2>&1 || die "curl is required"

  local arch pm latest current bindir
  arch="$(detect_arch)"
  latest="$(latest_version)"
  current="$(installed_version)"

  if [ -z "$latest" ]; then
    die "could not determine the latest release (is the network up?)"
  fi

  # Nothing to do: skip the package manager entirely so a re-run is a fast no-op.
  if [ "$current" = "$latest" ] && backends_present; then
    ok "$BIN is already up to date (v$current) and ready to use"
    return 0
  fi

  pm="$(detect_pm)"
  install_backends "$pm"

  bindir="$(choose_bindir)"
  if [ "$current" = "$latest" ]; then
    ok "$BIN v$current is already installed"
  else
    [ -n "$current" ] && step "Upgrading $BIN: v$current -> v$latest"
    install_binary "$latest" "$arch" "$bindir"
  fi

  printf '\n'
  ok "Done. Run '$BIN' to start."
}

# Run the installer only when executed (directly or via `curl ... | bash`), not
# when sourced — the test suite sources this file to exercise single functions
# without performing an install.
if ! (return 0 2>/dev/null); then
  main "$@"
fi
