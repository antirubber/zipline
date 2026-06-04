//! A small keyboard file browser. Non-technical users pick a file or folder by
//! arrowing through a list instead of typing a path.

use std::fs;
use std::path::{Path, PathBuf};

use ratatui::widgets::ListState;

/// What a row in the list represents.
#[derive(Clone)]
pub enum Row {
    /// "Lock this whole folder" — only shown when picking something to encrypt.
    UseCurrent,
    /// Go up to the parent directory.
    Up,
    Dir(PathBuf),
    File(PathBuf),
}

/// The result of pressing Enter on the highlighted row.
pub enum Action {
    /// Move into a new directory (the browser handled it).
    Browsed,
    /// The user chose this path as their file/folder/archive.
    Chosen(PathBuf),
    /// Nothing actionable (e.g. an empty directory).
    None,
}

pub struct Browser {
    cwd: PathBuf,
    /// Everything in `cwd` that passes the extension filter, unfiltered by the
    /// query. `rows` is this list narrowed by the current fuzzy query.
    all_rows: Vec<Row>,
    rows: Vec<Row>,
    state: ListState,
    /// A live filter / path the user is typing. Empty means "show everything".
    query: String,
    /// When set, only directories and files with these extensions are listed
    /// (used when picking an archive to open). `None` lists everything and
    /// offers "lock this whole folder".
    only: Option<&'static [&'static str]>,
}

impl Browser {
    /// `only = None` for picking something to encrypt; `Some(exts)` to pick an
    /// existing archive of the given extensions.
    pub fn new(start: PathBuf, only: Option<&'static [&'static str]>) -> Self {
        let mut b = Browser {
            cwd: start,
            all_rows: Vec::new(),
            rows: Vec::new(),
            state: ListState::default(),
            query: String::new(),
            only,
        };
        b.reload();
        b
    }

    pub fn cwd(&self) -> &Path {
        &self.cwd
    }

    pub fn rows(&self) -> &[Row] {
        &self.rows
    }

    pub fn state(&mut self) -> &mut ListState {
        &mut self.state
    }

    /// Whether this browser is selecting an archive to open (vs. a target to
    /// encrypt).
    pub fn picking_archive(&self) -> bool {
        self.only.is_some()
    }

    pub fn label(&self, row: &Row) -> String {
        match row {
            Row::UseCurrent => {
                let name = self
                    .cwd
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| "/".to_string());
                format!("Lock this whole folder  ({name})")
            }
            Row::Up => "..  (up one level)".to_string(),
            Row::Dir(p) => format!("{}/", file_name(p)),
            Row::File(p) => file_name(p),
        }
    }

    pub fn move_up(&mut self) {
        let i = self.state.selected().unwrap_or(0);
        let next = if i == 0 {
            self.rows.len().saturating_sub(1)
        } else {
            i - 1
        };
        self.state.select(Some(next));
    }

    pub fn move_down(&mut self) {
        let i = self.state.selected().unwrap_or(0);
        let next = if i + 1 >= self.rows.len() { 0 } else { i + 1 };
        self.state.select(Some(next));
    }

    pub fn go_up(&mut self) {
        if let Some(parent) = self.cwd.parent() {
            self.cwd = parent.to_path_buf();
            self.reload();
        }
    }

    /// Act on the highlighted row.
    pub fn activate(&mut self) -> Action {
        let Some(row) = self
            .state
            .selected()
            .and_then(|i| self.rows.get(i).cloned())
        else {
            return Action::None;
        };
        match row {
            Row::UseCurrent => Action::Chosen(self.cwd.clone()),
            Row::Up => {
                self.go_up();
                Action::Browsed
            }
            Row::Dir(p) => {
                if self.picking_archive() {
                    self.cwd = p;
                    self.reload();
                    Action::Browsed
                } else {
                    // Encrypting: open the folder to browse inside it. Choosing
                    // it is done via the "Lock this whole folder" row.
                    self.cwd = p;
                    self.reload();
                    Action::Browsed
                }
            }
            Row::File(p) => Action::Chosen(p),
        }
    }

    fn reload(&mut self) {
        let mut dirs: Vec<PathBuf> = Vec::new();
        let mut files: Vec<PathBuf> = Vec::new();
        if let Ok(read) = fs::read_dir(&self.cwd) {
            for entry in read.flatten() {
                let path = entry.path();
                let name = file_name(&path);
                if name.starts_with('.') {
                    continue; // hide dotfiles to keep the list approachable
                }
                let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
                if is_dir {
                    dirs.push(path);
                } else if self.file_allowed(&path) {
                    files.push(path);
                }
            }
        }
        dirs.sort_by_key(|p| file_name(p).to_lowercase());
        files.sort_by_key(|p| file_name(p).to_lowercase());

        let mut rows = Vec::new();
        if self.only.is_none() {
            rows.push(Row::UseCurrent);
        }
        if self.cwd.parent().is_some() {
            rows.push(Row::Up);
        }
        rows.extend(dirs.into_iter().map(Row::Dir));
        rows.extend(files.into_iter().map(Row::File));

        self.all_rows = rows;
        self.apply_filter();
    }

    /// Narrow `all_rows` to `rows` by the current query. An empty or path-like
    /// query shows everything; a plain query fuzzy-filters the file/folder rows
    /// by name, best matches first, and hides the control rows.
    fn apply_filter(&mut self) {
        if self.query.is_empty() || self.is_path_query() {
            self.rows = self.all_rows.clone();
        } else {
            let mut scored: Vec<(i32, &Row)> = self
                .all_rows
                .iter()
                .filter_map(|row| match row {
                    Row::Dir(p) | Row::File(p) => {
                        fuzzy_score(&self.query, &file_name(p)).map(|s| (s, row))
                    }
                    _ => None,
                })
                .collect();
            scored.sort_by(|a, b| {
                b.0.cmp(&a.0)
                    .then_with(|| row_name(a.1).cmp(&row_name(b.1)))
            });
            self.rows = scored.into_iter().map(|(_, r)| r.clone()).collect();
        }
        let sel = if self.rows.is_empty() { None } else { Some(0) };
        self.state.select(sel);
    }

    pub fn query(&self) -> &str {
        &self.query
    }

    /// A query naming a path (rather than a fuzzy filter): contains a separator
    /// or starts at home/root.
    pub fn is_path_query(&self) -> bool {
        self.query.contains('/') || self.query.starts_with('~')
    }

    pub fn push_query(&mut self, c: char) {
        self.query.push(c);
        self.apply_filter();
    }

    pub fn pop_query(&mut self) {
        self.query.pop();
        self.apply_filter();
    }

    pub fn clear_query(&mut self) {
        self.query.clear();
        self.apply_filter();
    }

    /// Interpret a path-like query (see `is_path_query`) as a destination.
    /// A directory is entered (clearing the query); a file that passes the
    /// extension filter is chosen. Anything missing or disallowed yields
    /// `Action::None` so the caller can explain why.
    pub fn resolve_query(&mut self) -> Action {
        let target = self.expand(&self.query);
        if target.is_dir() {
            self.cwd = target;
            self.query.clear();
            self.reload();
            Action::Browsed
        } else if target.is_file() && self.file_allowed(&target) {
            Action::Chosen(target)
        } else {
            Action::None
        }
    }

    /// Resolve a typed path: expand a leading `~`, and treat relative paths as
    /// relative to the current directory.
    fn expand(&self, raw: &str) -> PathBuf {
        let trimmed = raw.trim();
        if let Some(rest) = trimmed.strip_prefix('~') {
            if let Some(home) = std::env::var_os("HOME") {
                let rest = rest.strip_prefix('/').unwrap_or(rest);
                return PathBuf::from(home).join(rest);
            }
        }
        let p = PathBuf::from(trimmed);
        if p.is_absolute() {
            p
        } else {
            self.cwd.join(p)
        }
    }

    fn file_allowed(&self, path: &Path) -> bool {
        match self.only {
            None => true,
            Some(exts) => path
                .extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase())
                .map(|e| exts.contains(&e.as_str()))
                .unwrap_or(false),
        }
    }
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.to_string_lossy().into_owned())
}

fn row_name(row: &Row) -> String {
    match row {
        Row::Dir(p) | Row::File(p) => file_name(p),
        _ => String::new(),
    }
}

/// Score `haystack` against `needle` as a case-insensitive subsequence: every
/// character of `needle` must appear in order. Consecutive matches and matches
/// at a word boundary (start, or after a separator) score higher, so `rep`
/// ranks `report` above `xrxexp`. `None` means no match.
fn fuzzy_score(needle: &str, haystack: &str) -> Option<i32> {
    let needle = needle.to_lowercase();
    if needle.is_empty() {
        return Some(0);
    }
    let hay: Vec<char> = haystack.to_lowercase().chars().collect();
    let mut score = 0;
    let mut hi = 0;
    let mut prev_matched = false;
    for nc in needle.chars() {
        loop {
            let hc = *hay.get(hi)?;
            hi += 1;
            if hc == nc {
                score += 1;
                if prev_matched {
                    score += 3; // reward runs
                }
                // `hi` was just incremented, so the matched char is `hay[hi-1]`
                // and `hay[hi-2]` is the one before it. A match at index 0
                // (hi == 1) or right after a separator starts a new "word".
                let at_boundary =
                    hi == 1 || matches!(hay.get(hi - 2), Some('.' | '-' | '_' | ' ' | '/'));
                if at_boundary {
                    score += 2;
                }
                prev_matched = true;
                break;
            }
            prev_matched = false;
        }
    }
    Some(score)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("subfolder")).unwrap();
        fs::write(dir.path().join("readme.txt"), b"x").unwrap();
        fs::write(dir.path().join("backup.7z"), b"x").unwrap();
        fs::write(dir.path().join("secret.age"), b"x").unwrap();
        fs::write(dir.path().join(".hidden"), b"x").unwrap();
        dir
    }

    fn labels(b: &Browser) -> Vec<String> {
        b.rows().iter().map(|r| b.label(r)).collect()
    }

    #[test]
    fn encrypt_mode_offers_use_current_and_hides_dotfiles() {
        let dir = fixture();
        let b = Browser::new(dir.path().to_path_buf(), None);
        let labels = labels(&b);
        assert!(matches!(b.rows()[0], Row::UseCurrent));
        assert!(labels.iter().any(|l| l.contains("subfolder")));
        assert!(labels.iter().any(|l| l.contains("readme.txt")));
        assert!(
            !labels.iter().any(|l| l.contains(".hidden")),
            "dotfiles must be hidden"
        );
    }

    #[test]
    fn archive_mode_lists_only_archives_and_folders() {
        let dir = fixture();
        let b = Browser::new(dir.path().to_path_buf(), Some(&["age", "7z"]));
        let labels = labels(&b);
        assert!(!b.rows().iter().any(|r| matches!(r, Row::UseCurrent)));
        assert!(labels.iter().any(|l| l.contains("secret.age")));
        assert!(labels.iter().any(|l| l.contains("backup.7z")));
        assert!(labels.iter().any(|l| l.contains("subfolder")));
        assert!(
            !labels.iter().any(|l| l.contains("readme.txt")),
            "plain files are filtered out"
        );
    }

    #[test]
    fn choosing_use_current_returns_cwd() {
        let dir = fixture();
        let mut b = Browser::new(dir.path().to_path_buf(), None);
        b.state.select(Some(0)); // UseCurrent
        match b.activate() {
            Action::Chosen(p) => assert_eq!(p, dir.path()),
            _ => panic!("expected the current folder to be chosen"),
        }
    }

    #[test]
    fn opening_a_folder_descends_into_it() {
        let dir = fixture();
        let mut b = Browser::new(dir.path().to_path_buf(), None);
        let idx = b
            .rows()
            .iter()
            .position(|r| matches!(r, Row::Dir(_)))
            .unwrap();
        b.state.select(Some(idx));
        assert!(matches!(b.activate(), Action::Browsed));
        assert_eq!(b.cwd(), dir.path().join("subfolder"));
    }

    #[test]
    fn choosing_a_file_returns_it() {
        let dir = fixture();
        let mut b = Browser::new(dir.path().to_path_buf(), Some(&["age", "7z"]));
        let idx = b
            .rows()
            .iter()
            .position(|r| matches!(r, Row::File(p) if p.extension().unwrap() == "age"))
            .unwrap();
        b.state.select(Some(idx));
        match b.activate() {
            Action::Chosen(p) => assert_eq!(p, dir.path().join("secret.age")),
            _ => panic!("expected the archive file to be chosen"),
        }
    }

    #[test]
    fn typing_filters_to_fuzzy_matches() {
        let dir = fixture();
        let mut b = Browser::new(dir.path().to_path_buf(), None);
        for c in "readme".chars() {
            b.push_query(c);
        }
        let labels = labels(&b);
        assert!(labels.iter().any(|l| l.contains("readme.txt")));
        assert!(!labels.iter().any(|l| l.contains("backup.7z")));
        assert!(!labels.iter().any(|l| l.contains("subfolder")));
    }

    #[test]
    fn clearing_the_query_restores_the_full_list() {
        let dir = fixture();
        let mut b = Browser::new(dir.path().to_path_buf(), None);
        let full = b.rows().len();
        for c in "readme".chars() {
            b.push_query(c);
        }
        assert!(b.rows().len() < full);
        b.clear_query();
        assert_eq!(b.rows().len(), full);
        assert_eq!(b.query(), "");
    }

    #[test]
    fn path_query_descends_into_a_directory() {
        let dir = fixture();
        let mut b = Browser::new(dir.path().to_path_buf(), None);
        let target = dir.path().join("subfolder");
        for c in target.to_string_lossy().chars() {
            b.push_query(c);
        }
        assert!(b.is_path_query());
        assert!(matches!(b.resolve_query(), Action::Browsed));
        assert_eq!(b.cwd(), target);
        assert_eq!(b.query(), "", "query clears after a jump");
    }

    #[test]
    fn path_query_chooses_a_matching_file() {
        let dir = fixture();
        let mut b = Browser::new(dir.path().to_path_buf(), Some(&["age", "7z"]));
        let target = dir.path().join("secret.age");
        for c in target.to_string_lossy().chars() {
            b.push_query(c);
        }
        match b.resolve_query() {
            Action::Chosen(p) => assert_eq!(p, target),
            other => panic!(
                "expected the .age file to be chosen, got {:?}",
                matches!(other, Action::None)
            ),
        }
    }

    #[test]
    fn path_query_to_a_filtered_out_file_is_rejected() {
        let dir = fixture();
        // Archive mode: a plain .txt is not an allowed pick.
        let mut b = Browser::new(dir.path().to_path_buf(), Some(&["age", "7z"]));
        let target = dir.path().join("readme.txt");
        for c in target.to_string_lossy().chars() {
            b.push_query(c);
        }
        assert!(matches!(b.resolve_query(), Action::None));
    }

    #[test]
    fn path_query_to_a_missing_path_is_none() {
        let dir = fixture();
        let mut b = Browser::new(dir.path().to_path_buf(), None);
        let target = dir.path().join("nope/does-not-exist");
        for c in target.to_string_lossy().chars() {
            b.push_query(c);
        }
        assert!(matches!(b.resolve_query(), Action::None));
    }

    #[test]
    fn navigation_wraps_around() {
        let dir = fixture();
        let mut b = Browser::new(dir.path().to_path_buf(), None);
        let n = b.rows().len();
        b.state.select(Some(0));
        b.move_up();
        assert_eq!(
            b.state.selected(),
            Some(n - 1),
            "up from the top wraps to the bottom"
        );
        b.move_down();
        assert_eq!(
            b.state.selected(),
            Some(0),
            "down from the bottom wraps to the top"
        );
    }
}
