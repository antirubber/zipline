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
    rows: Vec<Row>,
    state: ListState,
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
            rows: Vec::new(),
            state: ListState::default(),
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

        self.rows = rows;
        let sel = if self.rows.is_empty() { None } else { Some(0) };
        self.state.select(sel);
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
