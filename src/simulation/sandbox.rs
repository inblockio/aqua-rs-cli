// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

//! Temporary sandbox directory for simulation round-trips.
//!
//! Creates an isolated temp dir, writes `.aqua.json` files into it, then
//! provides the paths back for the `--forest` disk round-trip test.
//! Auto-cleans on drop unless `keep()` is called (e.g. on failure).

use std::path::PathBuf;
use tempfile::TempDir;

pub struct Sandbox {
    dir: Option<TempDir>,
}

impl Sandbox {
    pub fn new() -> std::io::Result<Self> {
        let dir = tempfile::Builder::new().prefix("aqua-sim-").tempdir()?;
        Ok(Self { dir: Some(dir) })
    }

    /// Write a tree as `{name}.aqua.json` in the sandbox.
    /// Returns the file path.
    pub fn write_tree(
        &self,
        name: &str,
        tree: &aqua_rs_sdk::schema::tree::Tree,
    ) -> std::io::Result<PathBuf> {
        let dir = self.dir.as_ref().expect("sandbox already consumed");
        let path = dir.path().join(format!("{}.aqua.json", name));
        let json = serde_json::to_string_pretty(tree)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        std::fs::write(&path, json)?;
        Ok(path)
    }

    /// Path to the sandbox directory.
    pub fn path(&self) -> &std::path::Path {
        self.dir.as_ref().expect("sandbox already consumed").path()
    }

    /// Prevent automatic cleanup (call on failure so the dir is inspectable).
    pub fn keep(mut self) -> PathBuf {
        let dir = self.dir.take().expect("sandbox already consumed");
        let path = dir.path().to_path_buf();
        let _ = dir.keep(); // prevents Drop cleanup
        path
    }
}
