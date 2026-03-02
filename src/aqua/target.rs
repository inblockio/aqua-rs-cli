// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

//! `--target <ID>` helper: push a Tree into a running daemon's forest via Unix socket.

use aqua_rs_sdk::schema::tree::Tree;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

extern crate serde_json_path_to_error as serde_json;

/// Connect to the daemon identified by `id`, send the tree as an `ingest` command,
/// and return the daemon's response.
pub async fn push_tree_to_daemon(id: u64, tree: &Tree) -> Result<String, String> {
    let socket_path = format!("/tmp/aqua-forest-{}.sock", id);

    let stream = UnixStream::connect(&socket_path)
        .await
        .map_err(|e| format!("Failed to connect to daemon {} ({}): {}", id, socket_path, e))?;

    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);

    // Serialize tree to single-line JSON (no newlines)
    let json = serde_json::to_string(tree)
        .map_err(|e| format!("Failed to serialize tree: {}", e))?;

    // Send: ingest <json>\n
    let cmd = format!("ingest {}\n", json);
    writer
        .write_all(cmd.as_bytes())
        .await
        .map_err(|e| format!("Failed to send to daemon: {}", e))?;
    writer
        .flush()
        .await
        .map_err(|e| format!("Failed to flush: {}", e))?;

    // Read response lines until \0\n sentinel
    let mut response = String::new();
    loop {
        let mut line = String::new();
        let n = buf_reader
            .read_line(&mut line)
            .await
            .map_err(|e| format!("Failed to read from daemon: {}", e))?;
        if n == 0 {
            break; // EOF
        }
        if line == "\0\n" {
            break; // sentinel
        }
        response.push_str(&line);
    }

    Ok(response.trim_end().to_string())
}
