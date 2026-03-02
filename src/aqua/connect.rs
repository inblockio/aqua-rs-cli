// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

//! `--connect <ID>` client REPL: connect to a running daemon via Unix socket.

use std::io::{self, Write};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Connect to a running forest daemon and provide an interactive REPL.
pub async fn cli_connect_forest(id: u64) {
    let socket_path = format!("/tmp/aqua-forest-{}.sock", id);

    let stream = match UnixStream::connect(&socket_path).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "Failed to connect to daemon {} ({}): {}",
                id, socket_path, e
            );
            std::process::exit(1);
        }
    };

    println!("Connected to forest daemon (id: {})", id);
    println!("Type 'help' for commands, 'quit' to disconnect.");
    println!();

    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);
    let stdin = io::stdin();

    loop {
        // Print prompt
        print!("forest> ");
        io::stdout().flush().ok();

        // Read user input
        let mut input = String::new();
        match stdin.read_line(&mut input) {
            Ok(0) => break, // EOF (Ctrl+D)
            Ok(_) => {}
            Err(e) => {
                eprintln!("Error reading input: {}", e);
                break;
            }
        }

        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Client-side quit shortcut
        if trimmed == "quit" || trimmed == "exit" {
            println!("Disconnected.");
            break;
        }

        // Send command to daemon
        let cmd = format!("{}\n", trimmed);
        if let Err(e) = writer.write_all(cmd.as_bytes()).await {
            eprintln!("Error sending command: {}", e);
            break;
        }
        if let Err(e) = writer.flush().await {
            eprintln!("Error flushing: {}", e);
            break;
        }

        // Read response until \0\n sentinel
        loop {
            let mut line = String::new();
            match buf_reader.read_line(&mut line).await {
                Ok(0) => {
                    // Server closed connection
                    println!("Daemon disconnected.");
                    return;
                }
                Ok(_) => {
                    if line == "\0\n" {
                        break; // end of response
                    }
                    print!("{}", line);
                }
                Err(e) => {
                    eprintln!("Error reading response: {}", e);
                    return;
                }
            }
        }
    }
}
