// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

//! Ephemeral forest CLI command + persistent daemon mode.
//!
//! `cli_ephemeral_forest` ingests one or more `.aqua.json` files into a
//! daemon `Forest` backed by `NullStorage`, resolving cross-tree dependencies
//! (attestation→claim, template hierarchies) via a pre-built revision index.
//!
//! When `--daemon` is specified, the forest stays alive with an idle timeout,
//! a REPL on stdin, and a Unix socket for IPC from `--connect` / `--target`.

use std::collections::HashMap;
use std::fs;
use std::io::Write as IoWrite;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aqua_rs_sdk::daemon::{topological_order, Forest, NullStorage};
use aqua_rs_sdk::primitives::RevisionLink;
use aqua_rs_sdk::schema::tree::Tree;
use aqua_rs_sdk::schema::{AnyRevision, AquaTreeWrapper};
use aqua_rs_sdk::{Aquafier, DefaultTrustStore};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::Mutex;

use axum::{
    extract::{Path as AxumPath, State as AxumState},
    http::StatusCode,
    response::Json as AxumJson,
    routing::get,
    Router,
};
use tower_http::cors::{Any, CorsLayer};

use crate::models::CliArgs;

extern crate serde_json_path_to_error as serde_json;

type SharedState = Arc<Mutex<DaemonState>>;

// ─── Daemon state ────────────────────────────────────────────────────────────

#[allow(dead_code)]
struct DaemonState {
    forest: Forest,
    aquafier: Aquafier,
    /// Reverse index: revision_hash → (filename, Tree) for link resolution
    rev_to_tree: HashMap<String, (String, Tree)>,
    last_accessed: Instant,
    idle_timeout: Duration,
    id: u64,
    verbose: bool,
}

impl DaemonState {
    fn touch(&mut self) {
        self.last_accessed = Instant::now();
    }

    fn is_expired(&self) -> bool {
        self.last_accessed.elapsed() >= self.idle_timeout
    }

    fn remaining(&self) -> Duration {
        self.idle_timeout
            .checked_sub(self.last_accessed.elapsed())
            .unwrap_or(Duration::ZERO)
    }
}

// ─── Shared ingestion logic ──────────────────────────────────────────────────

/// Ingest a single tree into the forest: verify → insert nodes → handle L3 deps.
/// Returns (success, status_message).
async fn ingest_tree_into_forest(
    forest: &mut Forest,
    aquafier: &Aquafier,
    rev_to_tree: &HashMap<String, (String, Tree)>,
    name: &str,
    tree: &Tree,
) -> (bool, String) {
    // Extract link_verification_hashes from anchor revisions
    let mut link_hashes: Vec<String> = Vec::new();
    for revision in tree.revisions.values() {
        if let AnyRevision::Anchor(anchor) = revision {
            for lh in anchor.link_verification_hashes() {
                let lh_str = lh.to_string();
                if lh_str != RevisionLink::zero().to_string() {
                    link_hashes.push(lh_str);
                }
            }
        }
    }

    // Resolve links to containing trees
    let mut linked_wrappers: Vec<AquaTreeWrapper> = Vec::new();
    for lh in &link_hashes {
        if let Some((_, linked_tree)) = rev_to_tree.get(lh) {
            if !std::ptr::eq(linked_tree, tree) {
                linked_wrappers.push(AquaTreeWrapper::new(linked_tree.clone(), None, None));
            }
        }
    }

    let wrapper = AquaTreeWrapper::new(tree.clone(), None, None);
    let verify_result = if linked_wrappers.is_empty() {
        aquafier.verify_and_build_state(wrapper, vec![]).await
    } else {
        aquafier
            .verify_and_build_state_with_linked_trees(wrapper, linked_wrappers, vec![])
            .await
    };

    match verify_result {
        Ok((vr, state_nodes)) => {
            let node_count = state_nodes.len();
            let status = if vr.is_valid {
                format!("OK  ({} node(s))", node_count)
            } else {
                format!("WARN ({}, {} node(s))", vr.status, node_count)
            };

            let ordered = topological_order(state_nodes);
            for node in ordered {
                let node_links = node.link_verification_hashes.clone();
                let rev_hash_str = node.revision_hash.clone();
                forest.insert_node(node);

                if let Some(links) = node_links {
                    for lh_str in &links {
                        if let Ok(lh) = lh_str.parse::<RevisionLink>() {
                            if lh == RevisionLink::zero() {
                                continue;
                            }
                            if !forest.load_builtin_template(&lh) {
                                if forest.get_node(&lh).is_none() {
                                    if let Ok(owner) = rev_hash_str.parse::<RevisionLink>() {
                                        forest.register_l3_pending(owner, lh);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            (vr.is_valid, format!("[{}] {}", name, status))
        }
        Err(e) => (false, format!("[{}] FAILED — verify error: {}", name, e)),
    }
}

// ─── Main entry point ────────────────────────────────────────────────────────

pub async fn cli_ephemeral_forest(args: CliArgs, aquafier: &Aquafier, files: Vec<PathBuf>) {
    // Build a local Aquafier with trust store if --trust was provided
    let aquafier = if let Some((ref did, level)) = args.trust {
        let mut levels = HashMap::new();
        levels.insert(did.clone(), level);
        println!("Trust store: {} at level {}", did, level);
        aquafier.with_trust_store(Arc::new(DefaultTrustStore::new(levels)))
    } else {
        aquafier.with_trust_store(Arc::new(DefaultTrustStore::new(HashMap::new())))
    };

    println!("Building ephemeral forest from {} file(s)...", files.len());
    println!();

    // ── Phase 1: Load all trees and build rev_hash → (name, tree) map ────
    let mut trees: Vec<(String, Tree)> = Vec::new();
    let mut rev_to_tree: HashMap<String, (String, Tree)> = HashMap::new();
    let mut load_failed = 0usize;

    for file in &files {
        let name = file
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| file.to_string_lossy().into_owned());

        let file_content = match fs::read_to_string(file) {
            Ok(s) => s,
            Err(e) => {
                println!("  [{}] FAILED — read error: {}", name, e);
                load_failed += 1;
                continue;
            }
        };

        let tree: Tree = match serde_json::from_str(&file_content) {
            Ok(t) => t,
            Err(e) => {
                println!("  [{}] FAILED — parse error: {}", name, e);
                load_failed += 1;
                continue;
            }
        };

        for rev_hash in tree.revisions.keys() {
            rev_to_tree.insert(rev_hash.to_string(), (name.clone(), tree.clone()));
        }
        trees.push((name, tree));
    }

    // ── Phase 2: Verify with pre-resolved linked trees, insert into Forest ──
    let mut forest = Forest::new("cli", "cli:session", Box::new(NullStorage));
    let mut results: Vec<(String, bool, String)> = Vec::new();

    for (name, tree) in &trees {
        let (passed, status) =
            ingest_tree_into_forest(&mut forest, &aquafier, &rev_to_tree, name, tree).await;
        results.push((name.clone(), passed, status));
    }

    // ── Phase 3: Post-insert L3 resolution ──────────────────────────────
    let pending_keys: Vec<RevisionLink> = forest.pending_dependencies().keys().cloned().collect();
    for awaited in &pending_keys {
        if forest.get_node(awaited).is_some() {
            forest.resolve_l3_pending(awaited);
        }
    }

    // ── Phase 4: Report ─────────────────────────────────────────────────
    let all_failed = print_forest_report(&forest, &results, load_failed);
    if all_failed && args.daemon.is_none() {
        std::process::exit(1);
    }

    if args.verbose {
        println!();
        println!("Node details:");
        let genesis_hashes = forest.genesis_hashes();
        for gh in &genesis_hashes {
            print_forest_subtree(&forest, gh, 0);
        }
    }

    if let Some(output_path) = &args.output {
        let report = build_forest_report(&forest);
        match fs::write(output_path, report) {
            Ok(_) => println!("Report written to {:?}", output_path),
            Err(e) => eprintln!("Failed to write report: {}", e),
        }
    }

    // ── Daemon mode ─────────────────────────────────────────────────────
    if let Some(timeout_secs) = args.daemon {
        let id = std::process::id() as u64;
        let state = DaemonState {
            forest,
            aquafier,
            rev_to_tree,
            last_accessed: Instant::now(),
            idle_timeout: Duration::from_secs(timeout_secs),
            id,
            verbose: args.verbose,
        };
        run_daemon(state, args.listen).await;
    }
}

// ─── Report printing ─────────────────────────────────────────────────────────

/// Print forest summary. Returns `true` if all files failed (caller decides whether to exit).
fn print_forest_report(forest: &Forest, results: &[(String, bool, String)], load_failed: usize) -> bool {
    println!("Per-file verification:");
    let mut pass_count = 0usize;
    let mut fail_count = 0usize;
    for (_, passed, status) in results {
        println!("  {}", status);
        if *passed {
            pass_count += 1;
        } else {
            fail_count += 1;
        }
    }
    println!();

    let summary = forest.summary();
    let genesis_hashes = forest.genesis_hashes();
    let tips = forest.tips();

    println!("Ephemeral Forest Summary");
    println!("========================");
    println!("  Session     : {}", summary.namespace_name);
    println!(
        "  Files       : {} ingested, {} failed",
        pass_count + fail_count,
        load_failed
    );
    println!("  Nodes       : {}", summary.node_count);
    println!("  Geneses     : {}", summary.genesis_count);
    println!("  Pending deps: {}", summary.pending_count);

    if !genesis_hashes.is_empty() {
        println!();
        println!("Genesis trees ({}):", genesis_hashes.len());
        for gh in &genesis_hashes {
            println!("  {}", gh);
        }
    }

    if !tips.is_empty() {
        println!();
        println!("Tip revisions ({}):", tips.len());
        for tip in &tips {
            println!("  {}", tip);
        }
    }

    let remaining_pending = forest.pending_dependencies();
    if !remaining_pending.is_empty() {
        println!();
        println!(
            "Unresolved cross-tree dependencies ({}):",
            remaining_pending.len()
        );
        for (awaited, owners) in remaining_pending {
            println!("  {} (awaited by {} node(s))", awaited, owners.len());
        }
    }

    println!();
    if fail_count == 0 && load_failed == 0 && summary.node_count > 0 {
        println!("Forest built successfully.");
        false
    } else if load_failed + fail_count > 0 && pass_count == 0 {
        eprintln!("All files failed to ingest.");
        true
    } else if fail_count + load_failed > 0 {
        println!("Forest built with {} error(s).", fail_count + load_failed);
        false
    } else {
        false
    }
}

// ─── Daemon event loop ───────────────────────────────────────────────────────

async fn run_daemon(state: DaemonState, listen_port: Option<u16>) {
    let id = state.id;
    let timeout_secs = state.idle_timeout.as_secs();
    let socket_path = format!("/tmp/aqua-forest-{}.sock", id);

    // Clean up stale socket file if it exists
    let _ = std::fs::remove_file(&socket_path);

    let listener = match UnixListener::bind(&socket_path) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to create Unix socket {}: {}", socket_path, e);
            return;
        }
    };

    println!();
    println!(
        "Forest daemon started (id: ephemeral:{}, timeout: {}s)",
        id, timeout_secs
    );
    println!("Socket: {}", socket_path);

    let shared = Arc::new(Mutex::new(state));

    let http_handle: Option<tokio::task::JoinHandle<()>> = if let Some(port) = listen_port {
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);
        let app = Router::new()
            .route("/health", get(api_health))
            .route("/trees", get(api_trees))
            .route("/trees/{hash}", get(api_tree_by_hash))
            .layer(cors)
            .with_state(shared.clone());
        println!("HTTP API listening on http://127.0.0.1:{}", port);
        Some(tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(std::net::SocketAddr::from(([127, 0, 0, 1], port)))
                .await
                .expect("Failed to bind HTTP listener");
            axum::serve(listener, app).await.expect("HTTP server failed");
        }))
    } else {
        None
    };

    // Stdin reader task
    let shared_stdin = shared.clone();
    let stdin_task = tokio::spawn(async move {
        let stdin = tokio::io::stdin();
        let mut reader = BufReader::new(stdin);
        loop {
            // Print prompt
            eprint!("forest> ");
            let _ = std::io::stderr().flush();

            let mut line = String::new();
            match reader.read_line(&mut line).await {
                Ok(0) => {
                    // EOF (Ctrl+D)
                    return "eof".to_string();
                }
                Ok(_) => {}
                Err(_) => {
                    return "error".to_string();
                }
            }

            let trimmed = line.trim().to_string();
            if trimmed.is_empty() {
                continue;
            }

            if trimmed == "quit" || trimmed == "exit" {
                return "quit".to_string();
            }

            let mut state = shared_stdin.lock().await;
            state.touch();
            let response = execute_command(&mut state, &trimmed).await;
            drop(state);
            println!("{}", response);
        }
    });

    // Socket accept task
    let shared_socket = shared.clone();
    let socket_path_cleanup = socket_path.clone();
    let socket_task = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let shared_conn = shared_socket.clone();
                    tokio::spawn(handle_socket_client(stream, shared_conn));
                }
                Err(e) => {
                    eprintln!("Socket accept error: {}", e);
                }
            }
        }
    });

    // Idle timeout check task
    let shared_idle = shared.clone();
    let idle_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let state = shared_idle.lock().await;
            if state.is_expired() {
                return;
            }
        }
    });

    // Wait for any termination reason
    tokio::select! {
        result = stdin_task => {
            match result {
                Ok(reason) => {
                    if reason == "quit" {
                        println!("Shutting down daemon...");
                    } else if reason == "eof" {
                        println!("\nShutting down daemon (EOF)...");
                    }
                }
                Err(_) => {}
            }
        }
        _ = idle_task => {
            println!("\nIdle timeout reached. Shutting down daemon...");
        }
        _ = tokio::signal::ctrl_c() => {
            println!("\nShutting down daemon (Ctrl+C)...");
        }
    }

    // Cleanup
    socket_task.abort();
    if let Some(h) = http_handle {
        h.abort();
    }
    let _ = std::fs::remove_file(&socket_path_cleanup);
    println!("Socket removed. Daemon stopped.");
}

// ─── Socket client handler ───────────────────────────────────────────────────

async fn handle_socket_client(
    stream: tokio::net::UnixStream,
    shared: Arc<Mutex<DaemonState>>,
) {
    let (reader, mut writer) = stream.into_split();
    let mut buf_reader = BufReader::new(reader);

    loop {
        let mut line = String::new();
        match buf_reader.read_line(&mut line).await {
            Ok(0) => break, // client disconnected
            Ok(_) => {}
            Err(_) => break,
        }

        let trimmed = line.trim().to_string();
        if trimmed.is_empty() {
            // Send empty response with sentinel
            let _ = writer.write_all(b"\0\n").await;
            let _ = writer.flush().await;
            continue;
        }

        if trimmed == "quit" || trimmed == "exit" {
            let _ = writer.write_all(b"Disconnected.\n\0\n").await;
            let _ = writer.flush().await;
            break;
        }

        let mut state = shared.lock().await;
        state.touch();
        let response = execute_command(&mut state, &trimmed).await;
        drop(state);

        // Send response + sentinel
        let _ = writer
            .write_all(format!("{}\n\0\n", response).as_bytes())
            .await;
        let _ = writer.flush().await;
    }
}

// ─── Command dispatcher ─────────────────────────────────────────────────────

async fn execute_command(state: &mut DaemonState, input: &str) -> String {
    let parts: Vec<&str> = input.splitn(2, ' ').collect();
    let cmd = parts[0].to_lowercase();
    let arg = parts.get(1).map(|s| s.trim()).unwrap_or("");

    match cmd.as_str() {
        "help" => cmd_help(),
        "status" => cmd_status(state),
        "geneses" => cmd_geneses(state),
        "tips" => cmd_tips(state),
        "pending" => cmd_pending(state),
        "count" => cmd_count(state),
        "inspect" => cmd_inspect(state, arg),
        "branches" => cmd_branches(state, arg),
        "tree" => cmd_tree(state, arg),
        "add" => cmd_add(state, arg).await,
        "evict" => cmd_evict(state, arg),
        "remove" => cmd_remove(state, arg),
        "ingest" => cmd_ingest(state, arg).await,
        _ => format!("Unknown command: '{}'. Type 'help' for available commands.", cmd),
    }
}

// ─── Hash prefix resolution ─────────────────────────────────────────────────

/// Resolve a hash argument (full or prefix, minimum 8 hex chars after 0x) to an exact RevisionLink.
fn resolve_hash_prefix(state: &DaemonState, input: &str) -> Result<RevisionLink, String> {
    if input.is_empty() {
        return Err("Missing hash argument.".to_string());
    }

    // Try exact parse first (only treat as exact match for full-length hashes)
    if let Ok(link) = input.parse::<RevisionLink>() {
        if state.forest.get_node(&link).is_some() {
            return Ok(link);
        }
        // Full-length hash (0x + 64 hex chars) that wasn't found → definitive miss
        let hex_part = input.strip_prefix("0x").unwrap_or(input);
        if hex_part.len() >= 64 {
            return Err(format!("Node not found: {}", input));
        }
        // Short hex that parsed as valid but isn't in forest → fall through to prefix matching
    }

    // Prefix matching: must start with 0x and have at least 8 hex chars
    let prefix = if input.starts_with("0x") {
        &input[2..]
    } else {
        input
    };

    if prefix.len() < 8 {
        return Err("Hash prefix too short (minimum 8 hex chars after 0x).".to_string());
    }

    let full_prefix = if input.starts_with("0x") {
        input.to_string()
    } else {
        format!("0x{}", prefix)
    };

    // Scan all genesis hashes and walk subtrees to find matches
    let mut matches: Vec<RevisionLink> = Vec::new();
    collect_all_hashes(&state.forest, &mut matches);

    let matched: Vec<RevisionLink> = matches
        .into_iter()
        .filter(|h| h.to_string().starts_with(&full_prefix))
        .collect();

    match matched.len() {
        0 => Err(format!("No node matches prefix: {}", input)),
        1 => Ok(matched[0].clone()),
        n => {
            let mut msg = format!("Prefix '{}' matches {} nodes:\n", input, n);
            for m in &matched {
                msg.push_str(&format!("  {}\n", m));
            }
            msg.push_str("Please provide a longer prefix.");
            Err(msg)
        }
    }
}

/// Collect all node hashes in the forest by walking from genesis roots.
fn collect_all_hashes(forest: &Forest, out: &mut Vec<RevisionLink>) {
    for gh in forest.genesis_hashes() {
        collect_subtree_hashes(forest, &gh, out);
    }
}

fn collect_subtree_hashes(forest: &Forest, hash: &RevisionLink, out: &mut Vec<RevisionLink>) {
    if out.contains(hash) {
        return;
    }
    out.push(hash.clone());
    for child in forest.branches(hash) {
        if let Ok(child_link) = child.state.revision_hash.parse::<RevisionLink>() {
            collect_subtree_hashes(forest, &child_link, out);
        }
    }
}

// ─── Read commands ───────────────────────────────────────────────────────────

fn cmd_help() -> String {
    r#"Available commands:

  Read:
    status              Node/genesis/pending counts + idle time remaining
    geneses             List all genesis hashes
    tips                List all tip (leaf) hashes
    pending             List unresolved L3 dependencies
    inspect <hash>      Full state node details
    branches <hash>     Direct children of a node
    tree <hash>         Indented subtree from a node
    count               Live node count

  Write:
    add <file> [file..] Ingest new .aqua.json files into forest
    evict <hash>        Remove genesis + cascade entire subtree
    remove <hash>       Surgical remove single node (no cascade)

  Session:
    help                Show this help
    quit / exit         Disconnect (socket) or shutdown (stdin)

Hash arguments support prefix matching (minimum 8 hex chars after 0x)."#
        .to_string()
}

fn cmd_status(state: &DaemonState) -> String {
    let summary = state.forest.summary();
    let remaining = state.remaining();
    format!(
        "Daemon id   : ephemeral:{}\n\
         Nodes       : {}\n\
         Geneses     : {}\n\
         Pending deps: {}\n\
         Idle timeout: {}s remaining",
        state.id,
        summary.node_count,
        summary.genesis_count,
        summary.pending_count,
        remaining.as_secs()
    )
}

fn cmd_geneses(state: &DaemonState) -> String {
    let hashes = state.forest.genesis_hashes();
    if hashes.is_empty() {
        return "No genesis nodes.".to_string();
    }
    let mut out = format!("Genesis hashes ({}):\n", hashes.len());
    for h in &hashes {
        out.push_str(&format!("  {}\n", h));
    }
    out.trim_end().to_string()
}

fn cmd_tips(state: &DaemonState) -> String {
    let tips = state.forest.tips();
    if tips.is_empty() {
        return "No tip nodes.".to_string();
    }
    let mut out = format!("Tip hashes ({}):\n", tips.len());
    for t in &tips {
        out.push_str(&format!("  {}\n", t));
    }
    out.trim_end().to_string()
}

fn cmd_pending(state: &DaemonState) -> String {
    let pending = state.forest.pending_dependencies();
    if pending.is_empty() {
        return "No pending dependencies.".to_string();
    }
    let mut out = format!("Pending dependencies ({}):\n", pending.len());
    for (awaited, owners) in pending {
        out.push_str(&format!("  {} (awaited by {} node(s))\n", awaited, owners.len()));
    }
    out.trim_end().to_string()
}

fn cmd_count(state: &DaemonState) -> String {
    format!("{}", state.forest.node_count())
}

fn cmd_inspect(state: &DaemonState, arg: &str) -> String {
    match resolve_hash_prefix(state, arg) {
        Ok(hash) => {
            if let Some(sn) = state.forest.get_state_node(&hash) {
                let mut out = format!("Node: {}\n", sn.revision_hash);
                out.push_str(&format!(
                    "  Type        : {}\n",
                    sn.revision_type
                ));
                if let Some(ref parent) = sn.parent_hash {
                    out.push_str(&format!("  Parent      : {}\n", parent));
                }
                if let Some(ref signer) = sn.signer {
                    out.push_str(&format!("  Signer      : {}\n", signer));
                }
                if let Some(ref sig_type) = sn.signature_type {
                    out.push_str(&format!("  Sig type    : {}\n", sig_type));
                }
                if let Some(ref link_type) = sn.link_type {
                    out.push_str(&format!("  Link type   : {}\n", link_type));
                }
                if let Some(ref links) = sn.link_verification_hashes {
                    out.push_str(&format!("  Links       : {:?}\n", links));
                }
                if let Some(ts) = sn.local_timestamp {
                    out.push_str(&format!("  Timestamp   : {}\n", ts));
                }
                if sn.revoked {
                    out.push_str(&format!(
                        "  Revoked     : true (by: {})\n",
                        sn.revoked_by.as_deref().unwrap_or("unknown")
                    ));
                }
                if !sn.payloads.is_null() {
                    let payload_str = serde_json::to_string_pretty(&sn.payloads)
                        .unwrap_or_else(|_| format!("{:?}", sn.payloads));
                    out.push_str(&format!("  Payloads    : {}\n", payload_str));
                }
                if !sn.wasm_output.is_null() {
                    let wasm_str = serde_json::to_string_pretty(&sn.wasm_output)
                        .unwrap_or_else(|_| format!("{:?}", sn.wasm_output));
                    out.push_str(&format!("  WASM output : {}\n", wasm_str));
                }
                out.trim_end().to_string()
            } else {
                format!("Node not found: {}", hash)
            }
        }
        Err(e) => e,
    }
}

fn cmd_branches(state: &DaemonState, arg: &str) -> String {
    match resolve_hash_prefix(state, arg) {
        Ok(hash) => {
            let children = state.forest.branches(&hash);
            if children.is_empty() {
                return format!("No children for {}", hash);
            }
            let mut out = format!("Children of {} ({}):\n", truncate(&hash.to_string(), 14), children.len());
            for child in &children {
                let signer = child.state.signer.as_deref().unwrap_or("-");
                out.push_str(&format!(
                    "  {} type={} signer={}\n",
                    truncate(&child.state.revision_hash, 14),
                    truncate(&child.state.revision_type, 12),
                    signer
                ));
            }
            out.trim_end().to_string()
        }
        Err(e) => e,
    }
}

fn cmd_tree(state: &DaemonState, arg: &str) -> String {
    match resolve_hash_prefix(state, arg) {
        Ok(hash) => {
            let mut out = String::new();
            format_subtree(&state.forest, &hash, 0, &mut out);
            if out.is_empty() {
                format!("Node not found: {}", hash)
            } else {
                out.trim_end().to_string()
            }
        }
        Err(e) => e,
    }
}

fn format_subtree(forest: &Forest, hash: &RevisionLink, depth: usize, out: &mut String) {
    let indent = "  ".repeat(depth);
    if let Some(node) = forest.get_node(hash) {
        let signer = node.state.signer.as_deref().unwrap_or("-");
        let rev_type = truncate(&node.state.revision_type, 12);
        let hash_str = hash.to_string();
        out.push_str(&format!(
            "{}[{}] type={} signer={}\n",
            indent,
            truncate(&hash_str, 14),
            rev_type,
            signer
        ));
        for child in forest.branches(hash) {
            if let Ok(child_link) = child.state.revision_hash.parse::<RevisionLink>() {
                format_subtree(forest, &child_link, depth + 1, out);
            }
        }
    }
}

// ─── Write commands ──────────────────────────────────────────────────────────

async fn cmd_add(state: &mut DaemonState, arg: &str) -> String {
    if arg.is_empty() {
        return "Usage: add <file> [file...]".to_string();
    }

    let files: Vec<&str> = arg.split_whitespace().collect();
    let mut output = String::new();

    for file_path in &files {
        let path = PathBuf::from(file_path);
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| file_path.to_string());

        let file_content = match fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                output.push_str(&format!("[{}] FAILED — read error: {}\n", name, e));
                continue;
            }
        };

        let tree: Tree = match serde_json::from_str(&file_content) {
            Ok(t) => t,
            Err(e) => {
                output.push_str(&format!("[{}] FAILED — parse error: {}\n", name, e));
                continue;
            }
        };

        // Add to rev_to_tree index
        for rev_hash in tree.revisions.keys() {
            state
                .rev_to_tree
                .insert(rev_hash.to_string(), (name.clone(), tree.clone()));
        }

        let (_passed, status) = ingest_tree_into_forest(
            &mut state.forest,
            &state.aquafier,
            &state.rev_to_tree,
            &name,
            &tree,
        )
        .await;

        output.push_str(&format!("{}\n", status));
    }

    // Post-insert L3 resolution
    let pending_keys: Vec<RevisionLink> =
        state.forest.pending_dependencies().keys().cloned().collect();
    for awaited in &pending_keys {
        if state.forest.get_node(awaited).is_some() {
            state.forest.resolve_l3_pending(awaited);
        }
    }

    output.trim_end().to_string()
}

fn cmd_evict(state: &mut DaemonState, arg: &str) -> String {
    match resolve_hash_prefix(state, arg) {
        Ok(hash) => {
            // Verify it's a genesis node
            let geneses = state.forest.genesis_hashes();
            if !geneses.contains(&hash) {
                return format!(
                    "Error: {} is not a genesis node. Use 'remove' for non-genesis nodes, or provide the genesis hash to evict an entire tree.",
                    hash
                );
            }
            state.forest.evict_node(&hash);
            format!("Evicted genesis {} and its subtree.", hash)
        }
        Err(e) => e,
    }
}

fn cmd_remove(state: &mut DaemonState, arg: &str) -> String {
    match resolve_hash_prefix(state, arg) {
        Ok(hash) => {
            if state.forest.remove_node(&hash) {
                format!("Removed node {}.", hash)
            } else {
                format!("Failed to remove node {} (not found or is genesis root).", hash)
            }
        }
        Err(e) => e,
    }
}

async fn cmd_ingest(state: &mut DaemonState, arg: &str) -> String {
    if arg.is_empty() {
        return "Error: ingest requires JSON data.".to_string();
    }

    let tree: Tree = match serde_json::from_str(arg) {
        Ok(t) => t,
        Err(e) => {
            return format!("Error parsing tree JSON: {}", e);
        }
    };

    // Add to rev_to_tree index
    for rev_hash in tree.revisions.keys() {
        state
            .rev_to_tree
            .insert(rev_hash.to_string(), ("ingest".to_string(), tree.clone()));
    }

    let (_passed, status) = ingest_tree_into_forest(
        &mut state.forest,
        &state.aquafier,
        &state.rev_to_tree,
        "ingest",
        &tree,
    )
    .await;

    // Post-insert L3 resolution
    let pending_keys: Vec<RevisionLink> =
        state.forest.pending_dependencies().keys().cloned().collect();
    for awaited in &pending_keys {
        if state.forest.get_node(awaited).is_some() {
            state.forest.resolve_l3_pending(awaited);
        }
    }

    status
}

// ─── HTTP API handlers ───────────────────────────────────────────────────────

async fn api_health() -> AxumJson<serde_json::Value> {
    AxumJson(serde_json::json!({"status": "ok"}))
}

async fn api_trees(AxumState(state): AxumState<SharedState>) -> AxumJson<Vec<String>> {
    let mut st = state.lock().await;
    st.touch();
    // Only return tips whose revision hash exists in rev_to_tree (user-ingested
    // trees). Template trees inserted by the SDK are excluded — the state viewer
    // resolves those via its own built-in template cache.
    let tips: Vec<String> = st
        .forest
        .tips()
        .iter()
        .map(|t| t.to_string())
        .filter(|h| st.rev_to_tree.contains_key(h))
        .collect();
    AxumJson(tips)
}

async fn api_tree_by_hash(
    AxumState(state): AxumState<SharedState>,
    AxumPath(hash): AxumPath<String>,
) -> Result<AxumJson<serde_json::Value>, StatusCode> {
    let mut st = state.lock().await;
    st.touch();
    // Look up by exact hash in the revision-to-tree index.
    // Every revision hash in every ingested tree is a valid key.
    if let Some((_name, tree)) = st.rev_to_tree.get(&hash) {
        Ok(AxumJson(serde_json::json!(tree)))
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

// ─── Utilities ───────────────────────────────────────────────────────────────

/// Recursively print a forest node and its children with indentation (verbose mode).
fn print_forest_subtree(forest: &Forest, hash: &RevisionLink, depth: usize) {
    let indent = "  ".repeat(depth + 1);
    if let Some(node) = forest.get_node(hash) {
        let signer = node.state.signer.as_deref().unwrap_or("-");
        let rev_type = truncate(&node.state.revision_type, 12);
        let hash_str = hash.to_string();
        println!(
            "{}[{}] type={} signer={}",
            indent,
            truncate(&hash_str, 14),
            rev_type,
            signer
        );
        for child in forest.branches(hash) {
            if let Ok(child_link) = child.state.revision_hash.parse::<RevisionLink>() {
                print_forest_subtree(forest, &child_link, depth + 1);
            }
        }
    }
}

/// Truncate a string for display, appending "…" if truncated.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max.saturating_sub(1)])
    }
}

/// Serialize a JSON report using Forest API data.
fn build_forest_report(forest: &Forest) -> String {
    let summary = forest.summary();
    let genesis_hashes: Vec<String> = forest
        .genesis_hashes()
        .iter()
        .map(|h| h.to_string())
        .collect();
    let tips: Vec<String> = forest.tips().iter().map(|h| h.to_string()).collect();
    let pending: Vec<String> = forest
        .pending_dependencies()
        .keys()
        .map(|h| h.to_string())
        .collect();

    let report = serde_json::json!({
        "session": summary.namespace_name,
        "node_count": summary.node_count,
        "genesis_count": summary.genesis_count,
        "genesis_hashes": genesis_hashes,
        "tips": tips,
        "pending_count": summary.pending_count,
        "pending_dependencies": pending,
    });

    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
}
