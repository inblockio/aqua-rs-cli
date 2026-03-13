// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub enum SignType {
    Cli,
    Metamask,
    Did,
    P256,
}

#[derive(Debug, Clone)]
pub enum WitnessType {
    Eth,
    Nostr,
    Tsa,
}

#[derive(Debug, Clone)]
pub struct CliArgs {
    pub authenticate: Option<PathBuf>,
    pub sign: Option<PathBuf>,
    pub sign_type: Option<SignType>,
    pub witness: Option<PathBuf>,
    pub witness_type: Option<WitnessType>,
    pub file: Option<PathBuf>,
    pub verbose: bool,
    pub output: Option<PathBuf>,
    pub level: Option<String>,
    pub keys_file: Option<PathBuf>,
    pub link: Option<Vec<PathBuf>>,
    pub delete: Option<PathBuf>,
    pub info: bool,
    pub previous_hash: Option<String>,
    pub create_object: bool,
    pub template_hash: Option<String>,
    pub template_name: Option<String>,
    pub payload: Option<String>,
    pub list_templates: bool,
    pub minimal: bool,
    pub forest_files: Option<Vec<PathBuf>>,
    pub trust: Option<(String, u8)>,
    pub simulate: bool,
    pub simulate_personas: bool,
    pub simulate_2: bool,
    pub invalidate: Option<String>,
    pub keep: bool,
    pub daemon: Option<u64>,
    pub connect: Option<u64>,
    pub target: Option<u64>,
    pub listen: Option<u16>,
    pub cleanup: Option<String>,
}
