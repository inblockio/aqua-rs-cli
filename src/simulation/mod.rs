// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

//! Identity claim state simulation suite.
//!
//! Exercises all 12 WASM states for `PlatformIdentityClaim` (6) and
//! `Attestation` (6) using freshly generated Ed25519 + P-256 keys, building
//! trees via the lowest-level public SDK API, and running verification
//! through the full WASM pipeline.
//!
//! # Usage
//! ```
//! cargo build --features simulation
//! ./target/debug/aqua-cli --simulate
//! ./target/debug/aqua-cli --simulate -v   # verbose: show per-scenario wasm_outputs
//! ```

pub mod builders;
pub mod keygen;
pub mod persona_scenarios;
pub mod sandbox;
pub mod scenarios;

use persona_scenarios::PersonaResult;
use scenarios::ScenarioResult;

/// Entry point called by `main()` when `--simulate` is passed.
pub async fn run_simulation(verbose: bool, keep: bool) {
    println!("Aqua Identity Simulation Suite");
    println!("================================");
    println!();

    // Run all 12 scenarios in sequence.
    // Each scenario is self-contained: it generates fresh keys, builds trees,
    // signs, verifies, and returns a structured result.
    let results: Vec<ScenarioResult> = vec![
        scenarios::c1_unsigned().await,
        scenarios::c2_self_signed().await,
        scenarios::c3_untrusted().await,
        scenarios::c4_attested().await,
        scenarios::c5_expired().await,
        scenarios::c6_not_yet_valid().await,
        scenarios::a1_headless().await,
        scenarios::a2_unsigned().await,
        scenarios::a3_untrusted().await,
        scenarios::a4_attested().await,
        scenarios::a5_expired().await,
        scenarios::a6_not_yet_valid().await,
    ];

    // ── PlatformIdentityClaim group ──────────────────────────────────────
    println!("PlatformIdentityClaim States");
    println!("────────────────────────────");
    let claim_results = &results[..6];
    for r in claim_results {
        print_scenario(r, verbose);
    }
    println!();

    // ── Attestation group ────────────────────────────────────────────────
    println!("Attestation States");
    println!("──────────────────");
    let attest_results = &results[6..];
    for r in attest_results {
        print_scenario(r, verbose);
    }
    println!();

    // ── Summary ──────────────────────────────────────────────────────────
    let pass = results.iter().filter(|r| r.passed).count();
    let fail = results.iter().filter(|r| !r.passed).count();
    let total = results.len();
    println!(
        "Results: {}/{} passed, {}/{} failed",
        pass, total, fail, total
    );
    println!();

    // ── Keep trees for inspection ────────────────────────────────────────
    if keep {
        keep_trees(&results, verbose);
    }

    // ── SDK Friction Summary ─────────────────────────────────────────────
    print_friction_summary(&results);
}

fn print_scenario(r: &ScenarioResult, verbose: bool) {
    let status = if r.passed { "PASS" } else { "FAIL" };
    let state_str = match &r.actual_state {
        Some(s) => s.as_str(),
        None => "(none)",
    };
    println!(
        "  [{status}] {id} — expected={exp} actual={actual}",
        status = status,
        id = r.id,
        exp = r.expected_state,
        actual = state_str,
    );
    if let Some(ref err) = r.error {
        println!("         error: {}", err);
    }
    if verbose {
        println!("         desc: {}", r.description);
        if !r.raw_wasm_outputs.is_empty() {
            for w in &r.raw_wasm_outputs {
                println!("         wasm : {}", w);
            }
        } else {
            println!("         wasm : (no wasm_outputs produced)");
        }
        for f in &r.friction {
            println!("         note : {}", f);
        }
    }
}

/// Write every tree from each scenario result into a persistent sandbox directory
/// and print the location + file manifest so the caller can inspect them.
fn keep_trees(results: &[ScenarioResult], _verbose: bool) {
    println!("Simulation Tree Files");
    println!("─────────────────────");

    let sandbox = match sandbox::Sandbox::new() {
        Ok(s) => s,
        Err(e) => {
            println!("  ERROR: could not create sandbox: {}", e);
            return;
        }
    };

    let mut manifest: Vec<std::path::PathBuf> = Vec::new();
    let mut written: std::collections::HashSet<String> = std::collections::HashSet::new();
    for r in results {
        for (name, tree) in &r.trees {
            if written.contains(name) {
                continue;
            }
            match sandbox.write_tree(name, tree) {
                Ok(path) => {
                    manifest.push(path);
                    written.insert(name.clone());
                }
                Err(e) => println!("  ERROR writing {}: {}", name, e),
            }
        }
    }

    let dir = sandbox.keep();
    println!("  {} file(s) written to:", manifest.len());
    println!("  {}", dir.display());
    println!();
    for path in &manifest {
        if let Some(name) = path.file_name() {
            println!("    {}", name.to_string_lossy());
        }
    }
    println!();
    println!("  Inspect with:");
    println!("    jq . <file>.aqua.json");
    println!("    cargo run --features simulation -- -a <file>.aqua.json");
    println!();
}

/// Entry point for `--simulate-personas`.
///
/// Runs 5 personas (15 scenarios total) covering all 15 derived identity templates.
pub async fn run_personas_simulation(verbose: bool, keep: bool) {
    println!("Aqua Persona Identity Simulation");
    println!("=================================");
    println!();

    let all_results: Vec<Vec<PersonaResult>> = vec![
        persona_scenarios::persona_alice().await,
        persona_scenarios::persona_bob().await,
        persona_scenarios::persona_claire().await,
        persona_scenarios::persona_david().await,
        persona_scenarios::persona_eve().await,
    ];

    let personas = [
        ("P1: Alice Chen", "developer, San Francisco"),
        ("P2: Bob Martinez", "freelance translator, Madrid"),
        ("P3: Claire Dubois", "investigative journalist, Paris"),
        ("P4: David Kim", "graduate student, Seoul"),
        ("P5: Eve Okafor", "startup founder, Lagos"),
    ];

    let mut all_flat: Vec<&PersonaResult> = Vec::new();

    for (group, (name, role)) in all_results.iter().zip(personas.iter()) {
        println!("{} ({})", name, role);
        println!("{}", "─".repeat(name.len() + role.len() + 3));
        for r in group {
            print_persona_result(r, verbose);
            all_flat.push(r);
        }
        println!();
    }

    // ── Summary ──────────────────────────────────────────────────────────────
    let pass = all_flat.iter().filter(|r| r.passed).count();
    let fail = all_flat.iter().filter(|r| !r.passed).count();
    let total = all_flat.len();
    let sub = all_flat.iter().filter(|r| r.is_sub_condition).count();
    println!(
        "Results: {}/{} passed, {}/{} failed  ({} sub-condition scenarios)",
        pass, total, fail, total, sub
    );
    println!();

    // ── Keep trees ───────────────────────────────────────────────────────────
    if keep {
        keep_persona_trees(&all_results, verbose);
    }
}

fn print_persona_result(r: &PersonaResult, verbose: bool) {
    let status = if r.passed { "PASS" } else { "FAIL" };
    let sub_marker = if r.is_sub_condition { " ⚠" } else { "" };
    let actual_str = r.actual_state.as_deref().unwrap_or("(none)");
    println!(
        "  [{status}] {id} {ct:<22} expected={exp:<15} actual={actual}{sub}",
        status = status,
        id = r.scenario_id,
        ct = r.claim_type,
        exp = r.expected_state,
        actual = actual_str,
        sub = sub_marker,
    );
    if let Some(ref err) = r.error {
        println!("         error: {}", err);
    }
    if verbose {
        println!("         desc : {}", r.description);
        if !r.raw_wasm_outputs.is_empty() {
            for w in &r.raw_wasm_outputs {
                println!("         wasm : {}", w);
            }
        } else {
            println!("         wasm : (no wasm_outputs produced)");
        }
    }
}

fn keep_persona_trees(all_results: &[Vec<PersonaResult>], _verbose: bool) {
    println!("Persona Tree Files");
    println!("──────────────────");

    let sandbox = match sandbox::Sandbox::new() {
        Ok(s) => s,
        Err(e) => {
            println!("  ERROR: could not create sandbox: {}", e);
            return;
        }
    };

    let mut manifest: Vec<std::path::PathBuf> = Vec::new();
    let mut written: std::collections::HashSet<String> = std::collections::HashSet::new();
    for group in all_results {
        for r in group {
            for (name, tree) in &r.trees {
                if written.contains(name) {
                    continue;
                }
                match sandbox.write_tree(name, tree) {
                    Ok(path) => {
                        manifest.push(path);
                        written.insert(name.clone());
                    }
                    Err(e) => println!("  ERROR writing {}: {}", name, e),
                }
            }
        }
    }

    let dir = sandbox.keep();
    println!("  {} file(s) written to:", manifest.len());
    println!("  {}", dir.display());
    println!();
    for path in &manifest {
        if let Some(name) = path.file_name() {
            println!("    {}", name.to_string_lossy());
        }
    }
    println!();
}

fn print_friction_summary(results: &[ScenarioResult]) {
    println!("SDK Friction Points Discovered");
    println!("──────────────────────────────");

    let mut all_friction: Vec<&'static str> = results
        .iter()
        .flat_map(|r| r.friction.iter().copied())
        .collect();
    all_friction.sort_unstable();
    all_friction.dedup();

    if all_friction.is_empty() {
        println!("  (none encountered)");
    } else {
        for (i, f) in all_friction.iter().enumerate() {
            println!("  {}. {}", i + 1, f);
        }
    }
    println!();
}
