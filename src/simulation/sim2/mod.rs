// Copyright (c) 2024–2026 inblock.io assets GmbH
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial (contact legal@inblock.io)

//! SIM-2: Comprehensive Identity Simulation.
//!
//! 5 personas with 25 persona-based claims + 4 error scenarios = 29 total scenarios.
//! Covers ALL 17 distinct WASM return values across three verification modules:
//!
//! - `identity_claim_verify`: unsigned, self_signed, expired, not_yet_valid, rejected (-1)
//! - `platform_identity_verify`: unsigned, self_signed, untrusted, attested, expired, not_yet_valid, rejected (-1)
//! - `attestation_verify`: headless, unsigned, untrusted, attested, expired, not_yet_valid, rejected (-1)
//!
//! ## Usage
//! ```text
//! cargo run --features simulation -- --simulate-2 -v
//! cargo run --features simulation -- --simulate-2 -v --keep
//! cargo run --features simulation -- --simulate-2 --invalidate amara-attestation
//! ```

pub mod error_scenarios;
pub mod invalidate;
pub mod personas;
pub mod verify;

use verify::Sim2Result;

use crate::simulation::sandbox;

/// Entry point called by `main()` when `--simulate-2` is passed.
pub async fn run_simulation_2(verbose: bool, keep: bool) {
    println!("Aqua SIM-2: Comprehensive Identity Simulation");
    println!("===============================================");
    println!();

    // ── Persona scenarios ──────────────────────────────────────────────────
    let all_persona_results: Vec<Vec<Sim2Result>> = vec![
        personas::persona_amara().await,
        personas::persona_kenji().await,
        personas::persona_sofia().await,
        personas::persona_lars().await,
        personas::persona_priya().await,
    ];

    let persona_labels = [
        ("S1: Amara Osei", "healthcare administrator, Accra", 7),
        ("S2: Kenji Tanaka", "freelance photographer, Tokyo", 5),
        ("S3: Sofia Reyes", "university professor, Mexico City", 4),
        ("S4: Lars Eriksson", "cybersecurity consultant, Stockholm", 3),
        ("S5: Priya Sharma", "FinTech startup founder, Mumbai", 6),
    ];

    let mut all_flat: Vec<&Sim2Result> = Vec::new();

    for (group, (name, role, _count)) in all_persona_results.iter().zip(persona_labels.iter()) {
        println!("{} ({})", name, role);
        println!("{}", "─".repeat(name.len() + role.len() + 3));
        for r in group {
            print_sim2_result(r, verbose);
            all_flat.push(r);
        }
        println!();
    }

    // ── Error scenarios ────────────────────────────────────────────────────
    println!("Error Scenarios (E1–E4)");
    println!("───────────────────────");

    let error_results: Vec<Sim2Result> = vec![
        error_scenarios::e1_claim_missing_signer_did().await,
        error_scenarios::e2_attestation_missing_signer_did().await,
        error_scenarios::e3_attestation_linked_to_unsigned_claim().await,
        error_scenarios::e4_self_attestation().await,
    ];

    for r in &error_results {
        print_sim2_result(r, verbose);
        all_flat.push(r);
    }
    println!();

    // ── Summary ────────────────────────────────────────────────────────────
    let pass = all_flat.iter().filter(|r| r.passed).count();
    let fail = all_flat.iter().filter(|r| !r.passed).count();
    let total = all_flat.len();
    let sub = all_flat.iter().filter(|r| r.is_sub_condition).count();
    println!(
        "Results: {}/{} passed, {}/{} failed  ({} sub-condition scenarios)",
        pass, total, fail, total, sub
    );
    println!();

    // ── Coverage matrix ────────────────────────────────────────────────────
    if verbose {
        print_coverage_matrix(&all_flat);
    }

    // ── Keep trees ─────────────────────────────────────────────────────────
    if keep {
        keep_sim2_trees(&all_persona_results, &error_results);
    }
}

fn print_sim2_result(r: &Sim2Result, verbose: bool) {
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

fn print_coverage_matrix(results: &[&Sim2Result]) {
    println!("State Coverage Matrix");
    println!("─────────────────────");
    println!();
    println!("  {:<14} {:<25} {:<25} {}", "State", "identity_claim", "platform_identity", "attestation");
    println!("  {:<14} {:<25} {:<25} {}", "─────", "──────────────", "─────────────────", "───────────");

    let states = ["unsigned", "self_signed", "untrusted", "attested", "expired", "not_yet_valid", "headless", "rejected"];
    let identity_claims = ["EmailClaim", "NameClaim", "PhoneClaim", "DnsClaim",
        "NationalIdClaim", "AddressClaim", "AgeClaim", "BirthdateClaim",
        "DocumentClaim", "PassportClaim", "DriversLicenseClaim"];
    let platform_claims = ["PlatformIdentityClaim", "GitHubClaim", "GoogleClaim"];

    for state in &states {
        let identity: Vec<String> = results.iter()
            .filter(|r| r.actual_state.as_deref() == Some(state) && identity_claims.contains(&r.claim_type))
            .map(|r| r.scenario_id.clone())
            .collect();
        let platform: Vec<String> = results.iter()
            .filter(|r| r.actual_state.as_deref() == Some(state) && platform_claims.contains(&r.claim_type))
            .map(|r| r.scenario_id.clone())
            .collect();
        let attestation: Vec<String> = results.iter()
            .filter(|r| r.actual_state.as_deref() == Some(state) && r.claim_type == "Attestation")
            .map(|r| r.scenario_id.clone())
            .collect();

        let id_str = if identity.is_empty() { "—".to_string() } else { identity.join(", ") };
        let pl_str = if platform.is_empty() { "—".to_string() } else { platform.join(", ") };
        let at_str = if attestation.is_empty() { "—".to_string() } else { attestation.join(", ") };

        println!("  {:<14} {:<25} {:<25} {}", state, id_str, pl_str, at_str);
    }
    println!();
}

fn keep_sim2_trees(persona_results: &[Vec<Sim2Result>], error_results: &[Sim2Result]) {
    println!("SIM-2 Tree Files");
    println!("────────────────");

    let sandbox = match sandbox::Sandbox::new() {
        Ok(s) => s,
        Err(e) => {
            println!("  ERROR: could not create sandbox: {}", e);
            return;
        }
    };

    let mut manifest: Vec<std::path::PathBuf> = Vec::new();
    let mut written: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Write persona trees
    for group in persona_results {
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

    // Write error scenario trees
    for r in error_results {
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
    println!("  Load into state-viewer:");
    println!("    aqua-state-viewer {}/*.aqua.json --label \"SIM-2\"", dir.display());
    println!();
    println!("  Demonstrate invalidation (node removal):");
    println!("    cargo run --features simulation -- --simulate-2 --invalidate amara-attestation");
    println!();
}
