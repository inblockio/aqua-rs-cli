# Aqua CLI v3.2 Upgrade Changelog

## Overview

Upgrading aqua-rs-cli from v1.2.1 (protocol v2) to v3.2.0 (protocol v3.2)

## Key Changes Required

### 1. Data Model Updates

- [x] Replace `PageData` structures with `AquaTree`
- [x] Update revision types (file, content, form, signature, witness, link)
- [x] Add new fields: `file_index`, `tree_mapping`
- [x] Update schema version strings
- [x] Create validation framework for v3 compliance

### 2. CLI Interface Updates

- [x] Add new commands for form management
- [x] Add content vs file revision options
- [x] Add link revision support
- [x] Update argument parsing for v3 features
- [x] Maintain backward compatibility where possible

### 3. Dependencies

- [x] Keep `aqua-verifier="1.2.0"`
- [x] Keep `aqua-verifier-rs-types = "1.2.0"`
- [x] Keep `sha3 = "0.10.8"`
- [x] Update other dependencies as needed

## Files Completed ✅

### Core Files

- [x] `Cargo.toml` - Updated to v3.2.0
- [x] `src/models.rs` - Complete v3 data structures
- [x] `src/main.rs` - Updated CLI argument parsing for v3
- [x] `src/utils.rs` - Updated file I/O and validation functions

### New V3 Modules

- [x] `src/validation/mod.rs` - Complete v3 compliance validator
- [x] `src/aqua/content.rs` - Content revision handling
- [x] `src/aqua/form.rs` - Form revision for identity claims
- [x] `src/aqua/link.rs` - Link revision handling
- [x] `src/aqua/mod.rs` - Updated exports

### Updated Core Modules

- [x] `src/aqua/verify.rs` - Updated verification with v3 validator
- [x] `src/aqua/generate_aqua_chain_from_file.rs` - Updated for v3 format

## Files Still Needed

### Legacy Module Updates

- [x] `src/aqua/sign.rs` - Update signing for v3 format
- [x] `src/aqua/witness.rs` - Update witnessing for v3 format
- [x] `src/aqua/delete_revision_from_aqua_chain.rs` - Update deletion
- [ ] `src/aqua/wallet.rs` - May need minor updates

### Server Module Updates

- [x] Update payload structures in server modules
- [x] Maintain MetaMask integration compatibility
- [x] Update HTML templates if needed

### Tests

- [x] Update test data for v3 format
- [x] Update test assertions
- [x] Add new tests for v3 features

## Architecture Improvements

### New Features Added

- **Tree/Scalar Hashing Methods**: Support for both verification approaches
- **Selective Disclosure**: Form revisions with merkle trees
- **Content Embedding**: Smart embedding based on size/type
- **Link References**: Cross-tree references for complex structures
- **Comprehensive Validation**: Full v3 compliance checking

## Notes

- Networks maintained: nostr, TSA_RFC3161 (unchanged from v2)
- Contract addresses kept from v2
- `sha3` remains at version "0.10.8" as requested
- Full schema compliance with https://aqua-protocol.org/docs/v3/schema_2
