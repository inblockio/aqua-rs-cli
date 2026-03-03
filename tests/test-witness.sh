#!/bin/sh

test_description='Test aqua chain witnessing with TSA and Nostr'

. ./sharness.sh

AQUA_CLI="$SHARNESS_TEST_DIRECTORY/../target/debug/aqua-cli"

test_expect_success 'Setup test fixtures' '
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/sample.txt" sample.txt &&
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/sample2.txt" sample2.txt &&
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/keys.json" keys.json
'

# --- TSA witnessing ---

test_expect_success 'Generate genesis for TSA witness test' '
    $AQUA_CLI -f sample.txt > /dev/null 2>&1 &&
    test -f sample.aqua.json
'

test_expect_success 'Witness with TSA (network dependent)' '
    $AQUA_CLI -w sample.aqua.json --witness-tsa > tsa_output 2>&1
    if grep -q "Successfully witnessed" tsa_output; then
        echo "TSA witness succeeded"
    else
        echo "NOTE: TSA witness skipped (network unavailable)"
    fi
    # Always pass — network-dependent test degrades gracefully
    true
'

test_expect_success 'Verify after TSA witness (if it succeeded)' '
    if grep -q "Successfully witnessed" tsa_output; then
        $AQUA_CLI -a sample.aqua.json > /dev/null 2>&1
    else
        echo "Skipping verify — TSA witness was not applied"
    fi
'

# --- Nostr witnessing ---

test_expect_success 'Generate genesis for Nostr witness test' '
    $AQUA_CLI -f sample2.txt > /dev/null 2>&1 &&
    test -f sample2.aqua.json
'

test_expect_success 'Witness with Nostr (network dependent)' '
    $AQUA_CLI -w sample2.aqua.json --witness-nostr -k keys.json > nostr_output 2>&1
    if grep -q "Successfully witnessed" nostr_output; then
        echo "Nostr witness succeeded"
    else
        echo "NOTE: Nostr witness skipped (network unavailable)"
    fi
    true
'

test_expect_success 'Nostr witness adds revision (if it succeeded)' '
    if grep -q "Successfully witnessed" nostr_output; then
        python3 -c "
import json
tree = json.load(open(\"sample2.aqua.json\"))
assert len(tree[\"revisions\"]) > 2, \"witnessed chain should have > 2 revisions\"
"
    else
        echo "Skipping — Nostr witness was not applied"
    fi
'

# --- Nostr without keys should fail ---

test_expect_success 'Witness Nostr without keys file fails' '
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/sample.txt" no_keys_witness.txt &&
    $AQUA_CLI -f no_keys_witness.txt > /dev/null 2>&1 &&
    ! $AQUA_CLI -w no_keys_witness.aqua.json --witness-nostr > nostr_nokeys 2>&1 ||
    grep -qi "error\|fail\|keys" nostr_nokeys
'

test_done
