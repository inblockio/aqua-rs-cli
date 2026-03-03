#!/bin/sh

test_description='Test aqua chain signing with cli, did, and p256 key types'

. ./sharness/sharness.sh

AQUA_CLI="$SHARNESS_TEST_DIRECTORY/../target/debug/aqua-cli"

test_expect_success 'Setup test fixtures' '
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/sample.txt" sample.txt &&
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/keys.json" keys.json
'

test_expect_success 'Generate genesis for signing tests' '
    $AQUA_CLI -f sample.txt > /dev/null 2>&1 &&
    test -f sample.aqua.json
'

# --- CLI signing ---

test_expect_success 'Sign with cli type' '
    $AQUA_CLI -s sample.aqua.json --sign-type cli -k keys.json > output_cli 2>&1 &&
    grep -q "Successfully signed" output_cli
'

test_expect_success 'Verify after cli signing' '
    $AQUA_CLI -a sample.aqua.json > /dev/null 2>&1
'

test_expect_success 'CLI signing adds a revision' '
    python3 -c "
import json
tree = json.load(open(\"sample.aqua.json\"))
# After genesis (2) + sign (1) = 3 revisions
assert len(tree[\"revisions\"]) >= 3, \"expected >= 3 revisions after signing, got %d\" % len(tree[\"revisions\"])
"
'

# --- DID signing ---

test_expect_success 'Sign with did type' '
    $AQUA_CLI -s sample.aqua.json --sign-type did -k keys.json > output_did 2>&1 &&
    grep -q "Successfully signed" output_did
'

test_expect_success 'Verify after did signing' '
    $AQUA_CLI -a sample.aqua.json > /dev/null 2>&1
'

# --- P256 signing ---

test_expect_success 'Sign with p256 type' '
    $AQUA_CLI -s sample.aqua.json --sign-type p256 -k keys.json > output_p256 2>&1 &&
    grep -q "Successfully signed" output_p256
'

test_expect_success 'Verify after p256 signing' '
    $AQUA_CLI -a sample.aqua.json > /dev/null 2>&1
'

# --- MetaMask / secp256k1 signing (auto-detect) ---

test_expect_success 'Sign with metamask type (secp256k1 auto-detect)' '
    $AQUA_CLI -s sample.aqua.json --sign-type metamask -k keys.json > output_metamask 2>&1 &&
    grep -q "Successfully signed" output_metamask
'

test_expect_success 'Verify after metamask signing' '
    $AQUA_CLI -a sample.aqua.json > /dev/null 2>&1
'

# --- Multiple signatures accumulate ---

test_expect_success 'Multiple signatures accumulate revisions' '
    python3 -c "
import json
tree = json.load(open(\"sample.aqua.json\"))
# genesis(2) + cli(1) + did(1) + p256(1) + metamask/secp256k1(1) = 6
assert len(tree[\"revisions\"]) >= 6, \"expected >= 6 revisions after 4 signatures, got %d\" % len(tree[\"revisions\"])
"
'

# --- Error case: sign without keys ---

test_expect_success 'Sign without keys file fails' '
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/sample.txt" no_keys_test.txt &&
    $AQUA_CLI -f no_keys_test.txt > /dev/null 2>&1 &&
    ! $AQUA_CLI -s no_keys_test.aqua.json --sign-type cli > sign_nokeys 2>&1 ||
    grep -qi "error\|fail\|keys" sign_nokeys
'

test_done
