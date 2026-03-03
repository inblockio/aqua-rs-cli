#!/bin/sh

test_description='Test object creation with templates and payloads'

. ./sharness.sh

AQUA_CLI="$SHARNESS_TEST_DIRECTORY/../target/debug/aqua-cli"

test_expect_success 'Setup test fixtures' '
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/payload.json" payload.json
'

# --- Create object with template name and inline payload ---

test_expect_success 'Create object with file template and inline payload' '
    $AQUA_CLI --create-object --template-name file \
        --payload "{\"type\":\"file\",\"hash\":\"0x0000000000000000000000000000000000000000000000000000000000000000\",\"hash_type\":\"FIPS_202-SHA3-256\",\"descriptor\":\"test\",\"size\":100,\"content_type\":\"text/plain\"}" \
        > obj_output 2>&1 &&
    grep -q "Successfully created" obj_output
'

test_expect_success 'Object aqua.json file is created' '
    test -f object.aqua.json
'

test_expect_success 'Object has 2 revisions (anchor+object)' '
    python3 -c "
import json
tree = json.load(open(\"object.aqua.json\"))
assert len(tree[\"revisions\"]) >= 2, \"expected >= 2 revisions, got %d\" % len(tree[\"revisions\"])
"
'

# Clean up before next test
test_expect_success 'Clean up object.aqua.json' '
    rm -f object.aqua.json
'

# --- Create object with payload file ---

test_expect_success 'Create object with payload from file' '
    $AQUA_CLI --create-object --template-name file --payload payload.json > obj_file_output 2>&1 &&
    grep -q "Successfully created" obj_file_output
'

test_expect_success 'Object from file payload exists' '
    test -f payload.aqua.json
'

# Clean up before error tests
test_expect_success 'Clean up for error tests' '
    rm -f object.aqua.json
'

# --- Error cases ---

test_expect_success 'Create object without template fails' '
    ! $AQUA_CLI --create-object --payload payload.json > no_template 2>&1 ||
    grep -qi "error\|fail\|missing\|requires" no_template
'

test_expect_success 'Create object without payload fails' '
    ! $AQUA_CLI --create-object --template-name file > no_payload 2>&1 ||
    grep -qi "error\|fail\|missing" no_payload
'

test_expect_success 'Create object with invalid JSON payload fails' '
    ! $AQUA_CLI --create-object --template-name file --payload "not valid json" > bad_json 2>&1 ||
    grep -qi "error\|fail\|invalid" bad_json
'

# --- Create object with attestation template ---

test_expect_success 'Create object with attestation template' '
    rm -f object.aqua.json &&
    $AQUA_CLI --create-object --template-name attestation \
        --payload "{\"signer_did\":\"did:pkh:eip155:1:0x1234567890abcdef1234567890abcdef12345678\",\"context\":\"test attestation\"}" \
        > attest_output 2>&1 &&
    grep -q "Successfully created" attest_output
'

test_done
