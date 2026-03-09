#!/bin/sh

test_description='Test identity claim templates (email/phone bypass, non-verifiable, schema errors)'

. ./sharness/sharness.sh

AQUA_CLI="$SHARNESS_TEST_DIRECTORY/../target/debug/aqua-cli"

test_expect_success 'Setup test fixtures' '
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/keys.json" keys.json &&
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/plugin_payload.json" plugin_payload.json
'

# ============================================================
# A. Verifiable templates with Twilio test bypass
# ============================================================

test_expect_success 'Email claim with test bypass (test@inblock.io)' '
    rm -f email_claim.aqua.json &&
    $AQUA_CLI --create-object --template-name email \
        --payload "{\"email\":\"test@inblock.io\"}" \
        --keys-file keys.json \
        > email_output 2>&1 &&
    grep -q "Test mode: skipping Twilio verification" email_output
'

test_expect_success 'Email claim creates aqua.json with >=2 revisions' '
    test -f email_claim.aqua.json &&
    python3 -c "
import json
tree = json.load(open(\"email_claim.aqua.json\"))
assert len(tree[\"revisions\"]) >= 2, \"expected >= 2 revisions, got %d\" % len(tree[\"revisions\"])
"
'

test_expect_success 'Phone claim with test bypass (+10000000000)' '
    rm -f phone_claim.aqua.json &&
    $AQUA_CLI --create-object --template-name phone \
        --payload "{\"phone_number\":\"+10000000000\"}" \
        --keys-file keys.json \
        > phone_output 2>&1 &&
    grep -q "Test mode: skipping Twilio verification" phone_output
'

test_expect_success 'Phone claim creates aqua.json with >=2 revisions' '
    test -f phone_claim.aqua.json &&
    python3 -c "
import json
tree = json.load(open(\"phone_claim.aqua.json\"))
assert len(tree[\"revisions\"]) >= 2, \"expected >= 2 revisions, got %d\" % len(tree[\"revisions\"])
"
'

# ============================================================
# B. Schema validation error tests
# ============================================================

test_expect_success 'Phone template with email value fails validation' '
    rm -f phone_claim.aqua.json &&
    ! $AQUA_CLI --create-object --template-name phone \
        --payload "{\"phone_number\":\"test@inblock.io\"}" \
        --keys-file keys.json \
        > phone_email_err 2>&1 ||
    grep -qi "does not match\|pattern\|error\|fail" phone_email_err
'

test_expect_success 'Email template with phone number fails validation' '
    rm -f email_claim.aqua.json &&
    ! $AQUA_CLI --create-object --template-name email \
        --payload "{\"email\":\"+10000000000\"}" \
        --keys-file keys.json \
        > email_phone_err 2>&1 ||
    grep -qi "does not match\|pattern\|error\|fail" email_phone_err
'

test_expect_success 'Phone template without + prefix fails validation' '
    rm -f phone_claim.aqua.json &&
    ! $AQUA_CLI --create-object --template-name phone \
        --payload "{\"phone_number\":\"10000000000\"}" \
        --keys-file keys.json \
        > phone_noplus_err 2>&1 ||
    grep -qi "does not match\|pattern\|error\|fail" phone_noplus_err
'

# ============================================================
# C. Non-verifiable identity templates
# ============================================================

test_expect_success 'Name claim template' '
    rm -f object.aqua.json &&
    $AQUA_CLI --create-object --template-name name \
        --payload "{\"signer_did\":\"did:pkh:eip155:1:0x1234567890abcdef1234567890abcdef12345678\",\"given_name\":\"Alice\",\"family_name\":\"Smith\"}" \
        > name_output 2>&1 &&
    grep -q "Successfully created" name_output &&
    python3 -c "
import json
tree = json.load(open(\"object.aqua.json\"))
assert len(tree[\"revisions\"]) >= 2, \"expected >= 2 revisions, got %d\" % len(tree[\"revisions\"])
"
'

test_expect_success 'Wallet identification template' '
    rm -f object.aqua.json &&
    $AQUA_CLI --create-object --template-name wallet-identification \
        --payload "{\"signer_did\":\"did:pkh:eip155:1:0x1234567890abcdef1234567890abcdef12345678\",\"entity_type\":\"human\",\"wallet_type\":\"software_wallet\"}" \
        > wallet_output 2>&1 &&
    grep -q "Successfully created" wallet_output &&
    python3 -c "
import json
tree = json.load(open(\"object.aqua.json\"))
assert len(tree[\"revisions\"]) >= 2, \"expected >= 2 revisions, got %d\" % len(tree[\"revisions\"])
"
'

test_expect_success 'Trust assertion template' '
    rm -f object.aqua.json &&
    $AQUA_CLI --create-object --template-name trust-assertion \
        --payload "{\"subject_did\":\"did:pkh:eip155:1:0x1234567890abcdef1234567890abcdef12345678\",\"trust_level\":2}" \
        > trust_output 2>&1 &&
    grep -q "Successfully created" trust_output &&
    python3 -c "
import json
tree = json.load(open(\"object.aqua.json\"))
assert len(tree[\"revisions\"]) >= 2, \"expected >= 2 revisions, got %d\" % len(tree[\"revisions\"])
"
'

test_expect_success 'Access grant template' '
    rm -f object.aqua.json &&
    $AQUA_CLI --create-object --template-name access-grant \
        --payload "{\"receiver\":\"did:pkh:eip155:1:0x1234567890abcdef1234567890abcdef12345678\",\"resources\":[\"0xaabbccdd\"],\"propagation\":\"snapshot\"}" \
        > access_output 2>&1 &&
    grep -q "Successfully created" access_output &&
    python3 -c "
import json
tree = json.load(open(\"object.aqua.json\"))
assert len(tree[\"revisions\"]) >= 2, \"expected >= 2 revisions, got %d\" % len(tree[\"revisions\"])
"
'

test_expect_success 'Multi-signer template' '
    rm -f object.aqua.json &&
    $AQUA_CLI --create-object --template-name multi-signer \
        --payload "{\"required_signers\":2,\"authorized_signers\":[\"did:pkh:eip155:1:0xaaaa\",\"did:pkh:eip155:1:0xbbbb\",\"did:pkh:eip155:1:0xcccc\"]}" \
        > multi_output 2>&1 &&
    grep -q "Successfully created" multi_output &&
    python3 -c "
import json
tree = json.load(open(\"object.aqua.json\"))
assert len(tree[\"revisions\"]) >= 2, \"expected >= 2 revisions, got %d\" % len(tree[\"revisions\"])
"
'

test_expect_success 'Domain template' '
    rm -f object.aqua.json &&
    $AQUA_CLI --create-object --template-name domain \
        --payload "{\"signer_did\":\"did:pkh:eip155:1:0x1234567890abcdef1234567890abcdef12345678\",\"domain_name\":\"example.com\"}" \
        > domain_output 2>&1 &&
    grep -q "Successfully created" domain_output &&
    python3 -c "
import json
tree = json.load(open(\"object.aqua.json\"))
assert len(tree[\"revisions\"]) >= 2, \"expected >= 2 revisions, got %d\" % len(tree[\"revisions\"])
"
'

test_expect_success 'Vendor registration template' '
    rm -f object.aqua.json &&
    $AQUA_CLI --create-object --template-name vendor-registration \
        --payload "{\"vendor_name\":\"acme\",\"vendor_did\":\"did:pkh:eip155:1:0x1234567890abcdef1234567890abcdef12345678\"}" \
        > vendor_output 2>&1 &&
    grep -q "Successfully created" vendor_output &&
    python3 -c "
import json
tree = json.load(open(\"object.aqua.json\"))
assert len(tree[\"revisions\"]) >= 2, \"expected >= 2 revisions, got %d\" % len(tree[\"revisions\"])
"
'

test_expect_success 'Template registration template' '
    rm -f object.aqua.json &&
    $AQUA_CLI --create-object --template-name template-registration \
        --payload "{\"vendor\":\"acme\",\"name\":\"my-template\",\"template_hash\":\"0x0000000000000000000000000000000000000000000000000000000000000001\"}" \
        > templ_reg_output 2>&1 &&
    grep -q "Successfully created" templ_reg_output &&
    python3 -c "
import json
tree = json.load(open(\"object.aqua.json\"))
assert len(tree[\"revisions\"]) >= 2, \"expected >= 2 revisions, got %d\" % len(tree[\"revisions\"])
"
'

test_expect_success 'Alias registration template' '
    rm -f object.aqua.json &&
    $AQUA_CLI --create-object --template-name alias-registration \
        --payload "{\"vendor\":\"acme\",\"alias_name\":\"my-alias\",\"target_hash\":\"0x0000000000000000000000000000000000000000000000000000000000000002\"}" \
        > alias_output 2>&1 &&
    grep -q "Successfully created" alias_output &&
    python3 -c "
import json
tree = json.load(open(\"object.aqua.json\"))
assert len(tree[\"revisions\"]) >= 2, \"expected >= 2 revisions, got %d\" % len(tree[\"revisions\"])
"
'

test_expect_success 'Plugin registration template (from fixture file)' '
    rm -f object.aqua.json &&
    $AQUA_CLI --create-object --template-name plugin-registration \
        --payload plugin_payload.json \
        > plugin_output 2>&1 &&
    grep -q "Successfully created" plugin_output &&
    python3 -c "
import json
tree = json.load(open(\"plugin_payload.aqua.json\"))
assert len(tree[\"revisions\"]) >= 2, \"expected >= 2 revisions, got %d\" % len(tree[\"revisions\"])
"
'

test_done
