#!/bin/sh

test_description='Test aqua chain linking'

. ./sharness/sharness.sh

AQUA_CLI="$SHARNESS_TEST_DIRECTORY/../target/debug/aqua-cli"

test_expect_success 'Setup test fixtures' '
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/sample.txt" sample.txt &&
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/sample2.txt" sample2.txt
'

test_expect_success 'Generate genesis for sample.txt' '
    $AQUA_CLI -f sample.txt > /dev/null 2>&1 &&
    test -f sample.aqua.json
'

test_expect_success 'Generate genesis for sample2.txt' '
    $AQUA_CLI -f sample2.txt > /dev/null 2>&1 &&
    test -f sample2.aqua.json
'

test_expect_success 'Link sample2 into sample (parent=sample, child=sample2)' '
    $AQUA_CLI --link sample.aqua.json sample2.aqua.json > link_output 2>&1 &&
    grep -q "Successfully" link_output
'

test_expect_success 'Parent chain has more revisions after linking' '
    python3 -c "
import json
tree = json.load(open(\"sample.aqua.json\"))
assert len(tree[\"revisions\"]) > 2, \"parent should have > 2 revisions after link, got %d\" % len(tree[\"revisions\"])
"
'

test_expect_success 'Verify parent chain after linking' '
    $AQUA_CLI -a sample.aqua.json > /dev/null 2>&1
'

test_expect_success 'Verify child chain is still valid' '
    $AQUA_CLI -a sample2.aqua.json > /dev/null 2>&1
'

test_done
