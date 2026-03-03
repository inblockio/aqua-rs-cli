#!/bin/sh

test_description='Test aqua chain revision deletion'

. ./sharness.sh

AQUA_CLI="$SHARNESS_TEST_DIRECTORY/../target/debug/aqua-cli"

test_expect_success 'Setup test fixtures' '
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/sample.txt" sample.txt &&
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/keys.json" keys.json
'

test_expect_success 'Generate genesis for delete tests' '
    $AQUA_CLI -f sample.txt > /dev/null 2>&1 &&
    test -f sample.aqua.json
'

test_expect_success 'Count revisions before delete' '
    python3 -c "
import json
tree = json.load(open(\"sample.aqua.json\"))
print(len(tree[\"revisions\"]))
" > count_before
'

test_expect_success 'Delete last revision' '
    $AQUA_CLI -d sample.aqua.json > delete_output 2>&1 &&
    grep -q "Successfully removed" delete_output
'

test_expect_success 'Revision count decreases after delete' '
    python3 -c "
import json
tree = json.load(open(\"sample.aqua.json\"))
print(len(tree[\"revisions\"]))
" > count_after &&
    test "$(cat count_before)" -gt "$(cat count_after)"
'

test_expect_success 'Verify chain after delete' '
    $AQUA_CLI -a sample.aqua.json > /dev/null 2>&1
'

# --- Sign-delete-verify cycle ---

test_expect_success 'Generate fresh genesis for sign-delete-verify' '
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/sample.txt" cycle.txt &&
    $AQUA_CLI -f cycle.txt > /dev/null 2>&1 &&
    test -f cycle.aqua.json
'

test_expect_success 'Sign the chain' '
    $AQUA_CLI -s cycle.aqua.json --sign-type cli -k keys.json > /dev/null 2>&1
'

test_expect_success 'Delete last revision from signed chain' '
    $AQUA_CLI -d cycle.aqua.json > /dev/null 2>&1
'

test_expect_success 'Verify chain after sign-delete cycle' '
    $AQUA_CLI -a cycle.aqua.json > /dev/null 2>&1
'

test_done
