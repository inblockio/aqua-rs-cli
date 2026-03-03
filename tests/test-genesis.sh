#!/bin/sh

test_description='Test genesis aqua chain generation from files'

. ./sharness/sharness.sh

AQUA_CLI="$SHARNESS_TEST_DIRECTORY/../target/debug/aqua-cli"

test_expect_success 'aqua-cli binary exists' '
    test -x "$AQUA_CLI"
'

test_expect_success 'Setup test fixtures' '
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/sample.txt" sample.txt &&
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/sample2.txt" sample2.txt
'

test_expect_success 'Generate genesis from text file' '
    $AQUA_CLI -f sample.txt > output 2>&1 &&
    grep -q "Successfully" output &&
    test -f sample.aqua.json
'

test_expect_success 'Genesis output contains aqua.json path' '
    grep -q "aqua.json" output
'

test_expect_success 'Generated aqua.json is valid JSON' '
    python3 -c "import json; json.load(open(\"sample.aqua.json\"))"
'

test_expect_success 'Genesis has revisions object' '
    python3 -c "
import json
tree = json.load(open(\"sample.aqua.json\"))
assert \"revisions\" in tree, \"missing revisions\"
assert len(tree[\"revisions\"]) >= 2, \"expected >= 2 revisions, got %d\" % len(tree[\"revisions\"])
"
'

test_expect_success 'Genesis has file_index' '
    python3 -c "
import json
tree = json.load(open(\"sample.aqua.json\"))
assert \"file_index\" in tree, \"missing file_index\"
"
'

test_expect_success 'file_index keys match revision order' '
    python3 -c "
import json
tree = json.load(open(\"sample.aqua.json\"))
fi_keys = list(tree[\"file_index\"].keys())
rev_keys = list(tree[\"revisions\"].keys())
assert fi_keys == rev_keys, \"file_index keys %s != revision keys %s\" % (fi_keys, rev_keys)
"
'

test_expect_success 'Generate genesis from second file' '
    $AQUA_CLI -f sample2.txt > output2 2>&1 &&
    grep -q "Successfully" output2 &&
    test -f sample2.aqua.json
'

test_expect_success 'Two genesis chains are independent' '
    python3 -c "
import json
t1 = json.load(open(\"sample.aqua.json\"))
t2 = json.load(open(\"sample2.aqua.json\"))
r1 = list(t1[\"revisions\"].keys())
r2 = list(t2[\"revisions\"].keys())
assert r1 != r2, \"chains should have different revision hashes\"
"
'

test_expect_success 'Regenerating genesis from same file succeeds' '
    $AQUA_CLI -f sample.txt > output3 2>&1 &&
    grep -q "Successfully" output3
'

test_done
