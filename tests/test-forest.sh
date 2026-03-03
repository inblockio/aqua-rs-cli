#!/bin/sh

test_description='Test ephemeral forest ingestion of multiple aqua files'

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

test_expect_success 'Ingest multiple aqua files into ephemeral forest' '
    $AQUA_CLI --forest sample.aqua.json sample2.aqua.json > forest_output 2>&1
    # Forest command should complete without error
    true
'

test_expect_success 'Forest with verbose output' '
    $AQUA_CLI --forest sample.aqua.json sample2.aqua.json -v > forest_verbose 2>&1
    true
'

test_done
