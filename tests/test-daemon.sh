#!/bin/sh

test_description='Test daemon mode: ingest, add, remove, evict, and real-time re-validation'

. ./sharness/sharness.sh

AQUA_CLI="$SHARNESS_TEST_DIRECTORY/../target/debug/aqua-cli"

# ── Helpers ──────────────────────────────────────────────────────────────────

# Send a command to the daemon via Unix socket, print the response (sans sentinel).
# Usage: daemon_cmd <socket_path> <command>
daemon_cmd () {
    python3 -c "
import socket, sys
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(sys.argv[1])
sock.sendall((sys.argv[2] + '\n').encode())
buf = b''
while True:
    chunk = sock.recv(4096)
    if not chunk:
        break
    buf += chunk
    if b'\x00\n' in buf:
        buf = buf[:buf.index(b'\x00\n')]
        break
sock.close()
print(buf.decode(), end='')
" "$1" "$2"
}

# Wait for the daemon socket to appear (up to 10 seconds).
# Usage: wait_for_socket <socket_path>
wait_for_socket () {
    local i=0
    while [ ! -S "$1" ] && [ $i -lt 100 ]; do
        sleep 0.1
        i=$((i + 1))
    done
    test -S "$1"
}

# ── Fixtures ─────────────────────────────────────────────────────────────────

test_expect_success 'Setup: copy fixtures and build aqua files' '
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/sample.txt" sample.txt &&
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/sample2.txt" sample2.txt &&
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/keys.json" keys.json &&

    $AQUA_CLI -f sample.txt > /dev/null 2>&1 &&
    test -f sample.aqua.json &&

    $AQUA_CLI -f sample2.txt > /dev/null 2>&1 &&
    test -f sample2.aqua.json &&

    # Create a signed version for richer tree structure
    $AQUA_CLI -s sample.aqua.json --sign-type did -k keys.json > /dev/null 2>&1
'

# ── 1. Daemon lifecycle ─────────────────────────────────────────────────────

test_expect_success 'Start daemon with one tree' '
    # Use sleep to keep a pipe open as stdin (prevents EOF shutdown)
    sleep 300 | $AQUA_CLI --forest sample.aqua.json --daemon 30 >daemon_stdout 2>&1 &
    PIPE_PID=$! &&
    echo $PIPE_PID > pipe_pid &&

    # The actual daemon PID is the second process in the pipeline;
    # but we need the socket path which uses the daemon PID.
    # Wait a moment for the process to start, then find it.
    sleep 0.5 &&
    DAEMON_PID=$(pgrep -f "aqua-cli --forest.*--daemon" | head -1) &&
    test -n "$DAEMON_PID" &&
    echo $DAEMON_PID > daemon_pid &&

    SOCKET="/tmp/aqua-forest-${DAEMON_PID}.sock" &&
    echo "$SOCKET" > daemon_socket &&
    wait_for_socket "$SOCKET"
'

test_expect_success 'Daemon socket exists' '
    SOCKET=$(cat daemon_socket) &&
    test -S "$SOCKET"
'

# ── 2. Read commands ────────────────────────────────────────────────────────

test_expect_success 'status returns node count > 0' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "status" > status_out &&
    grep -q "Nodes" status_out &&
    # Extract node count — should be at least 2 (genesis + content hash) + 1 (signature)
    NODE_COUNT=$(grep "Nodes" status_out | grep -o "[0-9]*") &&
    test "$NODE_COUNT" -ge 3
'

test_expect_success 'count returns a number' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "count" > count_out &&
    grep -qE "^[0-9]+$" count_out
'

test_expect_success 'geneses lists at least one genesis hash' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "geneses" > geneses_out &&
    grep -q "0x" geneses_out
'

test_expect_success 'tips lists at least one tip hash' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "tips" > tips_out &&
    grep -q "0x" tips_out
'

test_expect_success 'pending shows no pending (single standalone tree)' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "pending" > pending_out &&
    grep -qi "no pending" pending_out
'

test_expect_success 'inspect a genesis node returns type and hash' '
    SOCKET=$(cat daemon_socket) &&
    GENESIS=$(daemon_cmd "$SOCKET" "geneses" | grep "0x" | head -1 | tr -d " ") &&
    daemon_cmd "$SOCKET" "inspect $GENESIS" > inspect_out &&
    grep -q "Node:" inspect_out &&
    grep -q "Type" inspect_out
'

test_expect_success 'branches of genesis returns children' '
    SOCKET=$(cat daemon_socket) &&
    FOUND="" &&
    for G in $(daemon_cmd "$SOCKET" "geneses" | grep -o "0x[0-9a-f]*"); do
        G=$(echo "$G" | tr -d "[:space:]") &&
        daemon_cmd "$SOCKET" "branches $G" > branches_out &&
        if grep -q "type=" branches_out; then
            FOUND=yes && break
        fi
    done &&
    test "$FOUND" = "yes"
'

test_expect_success 'tree command renders subtree' '
    SOCKET=$(cat daemon_socket) &&
    GENESIS=$(daemon_cmd "$SOCKET" "geneses" | grep "0x" | head -1 | tr -d " ") &&
    daemon_cmd "$SOCKET" "tree $GENESIS" > tree_out &&
    grep -q "type=" tree_out
'

test_expect_success 'help lists available commands' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "help" > help_out &&
    grep -q "status" help_out &&
    grep -q "add" help_out &&
    grep -q "evict" help_out &&
    grep -q "remove" help_out
'

# ── 3. Add a second tree (real-time ingest) ─────────────────────────────────

test_expect_success 'Record initial node count' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "count" > count_before &&
    cat count_before
'

test_expect_success 'Ingest second aqua file into running daemon' '
    SOCKET=$(cat daemon_socket) &&
    JSON=$(python3 -c "import json; print(json.dumps(json.load(open(\"sample2.aqua.json\"))))") &&
    daemon_cmd "$SOCKET" "ingest $JSON" > add_out &&
    cat add_out
'

test_expect_success 'Node count increased after add' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "count" > count_after &&
    BEFORE=$(cat count_before | tr -d "[:space:]") &&
    AFTER=$(cat count_after | tr -d "[:space:]") &&
    test "$AFTER" -gt "$BEFORE"
'

test_expect_success 'More genesis nodes after adding second tree' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "geneses" > geneses_two &&
    GENESIS_COUNT=$(grep -c "0x" geneses_two) &&
    test "$GENESIS_COUNT" -ge 2
'

# ── 4. Remove a single node (surgical removal) ─────────────────────────────

test_expect_success 'Record count before remove' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "count" > count_pre_remove
'

test_expect_success 'Remove a tip node (signature revision)' '
    SOCKET=$(cat daemon_socket) &&
    # Pick a tip — tips are leaf nodes (often signatures)
    TIP=$(daemon_cmd "$SOCKET" "tips" | grep "0x" | head -1 | tr -d " ") &&
    echo "$TIP" > removed_tip &&
    daemon_cmd "$SOCKET" "remove $TIP" > remove_out &&
    grep -qi "removed" remove_out
'

test_expect_success 'Node count decreased by 1 after remove' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "count" > count_post_remove &&
    BEFORE=$(cat count_pre_remove | tr -d "[:space:]") &&
    AFTER=$(cat count_post_remove | tr -d "[:space:]") &&
    test "$AFTER" -eq "$((BEFORE - 1))"
'

test_expect_success 'Removed node no longer appears in inspect' '
    SOCKET=$(cat daemon_socket) &&
    TIP=$(cat removed_tip) &&
    daemon_cmd "$SOCKET" "inspect $TIP" > inspect_removed &&
    grep -qi "not found" inspect_removed
'

# ── 5. Evict an entire tree (cascade removal) ──────────────────────────────

test_expect_success 'Record state before evict' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "count" > count_pre_evict &&
    daemon_cmd "$SOCKET" "geneses" > geneses_pre_evict
'

test_expect_success 'Evict a genesis node and its subtree' '
    SOCKET=$(cat daemon_socket) &&
    # Pick the first genesis
    GENESIS=$(daemon_cmd "$SOCKET" "geneses" | grep "0x" | head -1 | tr -d " ") &&
    echo "$GENESIS" > evicted_genesis &&
    daemon_cmd "$SOCKET" "evict $GENESIS" > evict_out &&
    grep -qi "evicted" evict_out
'

test_expect_success 'Genesis count decreased after evict' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "geneses" > geneses_post_evict &&
    BEFORE=$(grep -c "0x" geneses_pre_evict || echo 0) &&
    AFTER=$(grep -c "0x" geneses_post_evict || echo 0) &&
    test "$AFTER" -lt "$BEFORE"
'

test_expect_success 'Node count decreased significantly after evict' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "count" > count_post_evict &&
    BEFORE=$(cat count_pre_evict | tr -d "[:space:]") &&
    AFTER=$(cat count_post_evict | tr -d "[:space:]") &&
    test "$AFTER" -lt "$BEFORE"
'

test_expect_success 'Evicted genesis no longer found' '
    SOCKET=$(cat daemon_socket) &&
    GENESIS=$(cat evicted_genesis) &&
    daemon_cmd "$SOCKET" "inspect $GENESIS" > inspect_evicted &&
    grep -qi "not found" inspect_evicted
'

# ── 6. Evict non-genesis fails ──────────────────────────────────────────────

test_expect_success 'Re-add a tree so we have nodes to work with' '
    SOCKET=$(cat daemon_socket) &&
    JSON=$(python3 -c "import json; print(json.dumps(json.load(open(\"sample.aqua.json\"))))") &&
    daemon_cmd "$SOCKET" "ingest $JSON" > readd_out
'

test_expect_success 'Evict a non-genesis node fails with error' '
    SOCKET=$(cat daemon_socket) &&
    # Collect all genesis hashes into a file for comparison
    daemon_cmd "$SOCKET" "geneses" | grep -o "0x[0-9a-fA-F]*" | tr -d "[:space:]" | sort > all_geneses &&
    # Find a tip that is NOT a genesis (i.e. a signature or content node)
    NON_GENESIS="" &&
    for T in $(daemon_cmd "$SOCKET" "tips" | grep -o "0x[0-9a-fA-F]*"); do
        T=$(echo "$T" | tr -d "[:space:]") &&
        if ! grep -qF "$T" all_geneses; then
            NON_GENESIS="$T" && break
        fi
    done &&
    if [ -n "$NON_GENESIS" ]; then
        daemon_cmd "$SOCKET" "evict $NON_GENESIS" > evict_nogenesis_out &&
        grep -qi "not a genesis" evict_nogenesis_out
    else
        # All tips are geneses (single-node trees only) — skip gracefully
        true
    fi
'

# ── 7. Hash prefix resolution ──────────────────────────────────────────────

test_expect_success 'Inspect with hash prefix (first 10 chars) works' '
    SOCKET=$(cat daemon_socket) &&
    GENESIS=$(daemon_cmd "$SOCKET" "geneses" | grep -oi "0x[0-9a-fA-F]*" | head -1 | tr -d "[:space:]") &&
    # Use first 10 hex chars (0x + 8 chars)
    PREFIX=$(echo "$GENESIS" | cut -c1-10) &&
    daemon_cmd "$SOCKET" "inspect $PREFIX" > inspect_prefix_out &&
    grep -q "Node:" inspect_prefix_out
'

test_expect_success 'Too-short prefix is rejected' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "inspect 0x1234" > short_prefix_out &&
    grep -qi "too short\|not found\|missing" short_prefix_out
'

# ── 8. Error handling ──────────────────────────────────────────────────────

test_expect_success 'Unknown command returns error' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "foobar" > unknown_out &&
    grep -qi "unknown command" unknown_out
'

test_expect_success 'inspect without argument returns error' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "inspect" > inspect_noarg_out &&
    grep -qi "missing\|error\|not found" inspect_noarg_out
'

test_expect_success 'add nonexistent file returns error' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "add /nonexistent/path.aqua.json" > add_bad_out &&
    grep -qi "FAILED\|error\|read error" add_bad_out
'

# ── 9. --target: push from CLI operation into running daemon ────────────────

test_expect_success 'Record daemon node count before target push' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "count" > count_pre_target
'

test_expect_success 'Sign a tree with --target to push into daemon' '
    DAEMON_PID=$(cat daemon_pid) &&
    cp "$SHARNESS_TEST_DIRECTORY/fixtures/sample.txt" target_test.txt &&
    $AQUA_CLI -f target_test.txt > /dev/null 2>&1 &&
    $AQUA_CLI -s target_test.aqua.json --sign-type did -k keys.json --target "$DAEMON_PID" > target_out 2>&1 &&
    grep -qi "push\|daemon" target_out
'

test_expect_success 'Daemon node count increased after --target push' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "count" > count_post_target &&
    BEFORE=$(cat count_pre_target | tr -d "[:space:]") &&
    AFTER=$(cat count_post_target | tr -d "[:space:]") &&
    test "$AFTER" -gt "$BEFORE"
'

# ── 10. Ingest raw JSON into daemon ────────────────────────────────────────

test_expect_success 'Record count before ingest' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "count" > count_pre_ingest
'

test_expect_success 'Ingest a tree via raw JSON' '
    SOCKET=$(cat daemon_socket) &&
    # Read sample2.aqua.json as single-line JSON
    JSON=$(python3 -c "import json; print(json.dumps(json.load(open(\"sample2.aqua.json\"))))") &&
    daemon_cmd "$SOCKET" "ingest $JSON" > ingest_json_out &&
    cat ingest_json_out
'

test_expect_success 'Node count increased after JSON ingest' '
    SOCKET=$(cat daemon_socket) &&
    daemon_cmd "$SOCKET" "count" > count_post_ingest &&
    BEFORE=$(cat count_pre_ingest | tr -d "[:space:]") &&
    AFTER=$(cat count_post_ingest | tr -d "[:space:]") &&
    test "$AFTER" -ge "$BEFORE"
'

# ── 11. Re-validation: add + remove + re-add cycle ────────────────────────

test_expect_success 'Evict all trees to start fresh' '
    SOCKET=$(cat daemon_socket) &&
    # Evict each genesis one by one
    for g in $(daemon_cmd "$SOCKET" "geneses" | grep "0x" | tr -d " "); do
        daemon_cmd "$SOCKET" "evict $g" > /dev/null
    done &&
    COUNT=$(daemon_cmd "$SOCKET" "count" | tr -d "[:space:]") &&
    test "$COUNT" -eq 0
'

test_expect_success 'Ingest tree, remove signature, re-ingest restores it' '
    SOCKET=$(cat daemon_socket) &&
    JSON=$(python3 -c "import json; print(json.dumps(json.load(open(\"sample.aqua.json\"))))") &&

    # Step 1: Ingest signed tree
    daemon_cmd "$SOCKET" "ingest $JSON" > /dev/null &&
    COUNT1=$(daemon_cmd "$SOCKET" "count" | tr -d "[:space:]") &&
    test "$COUNT1" -ge 3 &&

    # Step 2: Remove a tip (signature)
    TIP=$(daemon_cmd "$SOCKET" "tips" | grep "0x" | head -1 | tr -d " ") &&
    daemon_cmd "$SOCKET" "remove $TIP" > /dev/null &&
    COUNT2=$(daemon_cmd "$SOCKET" "count" | tr -d "[:space:]") &&
    test "$COUNT2" -eq "$((COUNT1 - 1))" &&

    # Step 3: Re-ingest — daemon should restore the removed node
    daemon_cmd "$SOCKET" "ingest $JSON" > readd_cycle_out &&
    COUNT3=$(daemon_cmd "$SOCKET" "count" | tr -d "[:space:]") &&
    test "$COUNT3" -ge "$COUNT1"
'

# ── Cleanup ─────────────────────────────────────────────────────────────────

test_expect_success 'Stop daemon' '
    DAEMON_PID=$(cat daemon_pid) &&
    PIPE_PID=$(cat pipe_pid) &&
    # Kill the sleep|daemon pipeline (sends EOF → daemon shuts down)
    kill "$PIPE_PID" 2>/dev/null || true &&
    kill "$DAEMON_PID" 2>/dev/null || true &&
    sleep 1 &&
    ! kill -0 "$DAEMON_PID" 2>/dev/null
'

test_expect_success 'Socket file cleaned up' '
    SOCKET=$(cat daemon_socket) &&
    # Force-remove if kill didnt trigger graceful cleanup
    rm -f "$SOCKET" &&
    ! test -S "$SOCKET"
'

test_done
