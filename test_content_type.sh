#!/bin/bash

echo "🧪 Testing Content Type Validation"
echo "=================================="

echo ""
echo "1️⃣ Testing with VALID file (should work):"
echo "   File: sample.chain.json"
echo "   Expected: Content type detected successfully"
echo "   Command: cargo run -- --sign sample.chain.json --keys-file keys.sample.json"
echo ""

echo "2️⃣ Testing with MALFORMED content (should fail):"
echo "   File: malformed_content.json"
echo "   Expected: Error about missing 'file' or 'text' field"
echo "   Command: cargo run -- --sign malformed_content.json --keys-file keys.sample.json"
echo ""

echo "3️⃣ Testing with MISSING content (should fail):"
echo "   File: missing_content.json"
echo "   Expected: Error about missing 'content' object"
echo "   Command: cargo run -- --sign missing_content.json --keys-file keys.sample.json"
echo ""

echo "4️⃣ Testing with TEXT file (should work):"
echo "   File: sample.txt"
echo "   Expected: Content type detected as Text"
echo "   Command: cargo run -- --file sample.txt"
echo ""

echo ""
echo "🎯 What to Look For:"
echo "   ✅ 'Info : Checking content type before signing...'"
echo "   ✅ 'Info : Content type detected: [File|Text]'"
echo "   ✅ 'Info : Filename: [filename]'"
echo "   ❌ Error messages about missing fields"
echo ""

echo "🚀 Run these commands to test your content type validation!" 