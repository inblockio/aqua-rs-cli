#!/bin/bash

echo "🧪 Testing Aqua CLI v3.2 Features"
echo "=================================="

# Test 1: Help system shows v3.2 features
echo "Test 1: Checking help documentation for v3.2 features..."
if cargo run -- --help 2>/dev/null | grep -q "v3.2"; then
    echo "✅ v3.2 features found in help"
else
    echo "❌ v3.2 features missing from help"
fi

# Test 2: Check if v3.2 arguments are recognized
echo "Test 2: Checking v3.2 argument recognition..."
if cargo run -- --help 2>/dev/null | grep -q "chain link"; then
    echo "✅ Chain link functionality recognized"
else
    echo "❌ Chain link functionality not found"
fi

if cargo run -- --help 2>/dev/null | grep -q "identity form"; then
    echo "✅ Identity form functionality recognized"
else
    echo "❌ Identity form functionality not found"
fi

if cargo run -- --help 2>/dev/null | grep -q "validate-v3"; then
    echo "✅ v3.2 validation functionality recognized"
else
    echo "❌ v3.2 validation functionality not found"
fi

echo ""
echo "🎯 v3.2 Feature Test Complete!"
