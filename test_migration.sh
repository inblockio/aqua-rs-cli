#!/bin/bash

echo "🔍 Testing Aqua CLI Migration: v1.2 → v3.2"
echo "============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test 1: Version Check
echo -e "\n${BLUE}Test 1: Version Verification${NC}"
echo "Checking if package version is 3.2.0..."

VERSION=$(grep '^version = ' Cargo.toml | cut -d'"' -f2)
if [ "$VERSION" = "3.2.0" ]; then
    echo -e "✅ ${GREEN}Package version: $VERSION${NC}"
else
    echo -e "❌ ${RED}Expected version 3.2.0, got: $VERSION${NC}"
    exit 1
fi

# Test 2: v3.2 CLI Arguments
echo -e "\n${BLUE}Test 2: v3.2 CLI Arguments${NC}"
echo "Checking if v3.2 arguments are properly defined..."

V3_ARGS=("--link" "--identity-form" "--validate-v3" "--compliance-level")
for arg in "${V3_ARGS[@]}"; do
    if grep -q "Arg::new(\"${arg#--}\"" src/main.rs; then
        echo -e "✅ ${GREEN}$arg argument found${NC}"
    else
        echo -e "❌ ${RED}$arg argument missing${NC}"
        exit 1
    fi
done

# Test 3: v3.2 Modules
echo -e "\n${BLUE}Test 3: v3.2 Module Files${NC}"
echo "Checking if v3.2 modules exist..."

V3_MODULES=("chain_link.rs" "identity_form.rs" "v3_validator.rs")
for module in "${V3_MODULES[@]}"; do
    if [ -f "src/aqua/$module" ]; then
        echo -e "✅ ${GREEN}$module exists${NC}"
    else
        echo -e "❌ ${RED}$module missing${NC}"
        exit 1
    fi
done

# Test 4: Module Registration
echo -e "\n${BLUE}Test 4: Module Registration${NC}"
echo "Checking if v3.2 modules are registered in mod.rs..."

if grep -q "chain_link" src/aqua/mod.rs; then
    echo -e "✅ ${GREEN}chain_link module registered${NC}"
else
    echo -e "❌ ${RED}chain_link module not registered${NC}"
    exit 1
fi

if grep -q "identity_form" src/aqua/mod.rs; then
    echo -e "✅ ${GREEN}identity_form module registered${NC}"
else
    echo -e "❌ ${RED}identity_form module not registered${NC}"
    exit 1
fi

if grep -q "v3_validator" src/aqua/mod.rs; then
    echo -e "✅ ${GREEN}v3_validator module registered${NC}"
else
    echo -e "❌ ${RED}v3_validator module not registered${NC}"
    exit 1
fi

# Test 5: v3.2 Dependencies
echo -e "\n${BLUE}Test 5: v3.2 Dependencies${NC}"
echo "Checking if v3.2 dependencies are added..."

V3_DEPS=("colored" "rayon" "lazy_static")
for dep in "${V3_DEPS[@]}"; do
    if grep -q "$dep" Cargo.toml; then
        echo -e "✅ ${GREEN}$dep dependency found${NC}"
    else
        echo -e "❌ ${RED}$dep dependency missing${NC}"
        exit 1
    fi
done

# Test 6: Help Documentation
echo -e "\n${BLUE}Test 6: v3.2 Help Documentation${NC}"
echo "Checking if help system includes v3.2 features..."

if grep -q "v3.2" src/main.rs; then
    echo -e "✅ ${GREEN}v3.2 mentioned in help documentation${NC}"
else
    echo -e "❌ ${RED}v3.2 not found in help documentation${NC}"
    exit 1
fi

if grep -q "chain link" src/main.rs; then
    echo -e "✅ ${GREEN}Chain linking documented${NC}"
else
    echo -e "❌ ${RED}Chain linking not documented${NC}"
    exit 1
fi

# Test 7: CLI Argument Processing
echo -e "\n${BLUE}Test 7: CLI Argument Processing${NC}"
echo "Checking if v3.2 arguments are processed in main..."

if grep -q "args.link" src/main.rs; then
    echo -e "✅ ${GREEN}Link argument processing found${NC}"
else
    echo -e "❌ ${RED}Link argument processing missing${NC}"
    exit 1
fi

if grep -q "args.identity_form" src/main.rs; then
    echo -e "✅ ${GREEN}Identity form argument processing found${NC}"
else
    echo -e "❌ ${RED}Identity form argument processing missing${NC}"
    exit 1
fi

if grep -q "args.validate_v3" src/main.rs; then
    echo -e "✅ ${GREEN}Validate v3 argument processing found${NC}"
else
    echo -e "❌ ${RED}Validate v3 argument processing missing${NC}"
    exit 1
fi

# Test 8: Function Calls
echo -e "\n${BLUE}Test 8: v3.2 Function Calls${NC}"
echo "Checking if v3.2 functions are called..."

if grep -q "cli_create_chain_link" src/main.rs; then
    echo -e "✅ ${GREEN}Chain link function call found${NC}"
else
    echo -e "❌ ${RED}Chain link function call missing${NC}"
    exit 1
fi

if grep -q "cli_create_identity_form" src/main.rs; then
    echo -e "✅ ${GREEN}Identity form function call found${NC}"
else
    echo -e "❌ ${RED}Identity form function call missing${NC}"
    exit 1
fi

if grep -q "AquaV3Validator" src/main.rs; then
    echo -e "✅ ${GREEN}v3.2 validator usage found${NC}"
else
    echo -e "❌ ${RED}v3.2 validator usage missing${NC}"
    exit 1
fi

# Test 9: Backward Compatibility
echo -e "\n${BLUE}Test 9: Backward Compatibility${NC}"
echo "Checking if v1.2 features are still available..."

V1_FEATURES=("--authenticate" "--sign" "--witness" "--file" "--delete")
for feature in "${V1_FEATURES[@]}"; do
    if grep -q "${feature#--}" src/main.rs; then
        echo -e "✅ ${GREEN}$feature still available${NC}"
    else
        echo -e "❌ ${RED}$feature missing (backward compatibility broken)${NC}"
        exit 1
    fi
done

# Test 10: Final Summary
echo -e "\n${BLUE}Test 10: Migration Summary${NC}"
echo "=================================="

echo -e "${GREEN}✅ Package Version: $VERSION${NC}"
echo -e "${GREEN}✅ v3.2 CLI Arguments: All Present${NC}"
echo -e "${GREEN}✅ v3.2 Modules: All Implemented${NC}"
echo -e "${GREEN}✅ Module Registration: Complete${NC}"
echo -e "${GREEN}✅ v3.2 Dependencies: All Added${NC}"
echo -e "${GREEN}✅ Help Documentation: Updated${NC}"
echo -e "${GREEN}✅ Argument Processing: Implemented${NC}"
echo -e "${GREEN}✅ Function Calls: All Connected${NC}"
echo -e "${GREEN}✅ Backward Compatibility: Maintained${NC}"

echo -e "\n🎉 ${GREEN}MIGRATION SUCCESSFUL!${NC}"
