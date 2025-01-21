#!/bin/bash

# Define variables
CLI="./target/debug/aqua-cli"
TEST_FILE="README.md"
LINK_FILE="LICENCE"
LOG_FILE="test_results.log"

# Clear the log file
> $LOG_FILE

# Remove README.aqua.json
[ -f "./README.aqua.json" ] && rm "./README.aqua.json"

# Test: Generate genesis revision
echo "1. Running test: Generate genesis revision" | tee -a $LOG_FILE
OUTPUT=$($CLI --file $TEST_FILE 2>&1)

# Log the output
echo "Command Output:" >> $LOG_FILE
echo "$OUTPUT" >> $LOG_FILE

# Check for 'Successfully' in the output
if [[ "$OUTPUT" == *"Successfully"* ]]; then
    echo "Test Passed: 'Successfully' found in output" | tee -a $LOG_FILE
else
    echo "Test Failed: 'Successfully' not found in output" | tee -a $LOG_FILE
fi

echo "1.1 Running test: Generate genesis revision" | tee -a $LOG_FILE
OUTPUT=$($CLI --file $LINK_FILE 2>&1)

# Log the output
echo "Command Output:" >> $LOG_FILE
echo "$OUTPUT" >> $LOG_FILE

# Check for 'Successfully' in the output
if [[ "$OUTPUT" == *"Successfully"* ]]; then
    echo "Test Passed: 'Successfully' found in output" | tee -a $LOG_FILE
else
    echo "Test Failed: 'Successfully' not found in output" | tee -a $LOG_FILE
fi



# Test: Generate genesis sign revision
echo -e "\n2.1 Running test: Generate Sign revision - CLI" | tee -a $LOG_FILE
OUTPUT=$($CLI --sign ./README.aqua.json --sign-type cli --keys_file ./keys.json 2>&1)

# Log the output
echo "Command Output:" >> $LOG_FILE
echo "$OUTPUT" >> $LOG_FILE

# Check for 'Successfully' in the output
if [[ "$OUTPUT" == *"Successfully"* ]]; then
    echo "Test Passed: 'Successfully' found in output" | tee -a $LOG_FILE
else
    echo "Test Failed: 'Successfully' not found in output" | tee -a $LOG_FILE
fi

echo -e "\n2.2 Running test: Generate Sign revision - DID" | tee -a $LOG_FILE
OUTPUT=$($CLI --sign ./README.aqua.json --sign-type did --keys_file ./keys.json 2>&1)

# Log the output
echo "Command Output:" >> $LOG_FILE
echo "$OUTPUT" >> $LOG_FILE

# Check for 'Successfully' in the output
if [[ "$OUTPUT" == *"Successfully"* ]]; then
    echo "Test Passed: 'Successfully' found in output" | tee -a $LOG_FILE
else
    echo "Test Failed: 'Successfully' not found in output" | tee -a $LOG_FILE
fi

# echo -e "\n2.3 Running test: Generate Sign revision - Metamask" | tee -a $LOG_FILE
# OUTPUT=$($CLI --sign ./README.aqua.json --sign-type metamask --keys_file ./keys.json 2>&1)

# # Log the output
# echo "Command Output:" >> $LOG_FILE
# echo "$OUTPUT" >> $LOG_FILE

# # Check for 'Successfully' in the output
# if [[ "$OUTPUT" == *"Successfully"* ]]; then
#     echo "Test Passed: 'Successfully' found in output" | tee -a $LOG_FILE
# else
#     echo "Test Failed: 'Successfully' not found in output" | tee -a $LOG_FILE
# fi

# Test: Generate genesis sign revision
# echo -e "\n3.1 Running test: Generate witness revision - Eth" | tee -a $LOG_FILE
# OUTPUT=$($CLI --witness ./README.aqua.json --witness-eth 2>&1)

# # Log the output
# echo "Command Output:" >> $LOG_FILE
# echo "$OUTPUT" >> $LOG_FILE

# # Check for 'Successfully' in the output
# if [[ "$OUTPUT" == *"Successfully"* ]]; then
#     echo "Test Passed: 'Successfully' found in output" | tee -a $LOG_FILE
# else
#     echo "Test Failed: 'Successfully' not found in output" | tee -a $LOG_FILE
# fi

echo -e "\n3.2 Running test: Generate witness revision - Nostr" | tee -a $LOG_FILE
OUTPUT=$($CLI --witness ./README.aqua.json --witness-nostr 2>&1)

# Log the output
echo "Command Output:" >> $LOG_FILE
echo "$OUTPUT" >> $LOG_FILE

# Check for 'Successfully' in the output
if [[ "$OUTPUT" == *"Successfully"* ]]; then
    echo "Test Passed: 'Successfully' found in output" | tee -a $LOG_FILE
else
    echo "Test Failed: 'Successfully' not found in output" | tee -a $LOG_FILE
fi


echo -e "\n4 Running test: Generate link revision" | tee -a $LOG_FILE
OUTPUT=$($CLI --link ./README.aqua.json LICENCE.aqua.json  2>&1)

# Log the output
echo "Command Output:" >> $LOG_FILE
echo "$OUTPUT" >> $LOG_FILE

# Check for 'Successfully' in the output
if [[ "$OUTPUT" == *"Successfully"* ]]; then
    echo "Test Passed: 'Successfully' found in output" | tee -a $LOG_FILE
else
    echo "Test Failed: 'Successfully' not found in output" | tee -a $LOG_FILE
fi


# Add more tests as needed
# echo "Adding more tests..." >> $LOG_FILE
# Example: $CLI other commands

echo "All tests completed." | tee -a $LOG_FILE
