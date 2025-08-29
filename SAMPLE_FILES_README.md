# Sample Files for aqua-cli

This directory contains sample files that can be used to test and demonstrate the aqua-cli functionality.

## Files Included

### 1. keys.sample.json
A sample keys file containing two test keys for signing operations.
- **sample-key-1**: Default key for testing
- **sample-key-2**: Additional key for testing

**Note**: These are sample keys and should NOT be used in production.

### 2. sample.chain.json
A sample aqua chain file that can be used for testing:
- **authenticate** command
- **sign** command  
- **witness** command
- **delete** command

### 3. sample.txt
A sample text document that can be used with the `--file` command to generate a new aqua chain.

## Usage Examples

### Generate a new aqua chain from a document
```bash
aqua-cli --file sample.txt
```

### Sign an existing aqua chain
```bash
aqua-cli --sign sample.chain.json
```

### Witness an aqua chain
```bash
aqua-cli --witness sample.chain.json
```

### Verify/authenticate an aqua chain
```bash
aqua-cli --authenticate sample.chain.json
```

### Delete revisions from an aqua chain
```bash
aqua-cli --delete sample.chain.json
```

## Important Notes

1. **Keys**: The sample keys are for testing only. In production, use your own secure keys.
2. **Chains**: The sample chain contains minimal data and is suitable for testing basic functionality.
3. **Documents**: The sample text file is simple and can be modified for different testing scenarios.

## File Structure

The sample files follow the standard aqua format:
- **keys.json**: Contains cryptographic keys for signing
- **chain.json**: Contains the aqua chain with revisions, signatures, and witnesses
- **txt**: Plain text documents that can be converted to aqua chains

## Testing Workflow

1. Start with `sample.txt` and use `--file` to generate a chain
2. Use the generated chain with `--sign` to add signatures
3. Use `--witness` to add witnesses
4. Use `--authenticate` to verify the chain
5. Use `--delete` to remove revisions if needed

This workflow allows you to test all the major functionality of aqua-cli. 