# Pylint Security Hardener

A custom security linter for Python files that detects insecure functions and hardcoded credentials using AST parsing and entropy analysis.

## Features

### 🔍 Insecure Function Detection
- `eval()` - Can execute arbitrary code
- `exec()` - Can execute arbitrary code  
- `os.system()` - Can execute arbitrary shell commands
- `pickle.loads()` - Can execute arbitrary code when loading malicious data

### 🔐 Hardcoded Secret Detection
- API keys and access tokens
- Secret keys and passwords
- High-entropy strings using Shannon entropy analysis
- Common secret patterns (api_key, secret_key, password, token, auth_token)

## Installation

1. Clone or download this repository
2. Ensure you have Python 3.6+ installed
3. No additional dependencies required (uses only standard library)

## Usage

### Command Line

```bash
# Lint a single Python file
python security_linter.py path/to/your/file.py

# Lint an entire directory recursively
python security_linter.py path/to/your/directory/

# Lint current directory
python security_linter.py .
```

### Windsurf Integration

The linter is configured to automatically run on file save for Python files through the `.windsurf/settings.json` configuration.

## Output

The linter provides color-coded severity indicators:

- 🔴 **HIGH** - Critical security issues (insecure functions)
- 🟡 **MEDIUM** - Potential hardcoded secrets
- 🟢 **LOW** - Minor security concerns
- ❌ **ERROR** - File processing errors

## Example Output

```
🚨 Found 4 security issues:
============================================================
1. 🔴 [HIGH] Use of eval() can execute arbitrary code
   📁 File: test_insecure.py
   📍 Line: 8
   💻 Code: eval()

2. 🟡 [MEDIUM] High entropy string detected - possible hardcoded secret
   📁 File: config.py
   📍 Line: 15
   💻 Code: sk-1234567890abcdef1234567890abcdef
```

## Exit Codes

- `0` - No high-severity issues found
- `1` - High-severity security issues or errors detected

## Security Analysis

### Entropy Calculation
The linter uses Shannon entropy to detect high-entropy strings that likely contain secrets:

```python
entropy = -Σ (probability * log₂(probability))
```

Default thresholds:
- `4.0` for secret pattern matches
- `3.5` for general high-entropy strings (minimum 16 characters)

### Pattern Matching
Regular expressions detect common secret patterns:
- `api[_-]?key`, `apikey`
- `secret[_-]?key`, `secretkey`  
- `password`, `pwd`
- `token`, `access[_-]?token`
- `auth[_-]?token`, `authtoken`

## Testing

Run the test files to verify the linter works correctly:

```bash
# Test with insecure code (should find issues)
python security_linter.py test_insecure.py

# Test with safe code (should find no issues)  
python security_linter.py test_safe.py
```

## Configuration

### Windsurf Settings
Edit `.windsurf/settings.json` to customize the auto-run behavior:

```json
{
  "autoRun": {
    "onSave": {
      "patterns": ["*.py"],
      "command": "python security_linter.py ${file}",
      "workingDirectory": ".",
      "showOutput": true,
      "stopOnError": false
    }
  }
}
```

### Customization
Modify `security_linter.py` to:
- Add new insecure functions to `self.insecure_functions`
- Adjust entropy thresholds in `is_high_entropy()`
- Add new secret patterns to `self.secret_patterns`

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## License

This project is open source and available under the MIT License.

## Security Considerations

This tool is designed to help identify potential security issues in code. However:
- It may produce false positives
- It may not catch all security issues
- Always review flagged code manually
- Use alongside other security tools and code reviews
