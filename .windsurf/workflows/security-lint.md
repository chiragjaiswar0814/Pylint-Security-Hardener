---
description: Run security linter on Python files
---

# Security Linter Workflow

This workflow runs the custom security linter on Python files to detect insecure functions and hardcoded credentials.

## Steps:

1. Navigate to the project directory
2. Run the security linter on the specified file or directory
3. Display results with severity indicators

## Usage:

- To lint a specific file: `python security_linter.py path/to/file.py`
- To lint entire directory: `python security_linter.py .`
- The linter will automatically run on file save when configured in Windsurf settings

## Security Checks Performed:

- **Insecure Functions**: Detects usage of eval(), exec(), os.system(), pickle.loads()
- **Hardcoded Secrets**: Identifies API keys, passwords, tokens using entropy analysis
- **High Entropy Strings**: Flags suspicious high-entropy strings that might be secrets

## Exit Codes:

- 0: No high-severity issues found
- 1: High-severity security issues or errors detected
