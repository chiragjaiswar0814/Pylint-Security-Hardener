#!/usr/bin/env python3
"""
Security Linter for Python Files
Detects insecure functions and hardcoded credentials using AST parsing.
"""

import ast
import re
import sys
import os
import math
from pathlib import Path
from typing import List, Dict, Any, Tuple


class SecurityLinter:
    def __init__(self):
        self.insecure_functions = {
            'eval': 'Use of eval() can execute arbitrary code',
            'exec': 'Use of exec() can execute arbitrary code', 
            'os.system': 'Use of os.system() can execute arbitrary shell commands',
            'pickle.loads': 'Use of pickle.loads() can execute arbitrary code when loading malicious data'
        }
        
        # High entropy patterns for detecting hardcoded secrets
        self.secret_patterns = [
            r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
            r'(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
            r'(?i)(password|pwd)\s*[:=]\s*["\']([a-zA-Z0-9]{8,})["\']',
            r'(?i)(token|access[_-]?token)\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
            r'(?i)(auth[_-]?token|authtoken)\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
        ]
        
        self.issues = []
    
    def calculate_entropy(self, string: str) -> float:
        """Calculate Shannon entropy of a string to detect high-entropy secrets."""
        if not string:
            return 0.0
        
        # Count character frequencies
        char_counts = {}
        for char in string:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        string_len = len(string)
        
        for count in char_counts.values():
            probability = count / string_len
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def is_high_entropy(self, string: str, threshold: float = 4.0) -> bool:
        """Check if a string has high entropy (likely a secret)."""
        return self.calculate_entropy(string) >= threshold
    
    def check_hardcoded_secrets(self, node: ast.Constant, file_path: str, line_num: int):
        """Check for hardcoded secrets in string constants."""
        if isinstance(node.value, str):
            # Check against known secret patterns
            for pattern in self.secret_patterns:
                matches = re.finditer(pattern, node.value)
                for match in matches:
                    secret_value = match.group(2) if len(match.groups()) >= 2 else match.group(1)
                    if self.is_high_entropy(secret_value):
                        self.issues.append({
                            'type': 'hardcoded_secret',
                            'file': file_path,
                            'line': line_num,
                            'message': f'Potential hardcoded secret detected: {match.group(1)}',
                            'severity': 'high',
                            'code': node.value
                        })
            
            # Check for high entropy strings that might be secrets
            if len(node.value) >= 16 and self.is_high_entropy(node.value, 3.5):
                # Only flag if it looks like a secret (contains mix of letters, numbers, symbols)
                if (re.search(r'[a-zA-Z]', node.value) and 
                    re.search(r'[0-9]', node.value) and 
                    len(set(node.value)) >= 8):
                    self.issues.append({
                        'type': 'high_entropy_string',
                        'file': file_path,
                        'line': line_num,
                        'message': 'High entropy string detected - possible hardcoded secret',
                        'severity': 'medium',
                        'code': node.value[:50] + '...' if len(node.value) > 50 else node.value
                    })
    
    def check_insecure_function_call(self, node: ast.Call, file_path: str, line_num: int):
        """Check for calls to insecure functions."""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in ['eval', 'exec']:
                self.issues.append({
                    'type': 'insecure_function',
                    'file': file_path,
                    'line': line_num,
                    'message': self.insecure_functions[func_name],
                    'severity': 'high',
                    'code': func_name + '()'
                })
        
        elif isinstance(node.func, ast.Attribute):
            # Handle module.function calls like os.system, pickle.loads
            if isinstance(node.func.value, ast.Name):
                module_name = node.func.value.id
                func_name = node.func.attr
                full_name = f"{module_name}.{func_name}"
                
                if full_name in self.insecure_functions:
                    self.issues.append({
                        'type': 'insecure_function',
                        'file': file_path,
                        'line': line_num,
                        'message': self.insecure_functions[full_name],
                        'severity': 'high',
                        'code': full_name + '()'
                    })
    
    def visit_node(self, node, file_path: str):
        """Visit AST nodes and check for security issues."""
        line_num = getattr(node, 'lineno', 0)
        
        # Check for insecure function calls
        if isinstance(node, ast.Call):
            self.check_insecure_function_call(node, file_path, line_num)
        
        # Check for hardcoded secrets in string constants
        elif isinstance(node, ast.Constant):
            self.check_hardcoded_secrets(node, file_path, line_num)
        
        # Recursively visit child nodes
        for child in ast.iter_child_nodes(node):
            self.visit_node(child, file_path)
    
    def lint_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Lint a single Python file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            tree = ast.parse(content, filename=file_path)
            self.visit_node(tree, file_path)
            
        except SyntaxError as e:
            self.issues.append({
                'type': 'syntax_error',
                'file': file_path,
                'line': e.lineno or 0,
                'message': f'Syntax error: {e.msg}',
                'severity': 'error',
                'code': ''
            })
        except Exception as e:
            self.issues.append({
                'type': 'error',
                'file': file_path,
                'line': 0,
                'message': f'Error processing file: {str(e)}',
                'severity': 'error',
                'code': ''
            })
        
        return self.issues
    
    def lint_directory(self, directory: str) -> List[Dict[str, Any]]:
        """Lint all Python files in a directory recursively."""
        self.issues = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    self.lint_file(file_path)
        
        return self.issues
    
    def print_issues(self, issues: List[Dict[str, Any]]):
        """Print found issues in a formatted way."""
        if not issues:
            print("✅ No security issues found!")
            return
        
        print(f"🚨 Found {len(issues)} security issues:")
        print("=" * 60)
        
        for i, issue in enumerate(issues, 1):
            severity_icon = {
                'high': '🔴',
                'medium': '🟡', 
                'low': '🟢',
                'error': '❌'
            }.get(issue['severity'], '⚪')
            
            print(f"{i}. {severity_icon} [{issue['severity'].upper()}] {issue['message']}")
            print(f"   📁 File: {issue['file']}")
            print(f"   📍 Line: {issue['line']}")
            if issue.get('code'):
                print(f"   💻 Code: {issue['code']}")
            print()


def main():
    """Main function to run the security linter."""
    linter = SecurityLinter()
    
    if len(sys.argv) < 2:
        print("Usage: python security_linter.py <file_or_directory>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    if os.path.isfile(target):
        if not target.endswith('.py'):
            print("Error: Please provide a Python file (.py)")
            sys.exit(1)
        issues = linter.lint_file(target)
    elif os.path.isdir(target):
        issues = linter.lint_directory(target)
    else:
        print(f"Error: {target} is not a valid file or directory")
        sys.exit(1)
    
    linter.print_issues(issues)
    
    # Exit with error code if issues found
    if any(issue['severity'] in ['high', 'error'] for issue in issues):
        sys.exit(1)


if __name__ == "__main__":
    main()
