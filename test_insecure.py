import os
import pickle

# Test insecure functions
def test_insecure_functions():
    # This should be flagged - eval usage
    user_input = "print('hello')"
    eval(user_input)
    
    # This should be flagged - exec usage  
    code = "x = 5"
    exec(code)
    
    # This should be flagged - os.system usage
    os.system("ls -la")
    
    # This should be flagged - pickle.loads usage
    malicious_data = b"..."
    pickle.loads(malicious_data)

# Test hardcoded secrets
API_KEY = "sk-1234567890abcdef1234567890abcdef"  # High entropy API key
SECRET_TOKEN = "abc123def456ghi789jkl012mno345pqr"  # High entropy token
PASSWORD = "MySuperSecretPassword123!"  # Password with high entropy

# Test configuration with secrets
config = {
    "api_key": "AKIAIOSFODNN7EXAMPLE",  # AWS access key pattern
    "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # AWS secret key
    "database_url": "postgresql://user:password123@localhost:5432/db"  # Database URL with password
}

def safe_function():
    # This should not be flagged
    x = 5 + 3
    return x
