# This file should not trigger any security issues

import os
import pickle

def safe_function():
    # Safe string operations
    name = "John Doe"
    greeting = f"Hello, {name}!"
    
    # Safe math operations
    result = 5 + 3 * 2
    
    # Safe file operations
    with open("safe_file.txt", "w") as f:
        f.write("This is safe content")
    
    # Safe list operations
    numbers = [1, 2, 3, 4, 5]
    total = sum(numbers)
    
    return result, greeting, total

def another_safe_function():
    # Safe configuration without secrets
    config = {
        "host": "localhost",
        "port": 8080,
        "debug": True,
        "timeout": 30
    }
    
    # Safe string with low entropy
    simple_string = "hello_world"
    another_string = "test123"
    
    return config, simple_string, another_string

# Class definition
class SafeClass:
    def __init__(self, value):
        self.value = value
    
    def get_value(self):
        return self.value

# Safe usage of os and pickle modules
def safe_os_usage():
    # Safe os operations
    current_dir = os.getcwd()
    file_exists = os.path.exists("safe_file.txt")
    return current_dir, file_exists

def safe_pickle_usage():
    # Safe pickle operations (using dumps instead of loads)
    data = {"key": "value", "number": 42}
    serialized = pickle.dumps(data)
    return serialized
