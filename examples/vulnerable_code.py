"""
Example file with various security vulnerabilities for testing.
This file intentionally contains security issues for demonstration purposes.
"""

import hashlib
import pickle
import subprocess
import sqlite3


# SQL Injection vulnerabilities
def get_user_unsafe(user_id):
    """Vulnerable to SQL injection via string formatting."""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return database.execute(query)


def search_products_unsafe(search_term):
    """Vulnerable to SQL injection via string concatenation."""
    query = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
    return database.execute(query)


# Cross-Site Scripting (XSS) vulnerabilities  
def render_comment_unsafe(comment):
    """Vulnerable to XSS via unsafe template rendering."""
    from flask import render_template_string
    template = f"<div class='comment'>{comment}</div>"
    return render_template_string(template)


# Weak cryptography
def hash_password_weak(password):
    """Uses weak MD5 hashing algorithm."""
    return hashlib.md5(password.encode()).hexdigest()


def generate_token_weak():
    """Uses weak random number generation."""
    import random
    return str(random.randint(100000, 999999))


# Hardcoded secrets
DATABASE_PASSWORD = "super_secret_password123"
API_KEY = "ak_1234567890abcdef1234567890abcdef"
JWT_SECRET = "my-jwt-secret-key"


def connect_to_database():
    """Contains hardcoded database credentials."""
    connection_string = f"postgresql://user:{DATABASE_PASSWORD}@localhost/mydb"
    return connection_string


# Insecure deserialization
def load_user_data_unsafe(data):
    """Vulnerable to code execution via pickle deserialization."""
    return pickle.loads(data)


# Command injection
def backup_file_unsafe(filename):
    """Vulnerable to command injection."""
    command = f"cp {filename} /backup/"
    subprocess.run(command, shell=True)


# Path traversal
def read_user_file_unsafe(filename):
    """Vulnerable to path traversal attacks."""
    with open(f"/uploads/{filename}", 'r') as f:
        return f.read()


# Unsafe eval usage
def calculate_expression_unsafe(expression):
    """Dangerous use of eval() function."""
    return eval(expression)


# LDAP injection
def authenticate_user_unsafe(username, password):
    """Vulnerable to LDAP injection."""
    import ldap
    filter_str = f"(&(uid={username})(password={password}))"
    # This would be used in LDAP search
    return filter_str


# Safe examples for comparison
def get_user_safe(user_id):
    """Safe parameterized query."""
    query = "SELECT * FROM users WHERE id = ?"
    return database.execute(query, (user_id,))


def hash_password_safe(password):
    """Uses secure SHA-256 hashing."""
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()


def generate_token_safe():
    """Uses cryptographically secure random generation."""
    import secrets
    return secrets.token_urlsafe(32)


if __name__ == "__main__":
    # Test vulnerable functions
    print("This file contains intentional vulnerabilities for testing purposes.")
    print("Do not use these patterns in production code!")