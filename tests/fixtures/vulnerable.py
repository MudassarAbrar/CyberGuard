# This file intentionally contains security vulnerabilities for testing purposes.
# DO NOT use any of the patterns below in production code.

import hashlib
import os
import pickle
import random
import sqlite3
import subprocess

# CWE-259: Hardcoded credentials
PASSWORD = "admin123"  # noqa: S105
API_KEY = "sk-secret-key-12345"  # noqa: S105


# CWE-89: SQL Injection via string concatenation
def get_user(username):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()


# CWE-78: OS Command Injection
def run_command(user_input):
    os.system("ls " + user_input)
    subprocess.run("echo " + user_input, shell=True)  # noqa: S602


# CWE-502: Insecure Deserialization
def load_data(data):
    return pickle.loads(data)  # noqa: S301


# CWE-327: Weak Cryptographic Hash
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # noqa: S324


def hash_password_sha1(password):
    return hashlib.sha1(password.encode()).hexdigest()  # noqa: S324


# CWE-338: Insecure Random
def generate_token():
    return random.randint(0, 1_000_000)  # noqa: S311


# CWE-95: Code Injection via eval
def evaluate_expression(expr):
    return eval(expr)  # noqa: S307


# CWE-215: Debug mode
def start_app(app):
    app.run(debug=True)
