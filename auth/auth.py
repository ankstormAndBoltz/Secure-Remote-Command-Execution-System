"""
UPDATED: Authentication module - credential collection.
Authentication verification now happens on the SERVER. This module
handles credential input and prepares login data for the JSON protocol.
"""

import getpass


# UPDATED: Client-side auth now only collects credentials; server does verification
def get_credentials():
    """
    Prompt user for username and password.
    Returns (username, password) tuple.
    Passwords are sent over TLS to server for verification.
    """
    print("=== Secure Remote Client Login ===")
    username = input("Username: ").strip()
    # UPDATED: Use getpass to avoid password echo on screen
    password = getpass.getpass("Password: ")
    return username, password


# UPDATED: Kept for backward compatibility; server performs actual verification
def prompt_login():
    """Prompt for credentials and return (username, password)."""
    return get_credentials()
