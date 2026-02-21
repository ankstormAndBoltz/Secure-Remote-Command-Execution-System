import hashlib
import os

# Get absolute path of this file's directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Absolute path to users.txt
USER_DB = os.path.join(BASE_DIR, "users.txt")


# ---------------- HASH FUNCTION ----------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


# ---------------- REGISTER USER ----------------
def register_user(username, password):
    hashed = hash_password(password)

    with open(USER_DB, "a") as file:
        file.write(f"{username}:{hashed}\n")


# ---------------- VERIFY USER ----------------
def verify_user(username, password):
    if not os.path.exists(USER_DB):
        return False

    hashed = hash_password(password)

    with open(USER_DB, "r") as file:
        for line in file:
            stored_user, stored_hash = line.strip().split(":")
            if stored_user == username and stored_hash == hashed:
                return True

    return False

