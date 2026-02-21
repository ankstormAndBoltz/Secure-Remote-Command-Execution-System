import hashlib

# Function to hash password
def hash_password(password):
    sha_signature = hashlib.sha256(password.encode()).hexdigest()
    return sha_signature


# Function to verify password
def verify_password(input_password, stored_hash):
    return hash_password(input_password) == stored_hash


# Testing
if __name__ == "__main__":
    pwd = input("Enter password: ")
    hashed = hash_password(pwd)

    print("Hashed Password:", hashed)

    check = input("Re-enter password to verify: ")

    if verify_password(check, hashed):
        print("Password Matched ")
    else:
        print("Wrong Password ")
