# import modules
import sys
import getpass
import os
import hashlib
import random
import string
from cryptography.fernet import Fernet


# Print a welcome banner
def print_banner():
    # Print welcome message
    banner = """
    *******************************
    *                             *
    *  Personal Password Manager  *
    *                             *
    *******************************
    """
    print(banner)


print_banner()
# Path for the file to store hashed master password
MASTER_PASSWORD_FILE = "master_password.txt"


def check_password_strength(password):
    # Calculate strength score
    score = 0

    # Award points for length
    length = len(password)
    if length > 12:
        score += 3
    elif length > 8:
        score += 2
    elif length > 6:
        score += 1

    # Award points for presence of
    # lowercase, uppercase, digits and special chars
    if any(char.islower() for char in password):
        score += 1
    if any(char.isupper() for char in password):
        score += 1
    if any(char.isdigit() for char in password):
        score += 1
    if any(char in string.punctuation for char in password):
        score += 1

    return score


# Securely store master password
def store_master_password():
    # Get master password from user
    while True:
        master_password = getpass.getpass("Create a master password: ")
        strength = check_password_strength(master_password)
        if strength < 4:
            print("Weak password. Try again.")
        else:
            break

    confirm_password = getpass.getpass("Confirm your master password: ")

    if master_password != confirm_password:
        print("\033[91m------------MASTER PASSWORDS DO NOT MATCH------------\033[0m")
        sys.exit()

    # Hash using SHA256
    hashed_password = hashlib.sha256(master_password.encode()).hexdigest()

    # Store hash in file
    with open(MASTER_PASSWORD_FILE, "w") as f:
        f.write(hashed_password)

    print("Master password has been set successfully!")


# Verify master password
def verify_master_password(entered_password):
    if not os.path.exists(MASTER_PASSWORD_FILE):
        print("\033[91m------------MASTER PASSWORD HAS NOT BEEN SET------------\033[0m")
        sys.exit()

    hashed_entered_password = hashlib.sha256(entered_password.encode()).hexdigest()

    # Read hashed master password
    with open(MASTER_PASSWORD_FILE, "r") as f:
        hashed_master_password = f.read()

    # Compare entered password
    # Verify correct or not
    if hashed_entered_password != hashed_master_password:
        print("\033[91m------------MASTER PASSWORD IS INCORRECT------------\033[0m")
        sys.exit()

    print("Master password verified successfully!")


# Generate encryption key
def generate_key():
    # Generate new key for encryption
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)


# Load encryption key
def load_key():
    # Load existing key from file
    return open("key.key", "rb").read()


# Encrypt password
def encrypt_password(password, key):
    # Encrypt password using key
    f = Fernet(key)
    encrypted_pass = f.encrypt(password.encode())
    return encrypted_pass


# Decrypt encrypted password
def decrypt_pass(encrypted_pass, key):
    # Decrypt encrypted password
    f = Fernet(key)
    decrypted_pass = f.decrypt(encrypted_pass)
    return decrypted_pass.decode()


# Generate random password
def generate_password(length):
    # Generate random password of given length
    password = ''.join(random.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(length))
    return password


# Store a password
def store_password():
    mst_pass = getpass.getpass("Enter master password: ")
    if master_password != mst_pass:
        print("\033[91m------------MASTER PASSWORD IS INCORRECT------------\033[0m")
        return

    # Get site, username, password
    site: str = input("Enter site-name or email: ")
    username = input("Enter your username: ")
    # getpass.getpass is used as an input, but it will hide the password on terminal which we will enter
    password = getpass.getpass("Enter your password: ")

    if not os.path.exists("key.key"):
        generate_key()

    # Encrypt password and store in file
    key = load_key()
    enc_password = encrypt_password(password, key)
    # open file by using with function
    with open("password.txt", 'a+') as f:
        f.write(f"{site}::{username}::{enc_password.decode()}\n")
        print("!!!!!!!!!!!Password stored successfully!!!!!!!!!")


# Retrieve passwords
def show_password():
    # Let user view decrypted passwords
    mst_pass = getpass.getpass("Enter master password: ")
    if master_password != mst_pass:
        print("\033[91m------------MASTER PASSWORD IS INCORRECT------------\033[0m")
        return
    if not os.path.exists("password.txt"):
        print("\033[91mCurrently no passwords are stored\033[0m")
        return

    key = load_key()
    # opening file password.txt
    with open("password.txt", 'r+') as f:
        # reading whole file at ones so that we can use the lines one by one
        lines = f.readlines()
        for line in lines:
            site, username, encrypt_password1 = line.split("::")
            dec_pass = decrypt_pass(encrypt_password1.encode(), key)
            print("------------------------------------------------------------")
            print(f"SITE = {site}\nUSERNAME = {username}\nPASSWORD = {dec_pass}")
        print("------------------------------------------------------------")


# Main menu
def main(mst_pass):
    # verify master password is present or not
    verify_master_password(mst_pass)
    # Show menu options in loop
    while True:
        print("1. Store a password:")
        print("2. Show password!")
        print("3. Generate random password")
        print("4. Quit")
        # Call appropriate functions
        choice = input("Enter your choice: ")
        if choice == "1":
            store_password()
        if choice == "2":
            show_password()
        if choice == "3":
            password_length = int(input("Enter password length: "))
            password = generate_password(password_length)
            print("Generated Password:", password)
        if choice == "4":
            sys.exit()


if not os.path.exists(MASTER_PASSWORD_FILE):
    store_master_password()
master_password = getpass.getpass("Enter master password: ")
# Start the program
main(master_password)

# created by Atharv sharma
# Github : https://github.com/satharv
