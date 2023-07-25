# Secure-Password-Manager

This is a secure password manager application written in Python. It allows you to store passwords encrypted using strong cryptography, so you can keep all your passwords safe in one place without worrying about security.

## Features

- Secure master password with enforced complexity requirements
- Passwords encrypted using Fernet symmetric encryption
- Hashed master password stored for verification
- Generate strong random passwords
- Simple menu interface to store/retrieve passwords

## Usage

The password manager has an easy-to-use menu:
1. Set a master password, which is hashed and stored for verification.
2. Choose to store a new password - you will be prompted for site/username/password. The password is encrypted before storing.
3. Retrieve stored passwords - re-enter the master password and decrypted passwords are displayed.
4. Generate a random strong password.
5. Quit when done.

The encrypted passwords are stored in a local file. The master password hash and encryption key are also stored locally. For additional security, these can be stored remotely.

## Installation

Requires Python 3.x
Clone the repo
```
git clone https://github.com/satharv/Secure-Password-Manager.git
```

Run:
```
pip install -r requirements.txt
```

### Requirements
The main dependencies are:

- ```cryptography``` - Used for the Fernet symmetric encryption

## Contributing
Contributions to add new features, enhance security, improve code quality are welcome!

Please submit a pull request with proposed changes.
