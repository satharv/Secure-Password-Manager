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
Install requirements:
```
cd Secure-Password-Manager-main
pip install -r requirements.txt
```
Run
```
python .\pass_manage.py
```

### Requirements
The main dependencies are:

- ```cryptography``` - Used for the Fernet symmetric encryption
- ```getpass``` - For securely getting password input
- ```hashlib``` - For hashing the master password
- ```os``` - For file operations like checking file exists
- ```random``` - For generating random passwords
- ```string``` - For characters used in random password
- ```sys``` - For exiting the program

## Contributing
Contributions to adding new features, enhancing security, and improving code quality are welcome!

Please submit a pull request with proposed changes.
