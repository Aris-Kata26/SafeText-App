# SafeText App
This Python application provides a graphical user interface for encrypting and decrypting secret messages using the Fernet symmetric encryption scheme. The app is built using Tkinter for the GUI and incorporates password-based authentication for added security.
## Table of Contents

-[Features]_(Features)
-[Requirements]_(Requirements)
-[Installation]_(Installation)
-[]_()
-[]_()
-[]_()
-[]_()
-[]_()
-[]_()
-[]_()
-[]_()
-[]_()
-[]_()



# Features
Encrypt and decrypt messages using Fernet encryption
Password-protected access to encryption/decryption functions
Simple and intuitive graphical user interface
Built-in unit tests for functionality verification

# Requirements
Python 3.x
tkinter
cryptography
bcrypt

# Installation
Ensure you have Python 3.x installed on your system.
Install the required packages:
bash
pip install cryptography bcrypt

# Usage
To run the application, execute the following command in your terminal:
bash
python secret.py

# How it works
Enter your secret message in the text area.
Input the password in the designated field (default is "secret").
Click "Encrypt" to encrypt the message or "Decrypt" to decrypt an encrypted message.
Use the "Clear" button to reset the text area and password field.

# Security Features
Fernet symmetric encryption for message security
Bcrypt for secure password hashing and verification
Password-protected access to encryption/decryption functions

# Code Structure
The application consists of two main classes:
SecretMessageApp: Handles the GUI and encryption/decryption logic
TestSecretMessageApp: Contains unit tests for the application

# Key Methods
encrypt(): Encrypts the message in the text area
decrypt(): Decrypts the message in the text area
check_password(): Verifies the entered password against the stored hash
clear(): Resets the text area and password field

# Testing
To run the unit tests, uncomment the following line at the end of the script:
python
# unittest.main()
Then execute the script as usual.

# Customization
To change the default password, modify the following line in the __init__ method of SecretMessageApp:
python
self.hashed_password = bcrypt.hashpw(b"your_new_password", bcrypt.gensalt())
Replace "your_new_password" with your desired password.

# Limitations and Security Considerations
The encryption key is generated at runtime and not persisted, meaning encrypted messages cannot be decrypted in subsequent sessions.
The hashed password is hardcoded in the script. For production use, implement a more secure password management system.
Always use strong, unique passwords and keep them confidential.

# License
This project is open-source and available under the MIT License.
