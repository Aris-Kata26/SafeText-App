# SafeText

SafeText is a simple, secure text encryption and decryption application built with Python and Tkinter. It uses the Fernet symmetric encryption scheme from the cryptography library to protect your sensitive information.

## Features

- Encrypt and decrypt text messages
- Password protection for encryption and decryption operations
- Import and export encryption keys
- Simple and intuitive graphical user interface

## Requirements

- Python 3.6+
- tkinter
- cryptography
- bcrypt

## Installation

1. Clone this repository or download the source code.
2. Install the required packages(if they are not yet installed):

pip install cryptography bcrypt

3. Run the application:

python safeText.py


## Usage

1. Launch the application.
2. Enter your text in the main text area.
3. Enter the password in the password field (default is "secret").
4. Click "Encrypt" to encrypt the text or "Decrypt" to decrypt the text.
5. Use the "Clear" button to clear both the text area and password field.
6. You can import or export encryption keys using the respective buttons.

## Security Notes

- The default password is set to "secret". In a real-world scenario, you should implement a secure way to set and store the password.
- The encryption key is stored locally. Ensure you keep this key secure and do not share it.
- Always use strong, unique passwords for best security.

## Contributing

Contributions, issues, and feature requests are welcome. Feel free to check [issues page](https://github.com/yourusername/safetext/issues) if you want to contribute.

## License

[LGK](https://lgk.lu/licenses/bts/)

## Disclaimer

This application is for educational purposes only. While it uses strong encryption, it has not been audited for security and should not be used for storing or transmitting highly sensitive information without further review and enhancements.


