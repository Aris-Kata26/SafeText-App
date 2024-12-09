import tkinter as tk  # Importing the tkinter library for GUI
from tkinter import messagebox, filedialog  # Importing specific modules from tkinter
from cryptography.fernet import Fernet, InvalidToken  # Importing Fernet for encryption and InvalidToken for error handling
import bcrypt  # Importing bcrypt for password hashing
import os  # Importing os for file operations
import base64  # Importing base64 for encoding/decoding
import cryptography  # Importing cryptography library

class SafeTextApp:  # Defining the main application class
    def __init__(self, master):  # Constructor method
        self.master = master  # Setting the master window
        master.title('SafeText')  # Setting the window title
        master.geometry("500x450")  # Setting the window size

        self.key = self.load_key()  # Loading the encryption key
        if self.key is None or not self.validate_key(self.key):  # Checking if the key is valid
            self.key = Fernet.generate_key()  # Generating a new key if not valid
            self.save_key()  # Saving the new key
        
        self.cipher = Fernet(self.key)  # Creating a Fernet cipher object

        # Creating a hashed password (in real-world scenarios, this should be stored securely)
        self.hashed_password = bcrypt.hashpw(b"secret", bcrypt.gensalt())

        self.setup_ui()  # Setting up the user interface
        
        # Printing cryptography version for debugging
        print(f"Cryptography version: {cryptography.__version__}")

    def load_key(self):  # Method to load the encryption key
        try:
            with open('encryption_key.key', 'rb') as key_file:  # Opening the key file
                return key_file.read()  # Reading and returning the key
        except FileNotFoundError:
            return None  # Returning None if the file is not found

    def save_key(self):  # Method to save the encryption key
        with open('encryption_key.key', 'wb') as key_file:  # Opening the key file in write mode
            key_file.write(self.key)  # Writing the key to the file

    def validate_key(self, key):  # Method to validate the encryption key
        try:
            decoded = base64.urlsafe_b64decode(key)  # Decoding the key
            return len(decoded) == 32  # Checking if the decoded key is 32 bytes long
        except:
            return False  # Returning False if decoding fails

    def setup_ui(self):  # Method to set up the user interface
        self.text_area = tk.Text(self.master, width=57, height=10)  # Creating a text area
        self.text_area.pack(pady=10)  # Packing the text area with padding

        password_label = tk.Label(self.master, text="Enter Your Password:", font=("Helvetica", 14))  # Creating a label for password entry
        password_label.pack()  # Packing the password label

        self.password_entry = tk.Entry(self.master, font=("Helvetica", 18), width=35, show="*")  # Creating a password entry field
        self.password_entry.pack(pady=10)  # Packing the password entry field

        button_frame = tk.Frame(self.master)  # Creating a frame for buttons
        button_frame.pack(pady=20)  # Packing the button frame

        enc_button = tk.Button(button_frame, text="Encrypt", font=("Helvetica", 18), command=self.encrypt)  # Creating an encrypt button
        enc_button.grid(row=0, column=0)  # Placing the encrypt button in the grid

        dec_button = tk.Button(button_frame, text="Decrypt", font=("Helvetica", 18), command=self.decrypt)  # Creating a decrypt button
        dec_button.grid(row=0, column=1, padx=20)  # Placing the decrypt button in the grid

        clear_button = tk.Button(button_frame, text="Clear", font=("Helvetica", 18), command=self.clear)  # Creating a clear button
        clear_button.grid(row=0, column=2)  # Placing the clear button in the grid

        # Adding buttons for importing and exporting keys
        import_key_button = tk.Button(self.master, text="Import Key", command=self.import_key)  # Creating an import key button
        import_key_button.pack()  # Packing the import key button

        export_key_button = tk.Button(self.master, text="Export Key", command=self.export_key)  # Creating an export key button
        export_key_button.pack()  # Packing the export key button

    def check_password(self, password):  # Method to check the entered password
        return bcrypt.checkpw(password.encode('utf-8'), self.hashed_password)  # Comparing the entered password with the stored hash

    def encrypt(self):  # Method to encrypt the text
        secret = self.text_area.get(1.0, tk.END).strip()  # Getting the text from the text area
        self.text_area.delete(1.0, tk.END)  # Clearing the text area

        if self.check_password(self.password_entry.get()):  # Checking if the entered password is correct
            try:
                secret = secret.encode("utf-8")  # Encoding the secret text
                encrypted_message = self.cipher.encrypt(secret)  # Encrypting the secret
                self.text_area.insert(tk.END, encrypted_message.decode("utf-8"))  # Inserting the encrypted message in the text area
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {str(e)}")  # Showing an error message if encryption fails
        else:
            messagebox.showwarning("Incorrect!", "Wrong Password, Try Again!")  # Showing a warning for incorrect password

    def decrypt(self):  # Method to decrypt the text
        secret = self.text_area.get(1.0, tk.END).strip()  # Getting the encrypted text from the text area
        self.text_area.delete(1.0, tk.END)  # Clearing the text area

        if self.check_password(self.password_entry.get()):  # Checking if the entered password is correct
            try:
                secret = secret.encode("utf-8")  # Encoding the encrypted text
                decrypted_message = self.cipher.decrypt(secret)  # Decrypting the message
                self.text_area.insert(tk.END, decrypted_message.decode("utf-8"))  # Inserting the decrypted message in the text area
            except InvalidToken:
                messagebox.showerror("Error", "Invalid token. The message may be corrupted or the wrong key is being used.")  # Showing an error for invalid token
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")  # Showing an error message if decryption fails
        else:
            messagebox.showwarning("Incorrect!", "Wrong Password, Try Again!")  # Showing a warning for incorrect password

    def clear(self):  # Method to clear the text area and password entry
        self.text_area.delete(1.0, tk.END)  # Clearing the text area
        self.password_entry.delete(0, tk.END)  # Clearing the password entry

    def import_key(self):  # Method to import a key
        file_path = filedialog.askopenfilename(filetypes=[("Key files", "*.key")])  # Opening a file dialog to select a key file
        if file_path:
            with open(file_path, 'rb') as key_file:  # Opening the selected key file
                new_key = key_file.read()  # Reading the new key
            if self.validate_key(new_key):  # Validating the new key
                self.key = new_key  # Setting the new key
                self.cipher = Fernet(self.key)  # Creating a new cipher with the new key
                self.save_key()  # Saving the new key
                messagebox.showinfo("Success", "Key imported successfully")  # Showing a success message
            else:
                messagebox.showerror("Error", "Invalid key file")  # Showing an error for invalid key file

    def export_key(self):  # Method to export the current key
        file_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key files", "*.key")])  # Opening a file dialog to save the key
        if file_path:
            with open(file_path, 'wb') as key_file:  # Opening the file to write the key
                key_file.write(self.key)  # Writing the key to the file
            messagebox.showinfo("Success", "Key exported successfully")  # Showing a success message

if __name__ == "__main__":  # Checking if the script is run directly
    root = tk.Tk()  # Creating the main window
    app = SafeTextApp(root)  # Creating an instance of the SafeTextApp
    root.mainloop()  # Starting the main event loop
