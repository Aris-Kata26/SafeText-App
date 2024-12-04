import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
import bcrypt
import os
import unittest

class SecretMessageApp:
    def __init__(self, master):
        self.master = master
        master.title('Secret Message Encryption/Decryption')
        master.geometry("500x400")

        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)

        # Hashed password (replace with your own securely hashed password)
        self.hashed_password = bcrypt.hashpw(b"secret", bcrypt.gensalt())

        self.setup_ui()

    def setup_ui(self):
        self.text_area = tk.Text(self.master, width=57, height=10)
        self.text_area.pack(pady=10)

        password_label = tk.Label(self.master, text="Enter Your Password:", font=("Helvetica", 14))
        password_label.pack()

        self.password_entry = tk.Entry(self.master, font=("Helvetica", 18), width=35, show="*")
        self.password_entry.pack(pady=10)

        button_frame = tk.Frame(self.master)
        button_frame.pack(pady=20)

        enc_button = tk.Button(button_frame, text="Encrypt", font=("Helvetica", 18), command=self.encrypt)
        enc_button.grid(row=0, column=0)

        dec_button = tk.Button(button_frame, text="Decrypt", font=("Helvetica", 18), command=self.decrypt)
        dec_button.grid(row=0, column=1, padx=20)

        clear_button = tk.Button(button_frame, text="Clear", font=("Helvetica", 18), command=self.clear)
        clear_button.grid(row=0, column=2)

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.hashed_password)

    def encrypt(self):
        secret = self.text_area.get(1.0, tk.END).strip()
        self.text_area.delete(1.0, tk.END)
        
        if self.check_password(self.password_entry.get()):
            try:
                secret = secret.encode("utf-8")
                encrypted_message = self.cipher.encrypt(secret)
                self.text_area.insert(tk.END, encrypted_message.decode("utf-8"))
            except Exception as e:
                messagebox.showerror("Error", f"Encryption failed: {str(e)}")
        else:
            messagebox.showwarning("Incorrect!", "Wrong Password, Try Again!")

    def decrypt(self):
        secret = self.text_area.get(1.0, tk.END).strip()
        self.text_area.delete(1.0, tk.END)
        
        if self.check_password(self.password_entry.get()):
            try:
                secret = secret.encode("utf-8")
                decrypted_message = self.cipher.decrypt(secret)
                self.text_area.insert(tk.END, decrypted_message.decode("utf-8"))
            except Exception as e:
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")
        else:
            messagebox.showwarning("Incorrect!", "Wrong Password, Try Again!")

    def clear(self):
        self.text_area.delete(1.0, tk.END)
        self.password_entry.delete(0, tk.END)

class TestSecretMessageApp(unittest.TestCase):
    def setUp(self):
        self.root = tk.Tk()
        self.app = SecretMessageApp(self.root)

    def test_encryption_decryption(self):
        test_message = "Hello, World!"
        self.app.text_area.insert(tk.END, test_message)
        self.app.password_entry.insert(0, "secret")
        self.app.encrypt()
        encrypted = self.app.text_area.get(1.0, tk.END).strip()
        self.app.text_area.delete(1.0, tk.END)
        self.app.text_area.insert(tk.END, encrypted)
        self.app.decrypt()
        decrypted = self.app.text_area.get(1.0, tk.END).strip()
        self.assertEqual(decrypted, test_message)

    def tearDown(self):
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = SecretMessageApp(root)
    root.mainloop()

    # Uncomment to run tests
    # unittest.main()