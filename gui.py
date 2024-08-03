import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter import ttk
from encryption import generate_key, save_key, load_key, encrypt_message, decrypt_message

KEY_FILE = 'encryption_key.key'

def generate_and_save_key():
    key = generate_key()
    save_key(key, KEY_FILE)
    return key

def load_existing_key():
    try:
        return load_key(KEY_FILE)
    except FileNotFoundError:
        messagebox.showerror("Error", "Key file not found. Please generate a new key.")
        return None

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Text Encryption/Decryption")
        self.key = None

        # Main frame
        self.main_frame = tk.Frame(self.root, padx=20, pady=20)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # Key Handling Frame
        self.key_frame = tk.LabelFrame(self.main_frame, text="Key Management", padx=10, pady=10)
        self.key_frame.pack(fill=tk.X, padx=10, pady=5)

        self.generate_key_button = tk.Button(self.key_frame, text="Generate New Key", command=self.generate_key)
        self.generate_key_button.pack(side=tk.LEFT, padx=5)

        self.load_key_button = tk.Button(self.key_frame, text="Load Existing Key", command=self.load_key)
        self.load_key_button.pack(side=tk.LEFT, padx=5)

        # Encryption Frame
        self.encrypt_frame = tk.LabelFrame(self.main_frame, text="Encryption", padx=10, pady=10)
        self.encrypt_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        tk.Label(self.encrypt_frame, text="Message to Encrypt:").pack(anchor=tk.W, pady=(0, 5))
        self.encrypt_text = scrolledtext.ScrolledText(self.encrypt_frame, height=4, wrap=tk.WORD)
        self.encrypt_text.pack(fill=tk.BOTH, padx=5, pady=(0, 10))

        self.encrypt_button = tk.Button(self.encrypt_frame, text="Encrypt", command=self.encrypt_message)
        self.encrypt_button.pack(pady=5)

        tk.Label(self.encrypt_frame, text="Encrypted Message:").pack(anchor=tk.W, pady=(0, 5))
        self.encrypted_text = scrolledtext.ScrolledText(self.encrypt_frame, height=4, wrap=tk.WORD)
        self.encrypted_text.pack(fill=tk.BOTH, padx=5)

        # Decryption Frame
        self.decrypt_frame = tk.LabelFrame(self.main_frame, text="Decryption", padx=10, pady=10)
        self.decrypt_frame.pack(fill=tk.BOTH, padx=10, pady=5, expand=True)

        tk.Label(self.decrypt_frame, text="Encrypted Message to Decrypt:").pack(anchor=tk.W, pady=(0, 5))
        self.decrypt_text = scrolledtext.ScrolledText(self.decrypt_frame, height=4, wrap=tk.WORD)
        self.decrypt_text.pack(fill=tk.BOTH, padx=5, pady=(0, 10))

        self.decrypt_button = tk.Button(self.decrypt_frame, text="Decrypt", command=self.decrypt_message)
        self.decrypt_button.pack(pady=5)

        tk.Label(self.decrypt_frame, text="Decrypted Message:").pack(anchor=tk.W, pady=(0, 5))
        self.decrypted_text = scrolledtext.ScrolledText(self.decrypt_frame, height=4, wrap=tk.WORD)
        self.decrypted_text.pack(fill=tk.BOTH, padx=5)

    def generate_key(self):
        self.key = generate_and_save_key()
        messagebox.showinfo("Success", "New key generated and saved.")

    def load_key(self):
        self.key = load_existing_key()
        if self.key:
            messagebox.showinfo("Success", "Key loaded successfully.")

    def encrypt_message(self):
        if not self.key:
            messagebox.showerror("Error", "No key found. Please generate or load a key.")
            return
        message = self.encrypt_text.get("1.0", tk.END).strip()
        encrypted_message = encrypt_message(message, self.key)
        self.encrypted_text.delete("1.0", tk.END)
        self.encrypted_text.insert(tk.END, encrypted_message.decode())

    def decrypt_message(self):
        if not self.key:
            messagebox.showerror("Error", "No key found. Please generate or load a key.")
            return
        encrypted_message = self.decrypt_text.get("1.0", tk.END).strip().encode()
        try:
            decrypted_message = decrypt_message(encrypted_message, self.key)
            self.decrypted_text.delete("1.0", tk.END)
            self.decrypted_text.insert(tk.END, decrypted_message)
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
