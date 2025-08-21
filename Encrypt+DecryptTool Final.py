import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import tkinterdnd2 as tkdnd
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os
import base64
from pathlib import Path

class AESFileEncryptor:
    def __init__(self):
        self.root = tkdnd.Tk()
        self.root.title("AES File Encryptor & Decryptor")
        self.root.geometry("600x800")
        self.root.configure(bg='#f0f0f0')
        
        self.file_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.password = tk.StringVar()
        self.operation = tk.StringVar(value="encrypt")
        self.show_password = tk.BooleanVar(value=False)
        
        self.setup_ui()
        self.setup_drag_drop()
        
    # user interface
    def setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="AES File Encryptor & Decryptor", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Operation selection
        op_frame = ttk.LabelFrame(main_frame, text="Operation", padding="10")
        op_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        
        ttk.Radiobutton(op_frame, text="Encrypt", variable=self.operation, 
                       value="encrypt").grid(row=0, column=0, padx=(0, 20))
        ttk.Radiobutton(op_frame, text="Decrypt", variable=self.operation, 
                       value="decrypt").grid(row=0, column=1)
        
        # File selection area
        file_frame = ttk.LabelFrame(main_frame, text="File Selection", padding="10")
        file_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        
        # Drag and drop UI
        self.drop_area = tk.Frame(file_frame, height=100, bg='#e6f3ff', 
                                 relief='solid', bd=2)
        self.drop_area.grid(row=0, column=0, columnspan=3, sticky=(tk.W, tk.E), 
                           pady=(0, 10))
        
        drop_label = tk.Label(self.drop_area, text="Drag & Drop file here\nor click Browse", 
                             bg='#e6f3ff', font=('Arial', 10))
        drop_label.place(relx=0.5, rely=0.5, anchor='center')
        
        # Input path
        ttk.Label(file_frame, text="Selected File:").grid(row=1, column=0, sticky=tk.W)
        file_entry = ttk.Entry(file_frame, textvariable=self.file_path, width=50, state='readonly')
        file_entry.grid(row=1, column=1, padx=(10, 10), sticky=(tk.W, tk.E))
        
        ttk.Button(file_frame, text="Browse", command=self.browse_file).grid(row=1, column=2)
        
        # Output path
        output_frame = ttk.LabelFrame(main_frame, text="Output Location (Optional)", padding="10")
        output_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        
        ttk.Label(output_frame, text="Output Folder:").grid(row=0, column=0, sticky=tk.W)
        output_entry = ttk.Entry(output_frame, textvariable=self.output_path, width=50, state='readonly')
        output_entry.grid(row=0, column=1, padx=(10, 10), sticky=(tk.W, tk.E))
        
        ttk.Button(output_frame, text="Browse", command=self.browse_output).grid(row=0, column=2)
        
        ttk.Label(output_frame, text="Leave empty to save in same folder as input file", 
                 font=('Arial', 8), foreground='gray').grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=(5, 0))
        
        # Password section
        pass_frame = ttk.LabelFrame(main_frame, text="Password", padding="10")
        pass_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 15))
        
        ttk.Label(pass_frame, text="Password:").grid(row=0, column=0, sticky=tk.W)
        
        # Password entry frame
        pass_entry_frame = ttk.Frame(pass_frame)
        pass_entry_frame.grid(row=0, column=1, padx=(10, 0), sticky=(tk.W, tk.E))
        
        self.pass_entry = ttk.Entry(pass_entry_frame, textvariable=self.password, show="*", width=35)
        self.pass_entry.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        # Show/Hide password button
        self.show_pass_btn = ttk.Button(pass_entry_frame, text="Show", width=7, 
                                       command=self.toggle_password_visibility)
        self.show_pass_btn.grid(row=0, column=1, padx=(5, 0))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=(0, 15))
        
        ttk.Button(button_frame, text="Process File", command=self.process_file,
                  style='Accent.TButton').grid(row=0, column=0, padx=(0, 10))
        ttk.Button(button_frame, text="Clear", command=self.clear_form).grid(row=0, column=1)
        
        # Status/Log area
        log_frame = ttk.LabelFrame(main_frame, text="Status", padding="10")
        log_frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.log_text = tk.Text(log_frame, height=8, width=70, wrap=tk.WORD)
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(6, weight=1)
        file_frame.columnconfigure(1, weight=1)
        output_frame.columnconfigure(1, weight=1)
        pass_frame.columnconfigure(1, weight=1)
        pass_entry_frame.columnconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
    # Configuring drag and drop feature
    def setup_drag_drop(self):
        self.drop_area.drop_target_register(tkdnd.DND_FILES)
        self.drop_area.dnd_bind('<<DropEnter>>', self.on_drop_enter)
        self.drop_area.dnd_bind('<<DropLeave>>', self.on_drop_leave)
        self.drop_area.dnd_bind('<<Drop>>', self.on_drop)
        
    def on_drop_enter(self, event):
        self.drop_area.configure(bg='#cce7ff')
        
    def on_drop_leave(self, event):
        self.drop_area.configure(bg='#e6f3ff')
        
    def on_drop(self, event):
        self.drop_area.configure(bg='#e6f3ff')
        files = self.root.tk.splitlist(event.data)
        if files:
            self.file_path.set(files[0])
            self.log_message(f"File selected: {Path(files[0]).name}")
        
    def browse_output(self):
        folder = filedialog.askdirectory(
            title="Select output folder"
        )
        if folder:
            self.output_path.set(folder)
            self.log_message(f"Output folder selected: {Path(folder).name}")
    
    def browse_file(self):
        filename = filedialog.askopenfilename(
            title="Select file to encrypt/decrypt",
            filetypes=[("All files", "*.*"),
                      ("Text files", "*.txt"),
                      ("Image files", "*.png *.jpg *.jpeg *.gif *.bmp"),
                      ("Document files", "*.pdf *.doc *.docx")]
        )
        if filename:
            self.file_path.set(filename)
            self.log_message(f"File selected: {Path(filename).name}")
    
    def browse_output(self):
        folder = filedialog.askdirectory(
            title="Select output folder"
        )
        if folder:
            self.output_path.set(folder)
            self.log_message(f"Output folder selected: {Path(folder).name}")
    
    def toggle_password_visibility(self):
        if self.show_password.get():
            self.pass_entry.config(show="")
            self.show_pass_btn.config(text="Hide")
            self.show_password.set(False)
        else:
            self.pass_entry.config(show="*")
            self.show_pass_btn.config(text="Show")
            self.show_password.set(True)
    
    # Generate output file path based on input file and operation
    def get_output_path(self, input_file_path: str, operation: str) -> str:
        input_path = Path(input_file_path)
        
        if self.output_path.get():
            # Function to use custom output folder
            output_dir = Path(self.output_path.get())
            if operation == "encrypt":
                output_file = output_dir / (input_path.name + '.encrypted')
            else:
                if input_path.name.endswith('.encrypted'):
                    output_file = output_dir / input_path.name[:-10]  # Remove .encrypted
                else:
                    output_file = output_dir / (input_path.name + '.decrypted')
        else:
            # Function to use same folder if not provided with custom folder
            if operation == "encrypt":
                output_file = input_path.parent / (input_path.name + '.encrypted')
            else:
                if input_path.name.endswith('.encrypted'):
                    output_file = input_path.parent / input_path.name[:-10]  # Remove .encrypted
                else:
                    output_file = input_path.parent / (input_path.name + '.decrypted')
        
        return str(output_file)
    
    # Derive encryption key from password using PBKDF2
    def derive_key(self, password: str, salt: bytes) -> bytes:
        return PBKDF2(password, salt, dkLen=32, count=100000, hmac_hash_module=SHA256)
    
    # Encryption Function
    def encrypt_file(self, file_path: str, password: str) -> bool:
        try:
            # Generate random salt and IV
            salt = get_random_bytes(16)
            iv = get_random_bytes(16)
            
            # Derive key from password
            key = self.derive_key(password, salt)
            
            # Read file content
            with open(file_path, 'rb') as file:
                plaintext = file.read()
            
            # Create AES cipher and encrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_data = pad(plaintext, AES.block_size)
            ciphertext = cipher.encrypt(padded_data)
            
            # Get output path
            encrypted_path = self.get_output_path(file_path, "encrypt")
            
            # Create encrypted file
            with open(encrypted_path, 'wb') as file:
                # Write salt, IV, and ciphertext
                file.write(salt)
                file.write(iv)
                file.write(ciphertext)
            
            self.log_message(f"File encrypted successfully!")
            self.log_message(f"Encrypted file saved as: {Path(encrypted_path).name}")
            self.log_message(f"Full path: {encrypted_path}")
            return True
            
        except Exception as e:
            self.log_message(f"Encryption failed: {str(e)}")
            return False
    
    # File Decryption Function
    def decrypt_file(self, file_path: str, password: str) -> bool:
        try:
            # Read encrypted file
            with open(file_path, 'rb') as file:
                salt = file.read(16)
                iv = file.read(16)
                ciphertext = file.read()

            # Derive key from password
            key = self.derive_key(password, salt)

            # Decrypt ciphertext to plaintext
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(padded_plaintext, AES.block_size)

            # Build decrypted file name: remove .encrypted, add _decrypted, restore original extension
            path = Path(file_path)
            if path.suffix == ".encrypted":
                original_stem = path.stem  
                second_part = Path(original_stem)
                decrypted_name = f"{second_part.stem}_decrypted{second_part.suffix}"
            else:
                decrypted_name = f"{path.stem}_decrypted{path.suffix}"

            output_dir = Path(self.output_path.get()) if self.output_path.get() else path.parent
            decrypted_path = output_dir / decrypted_name

            # Write decrypted content into new file
            with open(decrypted_path, 'wb') as file:
                file.write(plaintext)

            self.log_message("File decrypted successfully!")
            self.log_message(f"Decrypted file saved as: {Path(decrypted_path).name}")
            self.log_message(f"Full path: {decrypted_path}")
            return True
            
        except Exception as e:
            self.log_message(f"Decryption failed: {str(e)}")
            if "Padding is incorrect" in str(e) or "PKCS#7 padding" in str(e):
                self.log_message("This might be due to incorrect password or corrupted file.")
            return False
    
    def process_file(self):
        if not self.file_path.get():
            messagebox.showerror("Error", "Please select a file first.")
            return
        
        if not self.password.get():
            messagebox.showerror("Error", "Please enter a password.")
            return
        
        if not os.path.exists(self.file_path.get()):
            messagebox.showerror("Error", "Selected file does not exist.")
            return
        
        file_path = self.file_path.get()
        password = self.password.get()
        operation = self.operation.get()
        
        self.log_message(f"\n--- Starting {operation}ion ---")
        self.log_message(f"File: {Path(file_path).name}")
        self.log_message(f"Size: {os.path.getsize(file_path)} bytes")
        
        if operation == "encrypt":
            success = self.encrypt_file(file_path, password)
        else:
            success = self.decrypt_file(file_path, password)
        
        if success:
            messagebox.showinfo("Success", f"File {operation}ed successfully!")
        else:
            messagebox.showerror("Error", f"Failed to {operation} file. Check the log for details.")
    
    def clear_form(self):
        self.file_path.set("")
        self.output_path.set("")
        self.password.set("")
        self.pass_entry.config(show="*")
        self.show_pass_btn.config(text="👁")
        self.show_password.set(False)
        self.log_text.delete(1.0, tk.END)
        self.log_message("Form cleared. Ready for new operation.")
    
    def log_message(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        self.root.update()
    
    def run(self):
        self.log_message("AES File Encryptor ready!")
        self.log_message("Supported: Text files, images, documents, and more.")
        self.log_message("Drag & drop files or use Browse button.\n")
        self.root.mainloop()

if __name__ == "__main__":
    app = AESFileEncryptor()
    app.run()