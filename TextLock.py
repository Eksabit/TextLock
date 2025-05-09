import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import secrets

class AESCipher:
    def __init__(self, password, salt=None):
        if salt is None:
            self.salt = secrets.token_bytes(16)
        else:
            self.salt = salt
        self.key = self.derive_key(password)

    def derive_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt(self, data):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()
        encryptor = cipher.encryptor()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        return base64.b64encode(iv).decode('utf-8'), base64.b64encode(ct).decode('utf-8'), base64.b64encode(self.salt).decode('utf-8')

    def decrypt(self, iv, ct):
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ct)
        self.key = self.derive_key(self.salt)

        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ct) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        return unpadder.update(padded_data) + unpadder.finalize()

class App:
    def __init__(self, master):
        self.master = master
        master.title("AES-256 File Encryptor")
        master.geometry("400x300")
        master.configure(bg='#f0f0f0')

        self.label = tk.Label(master, text="Введите пароль для шифрования/дешифрования:", bg='#f0f0f0')
        self.label.pack(pady=10)

        self.password_entry = tk.Entry(master, show='*')
        self.password_entry.pack(pady=5)

        self.key_length_label = tk.Label(master, text="Длина ключа шифрования: 0 бит", bg='#f0f0f0')
        self.key_length_label.pack(pady=5)

        self.password_entry.bind("<KeyRelease>", self.update_key_length)

        self.select_button = tk.Button(master, text="Выбрать файл", command=self.select_file, bg='#4CAF50', fg='white')
        self.select_button.pack(pady=10)

        self.selected_file_label = tk.Label(master, text="Выбранный файл: None", bg='#f0f0f0')
        self.selected_file_label.pack(pady=5)

        self.encrypt_button = tk.Button(master, text="Зашифровать", command=self.encrypt_file, bg='#ff9800', fg='white')
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = tk.Button(master, text="Расшифровать", command=self.decrypt_file, bg='#f44336', fg='white')
        self.decrypt_button.pack(pady=5)

        self.file_path = ""

    def update_key_length(self, event):
        password = self.password_entry.get()
        if password:
            key_length = len(PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=secrets.token_bytes(16),
                iterations=100000
                backend=default_backend()
            ).derive(password.encode())) * 8  # Длина в битах
            self.key_length_label.config(text=f"Длина ключа шифрования: {key_length} бит")
        else:
            self.key_length_label.config(text="Длина ключа шифрования: 0 бит")

    def select_file(self):
        self.file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if self.file_path:
            self.selected_file_label.config(text=f"Выбранный файл: {os.path.basename(self.file_path)}")

    def encrypt_file(self):
        if not self.file_path:
            messagebox.showwarning("Ошибка", "Сначала выберите файл.")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Ошибка", "Введите пароль.")
            return

        # Проверяем, зашифрован ли файл
        with open(self.file_path, 'r') as file:
            lines = file.readlines()
            if len(lines) >= 3:
                messagebox.showwarning("Ошибка",
                                       "Файл уже зашифрован. Пожалуйста, расшифруйте его перед повторным шифрованием.")
                return

        with open(self.file_path, 'r') as file:
            data = file.read()

        cipher = AESCipher(password)
        iv, ct, salt = cipher.encrypt(data)

        # Сохраняем зашифрованные данные в том же файле
        with open(self.file_path, 'w') as file:
            file.write(f"{salt}\n{iv}\n{ct}")

        messagebox.showinfo("Успех", "Файл успешно зашифрован!")

    def decrypt_file(self):
        if not self.file_path:
            messagebox.showwarning("Ошибка", "Сначала выберите файл.")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Ошибка", "Введите пароль.")
            return

        with open(self.file_path, 'r') as file:
            lines = file.readlines()
            if len(lines) < 3:
                messagebox.showerror("Ошибка", "Файл не содержит необходимых данных для расшифровки.")
                return

            salt = lines[0].strip()
            iv = lines[1].strip()
            ct = lines[2].strip()

        cipher = AESCipher(password, salt=base64.b64decode(salt))
        try:
            decrypted_data = cipher.decrypt(iv, ct)

            # Сохраняем расшифрованные данные в том же файле
            with open(self.file_path, 'w') as file:
                file.write(decrypted_data.decode('utf-8'))

            messagebox.showinfo("Успех", "Файл успешно расшифрован!")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Не удалось расшифровать файл: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
