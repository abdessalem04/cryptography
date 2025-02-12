import tkinter as tk
from tkinter import ttk, messagebox
import ttkbootstrap as tb
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from Crypto.Cipher import DES, DES3, AES, Blowfish, ARC4
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import hashlib
import base64

# ----------------- GÉNÉRATION DES CLÉS -----------------
def generate_keys():
    algo = algo_var.get()
    key_sizes = {
        "AES": 16, "DES": 8, "3DES": 16, "Blowfish": 16, "RC4": 16,
        "Camellia": 16, "Twofish": 16, "CAST-128": 16, "ChaCha20": 32, 
    }
    
    if algo in key_sizes:
        key = get_random_bytes(key_sizes[algo])
        with open(f"{algo.lower()}_key.key", "wb") as key_file:
            key_file.write(key)
        messagebox.showinfo("Clé générée", f"Clé {algo} générée et sauvegardée.")
    
    

# ----------------- CHIFFREMENT -----------------
def encrypt_text():
    algo = algo_var.get()
    text = input_text.get("1.0", tk.END).strip()

    if not text:
        messagebox.showwarning("Attention", "Entrer un texte à chiffrer.")
        return

    key = get_key(f"{algo.lower()}_key.key")
    if not key:
        return

    if algo == "AES":
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(text.encode())
        result = base64.b64encode(cipher.nonce + tag + ciphertext).decode()

    elif algo == "DES":
        cipher = DES.new(key, DES.MODE_ECB)
        result = base64.b64encode(cipher.encrypt(text.ljust(8).encode())).decode()

    elif algo == "3DES":
        cipher = DES3.new(key, DES3.MODE_ECB)
        result = base64.b64encode(cipher.encrypt(text.ljust(16).encode())).decode()

    elif algo == "Blowfish":
        cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        result = base64.b64encode(cipher.encrypt(text.ljust(8).encode())).decode()

    elif algo == "RC4":
        cipher = ARC4.new(key)
        result = base64.b64encode(cipher.encrypt(text.encode())).decode()

    elif algo == "Camellia":
        cipher = Cipher(algorithms.Camellia(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        result = base64.b64encode(encryptor.update(text.ljust(16).encode())).decode()

    elif algo == "Twofish":
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        result = base64.b64encode(encryptor.update(text.ljust(16).encode())).decode()

    elif algo == "CAST-128":
        cipher = Cipher(algorithms.CAST5(key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        result = base64.b64encode(encryptor.update(text.ljust(8).encode())).decode()

    elif algo == "ChaCha20":
        cipher = ChaCha20Poly1305(key)
        nonce = get_random_bytes(12)
        ciphertext = cipher.encrypt(nonce, text.encode(), None)
        result = base64.b64encode(nonce + ciphertext).decode()

    

    

    elif algo == "SHA-256":
        result = hashlib.sha256(text.encode()).hexdigest()

    output_text.delete("1.0", tk.END)
    output_text.insert("1.0", result)
# ----------------- UTILITAIRES -----------------
def get_key(filename):
    try:
        with open(filename, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        messagebox.showerror("Erreur", f"Clé {filename} introuvable.")
        return None

def get_rsa_key(filename):
    try:
        with open(filename, "rb") as key_file:
            return RSA.import_key(key_file.read())
    except FileNotFoundError:
        messagebox.showerror("Erreur", f"Clé {filename} introuvable.")
        return None

# ----------------- INTERFACE GRAPHIQUE -----------------
root = tb.Window(themename="darkly")
root.title("CryptoTool - Multi-Algorithmes")
root.geometry("700x600")

algo_var = tk.StringVar(value="AES")
ttk.Label(root, text="Choisir l'algorithme :", font=("Arial", 12)).pack()
ttk.Combobox(root, textvariable=algo_var, values=[
    "AES", "DES", "3DES", "Blowfish", "RC4", "Camellia", "Twofish", 
    "CAST-128", "ChaCha20"
], state="readonly").pack()

ttk.Label(root, text="Entrée :", font=("Arial", 12)).pack()
input_text = tk.Text(root, height=5, width=80)
input_text.pack()

ttk.Button(root, text="Chiffrer", command=encrypt_text, bootstyle="success").pack(pady=5)
ttk.Button(root, text="Générer Clé", command=generate_keys, bootstyle="info").pack(pady=5)

ttk.Label(root, text="Résultat :", font=("Arial", 12)).pack()
output_text = tk.Text(root, height=5, width=80)
output_text.pack()

root.mainloop()
