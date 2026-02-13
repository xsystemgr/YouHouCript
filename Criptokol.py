#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import base64
import sqlite3
import struct
import time
from dataclasses import dataclass
from typing import Optional

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from tkinter.scrolledtext import ScrolledText

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

# =========================
# Crypto (AES-256-GCM + scrypt)
# =========================
MAGIC = b"SBX1"
VERSION = 1

SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1

SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32

@dataclass
class Container:
    salt: bytes
    nonce: bytes
    ciphertext: bytes

def _kdf_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Empty password is not allowed.")
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))

def _pack_container(salt: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    header = MAGIC + struct.pack("BBBB", VERSION, len(salt), len(nonce), 0)
    body = salt + nonce + struct.pack(">I", len(ciphertext)) + ciphertext
    return header + body

def _unpack_container(blob: bytes) -> Container:
    if len(blob) < 8:
        raise ValueError("Invalid container (too short).")
    if blob[:4] != MAGIC:
        raise ValueError("Invalid container (bad magic).")
    ver, salt_len, nonce_len, _ = struct.unpack("BBBB", blob[4:8])
    if ver != VERSION:
        raise ValueError(f"Unsupported container version: {ver}")

    off = 8
    if len(blob) < off + salt_len + nonce_len + 4:
        raise ValueError("Invalid container (truncated).")

    salt = blob[off:off+salt_len]; off += salt_len
    nonce = blob[off:off+nonce_len]; off += nonce_len
    (ct_len,) = struct.unpack(">I", blob[off:off+4]); off += 4
    if len(blob) < off + ct_len:
        raise ValueError("Invalid container (truncated ciphertext).")
    ct = blob[off:off+ct_len]
    return Container(salt=salt, nonce=nonce, ciphertext=ct)

def encrypt_bytes(plaintext: bytes, password: str, aad: Optional[bytes] = None) -> bytes:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _kdf_key(password, salt)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return _pack_container(salt, nonce, ct)

def decrypt_bytes(container_blob: bytes, password: str, aad: Optional[bytes] = None) -> bytes:
    c = _unpack_container(container_blob)
    key = _kdf_key(password, c.salt)
    return AESGCM(key).decrypt(c.nonce, c.ciphertext, aad)

# =========================
# DB (SQLite)
# =========================
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "securebox.db")

def db_init():
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS vault_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            item_type TEXT NOT NULL,          -- 'msg' or 'file'
            title TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            aad TEXT,
            blob BLOB NOT NULL                -- encrypted container bytes
        );
        """)
        con.execute("CREATE INDEX IF NOT EXISTS idx_vault_created ON vault_items(created_at DESC);")
        con.commit()

def db_add(item_type: str, title: str, aad: Optional[str], blob: bytes):
    with sqlite3.connect(DB_PATH) as con:
        con.execute(
            "INSERT INTO vault_items(item_type, title, created_at, aad, blob) VALUES(?,?,?,?,?)",
            (item_type, title, int(time.time()), aad, sqlite3.Binary(blob))
        )
        con.commit()

def db_list():
    with sqlite3.connect(DB_PATH) as con:
        cur = con.execute("SELECT id, item_type, title, created_at, aad FROM vault_items ORDER BY created_at DESC")
        return cur.fetchall()

def db_get_blob(item_id: int):
    with sqlite3.connect(DB_PATH) as con:
        cur = con.execute("SELECT item_type, title, aad, blob FROM vault_items WHERE id=?", (item_id,))
        row = cur.fetchone()
        return row

# =========================
# UI
# =========================
class SecureBoxUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SecureBox (UI + Embedded DB)")
        self.geometry("980x650")

        self._build()
        self.refresh_list()

    def _build(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Password:").pack(side="left")
        self.password_var = tk.StringVar()
        self.pwd_entry = ttk.Entry(top, textvariable=self.password_var, show="*", width=30)
        self.pwd_entry.pack(side="left", padx=8)

        ttk.Label(top, text="AAD (optional context):").pack(side="left", padx=(20, 0))
        self.aad_var = tk.StringVar()
        self.aad_entry = ttk.Entry(top, textvariable=self.aad_var, width=30)
        self.aad_entry.pack(side="left", padx=8)

        mid = ttk.Panedwindow(self, orient="horizontal")
        mid.pack(fill="both", expand=True, padx=10, pady=10)

        # Left: list
        left = ttk.Frame(mid, padding=10)
        mid.add(left, weight=1)

        ttk.Label(left, text="Vault Items").pack(anchor="w")
        self.tree = ttk.Treeview(left, columns=("id","type","title","created","aad"), show="headings", height=18)
        for col, w in [("id",60),("type",70),("title",300),("created",160),("aad",180)]:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=w, anchor="w")
        self.tree.pack(fill="both", expand=True, pady=8)

        btns = ttk.Frame(left)
        btns.pack(fill="x")

        ttk.Button(btns, text="Refresh", command=self.refresh_list).pack(side="left")
        ttk.Button(btns, text="Decrypt Selected", command=self.decrypt_selected).pack(side="left", padx=8)

        # Right: actions
        right = ttk.Frame(mid, padding=10)
        mid.add(right, weight=1)

        ttk.Label(right, text="New Message").pack(anchor="w")
        self.msg_title = tk.StringVar(value="message")
        row1 = ttk.Frame(right)
        row1.pack(fill="x", pady=(6, 0))
        ttk.Label(row1, text="Title:").pack(side="left")
        ttk.Entry(row1, textvariable=self.msg_title, width=40).pack(side="left", padx=8)

        self.msg_text = ScrolledText(right, height=10)
        self.msg_text.pack(fill="both", expand=False, pady=8)

        ttk.Button(right, text="Encrypt & Save Message to DB", command=self.save_message).pack(anchor="w", pady=(0, 12))

        ttk.Separator(right).pack(fill="x", pady=10)

        ttk.Label(right, text="File Encryption").pack(anchor="w")
        filebtns = ttk.Frame(right)
        filebtns.pack(fill="x", pady=8)

        ttk.Button(filebtns, text="Encrypt File → Save to DB", command=self.encrypt_file_to_db).pack(side="left")
        ttk.Button(filebtns, text="Decrypt Selected File Item → Save As...", command=self.decrypt_selected_file_to_disk).pack(side="left", padx=8)

        ttk.Separator(right).pack(fill="x", pady=10)

        ttk.Label(right, text="Decrypted Output").pack(anchor="w")
        self.out = ScrolledText(right, height=12)
        self.out.pack(fill="both", expand=True, pady=8)

    def _require_password(self) -> str:
        pwd = self.password_var.get().strip()
        if not pwd:
            messagebox.showerror("Missing password", "Βάλε password.")
            raise RuntimeError("missing password")
        return pwd

    def refresh_list(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        rows = db_list()
        for (item_id, item_type, title, created_at, aad) in rows:
            created_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(created_at))
            self.tree.insert("", "end", values=(item_id, item_type, title, created_str, aad or ""))

    def save_message(self):
        try:
            pwd = self._require_password()
            title = self.msg_title.get().strip() or "message"
            aad = self.aad_var.get().strip() or None
            plaintext = self.msg_text.get("1.0", "end").rstrip("\n").encode("utf-8")
            if not plaintext:
                messagebox.showwarning("Empty", "Γράψε μήνυμα πρώτα.")
                return
            blob = encrypt_bytes(plaintext, pwd, aad.encode("utf-8") if aad else None)
            db_add("msg", title, aad, blob)
            self.msg_text.delete("1.0", "end")
            self.refresh_list()
            messagebox.showinfo("OK", "Message αποθηκεύτηκε κρυπτογραφημένο στη DB.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _get_selected_id(self) -> Optional[int]:
        sel = self.tree.selection()
        if not sel:
            return None
        vals = self.tree.item(sel[0], "values")
        return int(vals[0])

    def decrypt_selected(self):
        try:
            item_id = self._get_selected_id()
            if item_id is None:
                messagebox.showwarning("Select", "Διάλεξε item.")
                return
            pwd = self._require_password()

            row = db_get_blob(item_id)
            if not row:
                messagebox.showerror("Not found", "Δεν βρέθηκε item.")
                return
            item_type, title, aad, blob = row
            aad_bytes = aad.encode("utf-8") if aad else None
            pt = decrypt_bytes(blob, pwd, aad_bytes)

            self.out.delete("1.0", "end")
            if item_type == "msg":
                self.out.insert("end", pt.decode("utf-8", errors="replace"))
            else:
                self.out.insert("end", f"[FILE ITEM]\nTitle: {title}\nSize: {len(pt)} bytes\n(Use 'Decrypt Selected File Item → Save As...')\n")
        except Exception as e:
            messagebox.showerror("Decrypt failed", f"{e}")

    def encrypt_file_to_db(self):
        try:
            pwd = self._require_password()
            path = filedialog.askopenfilename(title="Select file to encrypt")
            if not path:
                return
            aad = self.aad_var.get().strip() or None

            with open(path, "rb") as f:
                data = f.read()

            blob = encrypt_bytes(data, pwd, aad.encode("utf-8") if aad else None)
            title = os.path.basename(path)
            db_add("file", title, aad, blob)
            self.refresh_list()
            messagebox.showinfo("OK", f"File '{title}' αποθηκεύτηκε κρυπτογραφημένο στη DB.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_selected_file_to_disk(self):
        try:
            item_id = self._get_selected_id()
            if item_id is None:
                messagebox.showwarning("Select", "Διάλεξε file item.")
                return

            row = db_get_blob(item_id)
            if not row:
                messagebox.showerror("Not found", "Δεν βρέθηκε item.")
                return

            item_type, title, aad, blob = row
            if item_type != "file":
                messagebox.showwarning("Not a file", "Το επιλεγμένο item δεν είναι file.")
                return

            pwd = self._require_password()
            aad_bytes = aad.encode("utf-8") if aad else None
            data = decrypt_bytes(blob, pwd, aad_bytes)

            save_path = filedialog.asksaveasfilename(title="Save decrypted file as...", initialfile=title)
            if not save_path:
                return
            with open(save_path, "wb") as f:
                f.write(data)

            messagebox.showinfo("OK", f"Αποθηκεύτηκε: {save_path}")
        except Exception as e:
            messagebox.showerror("Decrypt failed", str(e))


def main():
    db_init()
    app = SecureBoxUI()
    app.mainloop()

if __name__ == "__main__":
    main()
