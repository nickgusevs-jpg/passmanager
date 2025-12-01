# password_manager.py
import json
import os
import base64
import secrets
import string
import hashlib
from tkinter import *
from tkinter import ttk, messagebox, simpledialog
from cryptography.fernet import Fernet
from hashlib import pbkdf2_hmac

# ========== Константы файлов ==========
MASTER_FILE = "master.json"   # хранит salt и hash мастер-пароля
VAULT_FILE = "vault.enc"      # зашифрованное хранилище (json)

# ========== Утилиты крипто ==========
def derive_key(password: str, salt: bytes, iterations: int = 390000) -> bytes:
    """
    Производим PBKDF2-HMAC-SHA256 и возвращаем urlsafe base64-ключ для Fernet.
    iterations по умолчанию достаточно большое значение для современных ПК.
    """
    k = pbkdf2_hmac("sha256", password.encode(), salt, iterations, dklen=32)
    return base64.urlsafe_b64encode(k)

def create_master(master_password: str):
    """Создаём запись мастер-пароля: сохраняем salt и salted hash (для проверки)."""
    salt = secrets.token_bytes(16)
    key = derive_key(master_password, salt)
    # Для проверки можно хранить хеш пароля (kdf output) отдельно (в base64)
    hash_b64 = base64.urlsafe_b64encode(pbkdf2_hmac("sha256", master_password.encode(), salt, 1)).decode()
    data = {"salt": base64.b64encode(salt).decode(), "hash": hash_b64}
    with open(MASTER_FILE, "w") as f:
        json.dump(data, f)
    return key

def verify_master(master_password: str):
    """Проверяем мастер-пароль и возвращаем ключ для шифрования при успехе."""
    if not os.path.exists(MASTER_FILE):
        return None
    with open(MASTER_FILE, "r") as f:
        data = json.load(f)
    salt = base64.b64decode(data["salt"])
    # Проверочный хеш (мы хранем pbkdf2_hmac(..., iterations=1) как упрощенный чек)
    check_hash = base64.urlsafe_b64encode(pbkdf2_hmac("sha256", master_password.encode(), salt, 1)).decode()
    if secrets.compare_digest(check_hash, data["hash"]):
        return derive_key(master_password, salt)
    return None

def encrypt_vault(key: bytes, vault_data: dict):
    f = Fernet(key)
    raw = json.dumps(vault_data).encode()
    token = f.encrypt(raw)
    with open(VAULT_FILE, "wb") as f_out:
        f_out.write(token)

def decrypt_vault(key: bytes):
    if not os.path.exists(VAULT_FILE):
        return {}
    f = Fernet(key)
    try:
        with open(VAULT_FILE, "rb") as f_in:
            token = f_in.read()
        raw = f.decrypt(token)
        return json.loads(raw.decode())
    except Exception as e:
        # неверный ключ или повреждение
        raise e

# ========== UI / Application ==========
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        root.title("🔐 Password Manager")
        root.geometry("720x520")
        root.configure(bg="#f0f4f8")
        root.resizable(False, False)

        # стиль
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook", background="#f0f4f8")
        style.configure("TFrame", background="#ffffff")
        style.configure("Treeview", font=("Arial", 10))
        style.configure("TButton", font=("Arial", 10))

        self.key = None  # ключ Fernet после логина
        self.vault = {}  # структура: id -> {website, username, password, note}

        self._build_ui()

    def _build_ui(self):
        # Notebook: вкладки Login/Register и Manager
        self.notebook = ttk.Notebook(self.root)
        self.notebook.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.98, relheight=0.96)

        # --- Вкладка авторизации ---
        self.auth_frame = Frame(self.notebook, bg="#ffffff")
        self.notebook.add(self.auth_frame, text="Login / Register")

        Label(self.auth_frame, text="🔐 Password Manager", bg="#4a90e2", fg="white",
              font=("Arial", 18, "bold"), anchor="w", padx=10).pack(fill=X)

        auth_inner = Frame(self.auth_frame, bg="#ffffff")
        auth_inner.pack(pady=20)

        # Entry для мастер-пароля
        Label(auth_inner, text="Master password:", bg="#ffffff", font=("Arial", 12)).grid(row=0, column=0, sticky=W)
        self.master_entry = Entry(auth_inner, width=30, show="*")
        self.master_entry.grid(row=0, column=1, padx=10, pady=5)

        # Show master pw
        self.show_master_var = BooleanVar(value=False)
        chk = Checkbutton(auth_inner, text="Show", variable=self.show_master_var, bg="#ffffff",
                          command=self._toggle_show_master)
        chk.grid(row=0, column=2, padx=5)

        btn_frame = Frame(auth_inner, bg="#ffffff")
        btn_frame.grid(row=1, column=0, columnspan=3, pady=10)

        ttk.Button(btn_frame, text="Login", command=self.login).grid(row=0, column=0, padx=8)
        ttk.Button(btn_frame, text="Create account", command=self.create_account_dialog).grid(row=0, column=1, padx=8)
        ttk.Button(btn_frame, text="Quick Demo (no persistent file)", command=self.demo_mode).grid(row=0, column=2, padx=8)

        Label(self.auth_frame, text="If you already have an account, press Login. Otherwise create an account.",
              bg="#ffffff", font=("Arial", 9)).pack(pady=8)

        # --- Вкладка менеджера ---
        self.manage_frame = Frame(self.notebook, bg="#ffffff")
        self.notebook.add(self.manage_frame, text="Manager")
        self.notebook.tab(1, state="disabled")  # закрыта до логина

        # Header
        header = Frame(self.manage_frame, bg="#4a90e2")
        header.pack(fill=X)
        Label(header, text="🔐 Vault", bg="#4a90e2", fg="white", font=("Arial", 16, "bold"), pady=8).pack(side=LEFT, padx=8)

        # Toolbar (генератор, добавление)
        tool = Frame(self.manage_frame, bg="#ffffff")
        tool.pack(fill=X, pady=10, padx=8)

        ttk.Button(tool, text="Add entry", command=self.add_entry_dialog).pack(side=LEFT, padx=6)
        ttk.Button(tool, text="Generate password", command=self.open_generator).pack(side=LEFT, padx=6)
        ttk.Button(tool, text="Copy password", command=self.copy_selected_password).pack(side=LEFT, padx=6)
        ttk.Button(tool, text="Show/Hide password", command=self.toggle_mask_selected).pack(side=LEFT, padx=6)
        ttk.Button(tool, text="Delete entry", command=self.delete_selected).pack(side=LEFT, padx=6)
        ttk.Button(tool, text="Logout", command=self.logout).pack(side=RIGHT, padx=6)

        # Treeview для записей
        cols = ("website", "username", "password", "note")
        self.tree = ttk.Treeview(self.manage_frame, columns=cols, show="headings", height=14)
        self.tree.heading("website", text="Website")
        self.tree.heading("username", text="Username")
        self.tree.heading("password", text="Password")
        self.tree.heading("note", text="Note")
        self.tree.column("website", width=180)
        self.tree.column("username", width=140)
        self.tree.column("password", width=160)
        self.tree.column("note", width=160)
        self.tree.pack(padx=8, pady=6, fill=BOTH, expand=True)

        # Footer
        footer = Frame(self.manage_frame, bg="#ffffff")
        footer.pack(fill=X, pady=6)
        ttk.Button(footer, text="Save vault", command=self.save_vault).pack(side=RIGHT, padx=8)
        ttk.Button(footer, text="Load vault", command=self.load_vault_prompt).pack(side=RIGHT, padx=8)

        # mask state per item
        self.masked = {}  # item_id -> True/False

    # ---------- Auth functions ----------
    def _toggle_show_master(self):
        if self.show_master_var.get():
            self.master_entry.config(show="")
        else:
            self.master_entry.config(show="*")

    def create_account_dialog(self):
        if os.path.exists(MASTER_FILE):
            if not messagebox.askyesno("Account exists", "A master account already exists. Overwrite?"):
                return
        pw1 = simpledialog.askstring("Create master password", "Enter new master password:", show="*")
        if not pw1:
            return
        pw2 = simpledialog.askstring("Confirm", "Confirm master password:", show="*")
        if pw1 != pw2:
            messagebox.showerror("Mismatch", "Passwords do not match.")
            return
        # create master
        key = create_master(pw1)
        # initialize empty vault and encrypt
        encrypt_vault(key, {})
        messagebox.showinfo("Success", "Account created and empty vault initialized.")

    def login(self):
        pw = self.master_entry.get()
        if not pw:
            messagebox.showwarning("Empty", "Enter master password.")
            return
        key = verify_master(pw)
        if key is None:
            messagebox.showerror("Login failed", "Incorrect master password or no account.")
            return
        try:
            vault = decrypt_vault(key)
        except Exception as e:
            messagebox.showerror("Vault error", f"Failed to decrypt vault: {e}")
            return
        self.key = key
        self.vault = vault
        self._enter_manager()

    def demo_mode(self):
        # Быстрый не-персистентный режим (ключ хранится только в памяти)
        pw = "demo" + secrets.token_hex(8)
        salt = secrets.token_bytes(16)
        self.key = derive_key(pw, salt)
        self.vault = {}
        self._enter_manager()
        messagebox.showinfo("Demo", "Demo mode: vault is in-memory and will not be saved to disk unless you press Save vault.")

    def logout(self):
        self.key = None
        self.vault = {}
        # очистим дерево
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.notebook.tab(1, state="disabled")
        self.notebook.select(0)
        self.master_entry.delete(0, END)

    # ---------- Vault / UI CRUD ----------
    def _enter_manager(self):
        # enable manager tab and populate
        self.notebook.tab(1, state="normal")
        self.notebook.select(1)
        self.refresh_tree()

    def refresh_tree(self):
        # очистка
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.masked.clear()
        # vault может быть dict или list; приведём к dict
        if isinstance(self.vault, dict):
            items = list(self.vault.items())
        else:
            # если список
            items = list(enumerate(self.vault))
        for k, v in items:
            wid = self.tree.insert("", END, values=(v.get("website", ""), v.get("username", ""), "•" * 8, v.get("note", "")))
            self.masked[wid] = True
            # сохраняем реальный пароль в тег/attrib (не в видимой колонке)
            self.tree.set(wid, "_real_pw", v.get("password", ""))  # not visual, just store
            # can't store arbitrary extra keys cleanly, so keep mapping in vault using k
            # attach mapping id
            self.tree.set(wid, "id", str(k))

    def add_entry_dialog(self):
        if self.key is None:
            messagebox.showwarning("Not logged in", "Login first.")
            return
        dlg = AddEntryDialog(self.root)
        self.root.wait_window(dlg.top)
        if dlg.result:
            entry_id = secrets.token_hex(8)
            self.vault[entry_id] = dlg.result
            self.refresh_tree()

    def delete_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select", "Select an entry to delete.")
            return
        if not messagebox.askyesno("Confirm delete", "Delete selected entries?"):
            return
        for item in sel:
            # get stored id
            id_val = self.tree.set(item, "id")
            if id_val in self.vault:
                del self.vault[id_val]
        self.refresh_tree()

    def copy_selected_password(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select", "Select an entry to copy password.")
            return
        item = sel[0]
        id_val = self.tree.set(item, "id")
        real_pw = self.vault.get(id_val, {}).get("password")
        if real_pw is None:
            # fallback: maybe we stored elsewhere
            real_pw = self.tree.set(item, "_real_pw")
        self.root.clipboard_clear()
        self.root.clipboard_append(real_pw)
        messagebox.showinfo("Copied", "Password copied to clipboard (temporarily).")

    def toggle_mask_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select", "Select an entry.")
            return
        item = sel[0]
        is_masked = self.masked.get(item, True)
        id_val = self.tree.set(item, "id")
        real_pw = self.vault.get(id_val, {}).get("password", "")
        if is_masked:
            # show real
            self.tree.set(item, "password", real_pw)
            self.masked[item] = False
        else:
            self.tree.set(item, "password", "•" * 8)
            self.masked[item] = True

    def save_vault(self):
        if self.key is None:
            messagebox.showwarning("Not logged in", "Login first.")
            return
        try:
            encrypt_vault(self.key, self.vault)
            messagebox.showinfo("Saved", f"Vault saved to {VAULT_FILE}")
        except Exception as e:
            messagebox.showerror("Save error", str(e))

    def load_vault_prompt(self):
        if self.key is None:
            messagebox.showwarning("Not logged in", "Login first.")
            return
        try:
            vault = decrypt_vault(self.key)
            self.vault = vault
            self.refresh_tree()
            messagebox.showinfo("Loaded", "Vault loaded from file.")
        except Exception as e:
            messagebox.showerror("Load error", f"Failed to load vault: {e}")

    # ---------- Generator UI ----------
    def open_generator(self):
        dlg = PasswordGeneratorDialog(self.root)
        self.root.wait_window(dlg.top)
        if dlg.result:
            # вставим сгенерированный пароль в буфер и покажем
            self.root.clipboard_clear()
            self.root.clipboard_append(dlg.result)
            messagebox.showinfo("Generated", "Password generated and copied to clipboard.")

# ---------- Диалог добавления записи ----------
class AddEntryDialog:
    def __init__(self, parent):
        top = self.top = Toplevel(parent)
        top.title("Add entry")
        top.transient(parent)
        top.grab_set()
        Label(top, text="Website:").grid(row=0, column=0, pady=6, padx=6, sticky=W)
        self.e_site = Entry(top, width=40)
        self.e_site.grid(row=0, column=1, pady=6, padx=6)

        Label(top, text="Username:").grid(row=1, column=0, pady=6, padx=6, sticky=W)
        self.e_user = Entry(top, width=40)
        self.e_user.grid(row=1, column=1, pady=6, padx=6)

        Label(top, text="Password:").grid(row=2, column=0, pady=6, padx=6, sticky=W)
        self.e_pass = Entry(top, width=30, show="*")
        self.e_pass.grid(row=2, column=1, pady=6, padx=6, sticky=W)

        self.show_var = BooleanVar(value=False)
        Checkbutton(top, text="Show", variable=self.show_var, command=self._toggle).grid(row=2, column=2, padx=4)

        Label(top, text="Note:").grid(row=3, column=0, pady=6, padx=6, sticky=W)
        self.e_note = Entry(top, width=40)
        self.e_note.grid(row=3, column=1, pady=6, padx=6)

        btn_frame = Frame(top)
        btn_frame.grid(row=4, column=0, columnspan=3, pady=10)
        Button(btn_frame, text="Generate", command=self.generate_and_fill).grid(row=0, column=0, padx=6)
        Button(btn_frame, text="OK", command=self.ok).grid(row=0, column=1, padx=6)
        Button(btn_frame, text="Cancel", command=self.cancel).grid(row=0, column=2, padx=6)

        self.result = None

    def _toggle(self):
        if self.show_var.get():
            self.e_pass.config(show="")
        else:
            self.e_pass.config(show="*")

    def generate_and_fill(self):
        pw = generate_password(16, True, True, True)
        self.e_pass.delete(0, END)
        self.e_pass.insert(0, pw)

    def ok(self):
        website = self.e_site.get().strip()
        username = self.e_user.get().strip()
        password = self.e_pass.get().strip()
        note = self.e_note.get().strip()
        if not website or not username or not password:
            messagebox.showwarning("Missing", "Website, username and password required.")
            return
        self.result = {"website": website, "username": username, "password": password, "note": note}
        self.top.destroy()

    def cancel(self):
        self.top.destroy()

# ---------- Генератор паролей ----------
class PasswordGeneratorDialog:
    def __init__(self, parent):
        top = self.top = Toplevel(parent)
        top.title("Password Generator")
        top.transient(parent)
        top.grab_set()

        Label(top, text="Length:").grid(row=0, column=0, padx=6, pady=6, sticky=W)
        self.len_var = IntVar(value=16)
        Spinbox(top, from_=6, to=64, textvariable=self.len_var, width=6).grid(row=0, column=1, padx=6, pady=6, sticky=W)

        self.upper = BooleanVar(value=True)
        self.digits = BooleanVar(value=True)
        self.symbols = BooleanVar(value=True)
        Checkbutton(top, text="Uppercase", variable=self.upper).grid(row=1, column=0, sticky=W, padx=6)
        Checkbutton(top, text="Digits", variable=self.digits).grid(row=1, column=1, sticky=W)
        Checkbutton(top, text="Symbols", variable=self.symbols).grid(row=1, column=2, sticky=W)

        Button(top, text="Generate", command=self.do_generate).grid(row=2, column=0, columnspan=3, pady=8)
        self.out_entry = Entry(top, width=50)
        self.out_entry.grid(row=3, column=0, columnspan=3, padx=6, pady=6)

        Button(top, text="Copy & Close", command=self.copy_close).grid(row=4, column=0, columnspan=3, pady=6)

        self.result = None

    def do_generate(self):
        length = self.len_var.get()
        pw = generate_password(length, self.upper.get(), self.digits.get(), self.symbols.get())
        self.out_entry.delete(0, END)
        self.out_entry.insert(0, pw)

    def copy_close(self):
        pw = self.out_entry.get().strip()
        if not pw:
            messagebox.showwarning("No password", "Generate a password first.")
            return
        self.result = pw
        self.top.destroy()

def generate_password(length: int = 16, use_upper=True, use_digits=True, use_symbols=True) -> str:
    alphabet = string.ascii_lowercase
    if use_upper:
        alphabet += string.ascii_uppercase
    if use_digits:
        alphabet += string.digits
    if use_symbols:
        alphabet += "!@#$%^&*()-_=+[]{};:,.<>/?"
    if not alphabet:
        alphabet = string.ascii_letters
    # secure generator
    return "".join(secrets.choice(alphabet) for _ in range(length))

# ========== Запуск ==========
if __name__ == "__main__":
    root = Tk()
    app = PasswordManagerApp(root)
    root.mainloop()
