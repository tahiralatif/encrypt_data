import sqlite3
import streamlit as st
import hashlib
import os
from cryptography.fernet import Fernet

# ---------------- Encryption Key ---------------- #
key_file = "encryption_key.key"

def load_key():
    if not os.path.exists(key_file):
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
    else:
        with open(key_file, "rb") as f:
            key = f.read()
    return key

cipher = Fernet(load_key())

# ---------------- Database Init ---------------- #
def init_db():
    conn = sqlite3.connect("secure_app.db")
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS vault (
                    label TEXT PRIMARY KEY,
                    encrypted_data TEXT,
                    passkey TEXT
                )''')
    conn.commit()
    conn.close()

init_db()

# ---------------- Utilities ---------------- #
def hash_text(text):
    return hashlib.sha256(text.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# ---------------- Auth System ---------------- #
def register_user(username, password):
    conn = sqlite3.connect("secure_app.db")
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hash_text(password)))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def login_user(username, password):
    conn = sqlite3.connect("secure_app.db")
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()
    if result and result[0] == hash_text(password):
        return True
    return False

# ---------------- Streamlit App ---------------- #
st.set_page_config(page_title="🔐 Secure Vault", page_icon="🔒", layout="centered")
st.markdown("""
    <style>
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        font-size: 16px;
        border-radius: 10px;
        padding: 10px 24px;
        border: none;
    }
    .stTextInput>div>div>input {
        border-radius: 10px;
        padding: 10px;
        border: 2px solid #4CAF50;
    }
    .stTextArea>div>div>textarea {
        border-radius: 10px;
        padding: 10px;
        border: 2px solid #4CAF50;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🔐 **Secure Vault with Stylish Login**")
st.markdown("""
    <h3 style="color: #4CAF50;">Welcome to your Secure Vault</h3>
    <p style="color: #555;">Store, retrieve, and manage your encrypted secrets with the utmost security!</p>
""", unsafe_allow_html=True)

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

menu = ["Login", "Register"]
if st.session_state.logged_in:
    menu = ["Home", "Add Data", "Retrieve Data", "Delete Data", "Logout"]

choice = st.sidebar.selectbox("Select Option", menu)

# ---------- Register ---------- #
if choice == "Register":
    st.subheader("Create New Account")
    username = st.text_input("Username", key="register_username", placeholder="Enter your username")
    password = st.text_input("Password", type="password", key="register_password", placeholder="Create a password")
    if st.button("Register"):
        if register_user(username, password):
            st.success("User registered! Now login.")
        else:
            st.error("Username already exists!")

# ---------- Login ---------- #
elif choice == "Login":
    st.subheader("Login to your account")
    username = st.text_input("Username", key="login_username", placeholder="Enter your username")
    password = st.text_input("Password", type="password", key="login_password", placeholder="Enter your password")
    if st.button("Login"):
        if login_user(username, password):
            st.session_state.logged_in = True
            st.session_state.username = username
            st.success("Logged in successfully!")
        else:
            st.error("Invalid credentials!")

# ---------- Home ---------- #
elif choice == "Home":
    st.header(f"Welcome Back, {st.session_state.username}")
    st.markdown("""
    <p style="color: #333; font-size: 16px;">You are now in your secure vault. Choose an option from the sidebar to:</p>
    <ul style="color: #333; font-size: 16px;">
        <li><b>Add Data:</b> Store your secrets securely</li>
        <li><b>Retrieve Data:</b> Decrypt and view your secrets</li>
        <li><b>Delete Data:</b> Remove your secrets securely</li>
    </ul>
    """, unsafe_allow_html=True)

# ---------- Add Data ---------- #
elif choice == "Add Data":
    st.subheader("Add Secret Data")
    label = st.text_input("Label", key="add_label", placeholder="Enter a label for your secret data")
    secret_data = st.text_area("Secret Data", key="add_secret_data", placeholder="Enter the secret data here")
    passkey = st.text_input("Passkey", type="password", key="add_passkey", placeholder="Enter a passkey for encryption")
    if st.button("Encrypt & Save"):
        if label and secret_data and passkey:
            conn = sqlite3.connect("secure_app.db")
            c = conn.cursor()
            encrypted = encrypt_data(secret_data)
            hashed_passkey = hash_text(passkey)
            try:
                c.execute("INSERT INTO vault (label, encrypted_data, passkey) VALUES (?, ?, ?)",
                          (label, encrypted, hashed_passkey))
                conn.commit()
                st.success("Data saved securely!")
            except sqlite3.IntegrityError:
                st.error("Label already exists.")
            finally:
                conn.close()

# ---------- Retrieve ---------- #
elif choice == "Retrieve Data":
    st.subheader("Retrieve Encrypted Data")
    label = st.text_input("Enter Label", key="retrieve_label", placeholder="Enter the label of your secret data")
    passkey = st.text_input("Enter Passkey", type="password", key="retrieve_passkey", placeholder="Enter your passkey")
    if st.button("Decrypt"):
        conn = sqlite3.connect("secure_app.db")
        c = conn.cursor()
        c.execute("SELECT encrypted_data, passkey FROM vault WHERE label=?", (label,))
        result = c.fetchone()
        conn.close()
        if result:
            encrypted_data, stored_hash = result
            if hash_text(passkey) == stored_hash:
                try:
                    st.success(f"Decrypted Data: {decrypt_data(encrypted_data)}")
                except:
                    st.error("Decryption failed. Possibly wrong key or corrupted data.")
            else:
                st.error("Incorrect passkey!")
        else:
            st.warning("Label not found.")

# ---------- Delete ---------- #
elif choice == "Delete Data":
    st.subheader("Delete Secret Data")
    label = st.text_input("Label to Delete", key="delete_label", placeholder="Enter the label of data to delete")
    passkey = st.text_input("Passkey", type="password", key="delete_passkey", placeholder="Enter the passkey")
    if st.button("Delete"):
        conn = sqlite3.connect("secure_app.db")
        c = conn.cursor()
        c.execute("SELECT passkey FROM vault WHERE label=?", (label,))
        result = c.fetchone()
        if result and result[0] == hash_text(passkey):
            c.execute("DELETE FROM vault WHERE label=?", (label,))
            conn.commit()
            st.success("Data deleted successfully.")
        else:
            st.error("Incorrect label or passkey.")
        conn.close()

# ---------- Logout ---------- #
elif choice == "Logout":
    st.session_state.logged_in = False
    st.success("Logged out successfully. See you again!")
