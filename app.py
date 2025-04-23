import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import pyperclip
import os
import base64
import json
import time
from datetime import datetime, timedelta

# Initialize session state
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  
if 'current_page' not in st.session_state:
    st.session_state.current_page = 'Home'
if 'master_key' not in st.session_state:
    st.session_state.master_key = Fernet.generate_key()
    st.session_state.cipher_master = Fernet(st.session_state.master_key)
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'lockout_until' not in st.session_state:
    st.session_state.lockout_until = None
if 'authenticated_user' not in st.session_state:
    st.session_state.authenticated_user = None

# Load and save data
DATA_FILE = "data.json"
USERS_FILE = "users.json"

def load_data():
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, 'r') as f:
                st.session_state.stored_data = json.load(f)
        except:
            st.session_state.stored_data = {}

def save_data():
    with open(DATA_FILE, 'w') as f:
        json.dump(st.session_state.stored_data, f)

def load_users():
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f)

# Initialize data on startup
load_data()
users = load_users()

# Function to hash passwords or passkeys with PBKDF2
def hash_pbkdf2(data, salt=b'static_salt', iterations=100000):
    return hashlib.pbkdf2_hmac('sha256', data.encode(), salt, iterations).hex()

# Function to encrypt the message with the passkey
def encrypt_message(text, passkey):
    key = base64.urlsafe_b64encode(hashlib.sha256(passkey.encode()).digest())
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt the message with the passkey
def decrypt_message(encrypted_text, passkey):
    key = base64.urlsafe_b64encode(hashlib.sha256(passkey.encode()).digest())
    cipher = Fernet(key)
    return cipher.decrypt(encrypted_text.encode()).decode()

# User authentication
def authenticate_user(username, password):
    hashed_password = hash_pbkdf2(password)
    if username in users and users[username] == hashed_password:
        return True
    return False

def register_user(username, password):
    if username not in users:
        users[username] = hash_pbkdf2(password)
        save_users(users)
        return True
    return False

# Check lockout status
def is_locked_out():
    if st.session_state.lockout_until:
        if datetime.now() < st.session_state.lockout_until:
            remaining = (st.session_state.lockout_until - datetime.now()).seconds // 60
            st.error(f"⏰ Account locked. Try again in {remaining} minutes.")
            return True
        else:
            st.session_state.lockout_until = None
            st.session_state.failed_attempts = 0
    return False

# Main app title
st.title("🔒 My Secret Message Locker")

# Sidebar navigation with separate buttons
st.sidebar.title("Navigation")
if st.sidebar.button("Home"):
    st.session_state.current_page = "Home"
if st.sidebar.button("Store Data", disabled=not st.session_state.authenticated_user):
    st.session_state.current_page = "Store Data"
if st.sidebar.button("Retrieve Data", disabled=not st.session_state.authenticated_user):
    st.session_state.current_page = "Retrieve Data"
if st.sidebar.button("Login"):
    st.session_state.current_page = "Login"
if st.session_state.authenticated_user and st.sidebar.button("Logout"):
    st.session_state.authenticated_user = None
    st.session_state.current_page = "Home"

# User authentication page
if not st.session_state.authenticated_user and st.session_state.current_page != "Login":
    st.session_state.current_page = "Login"

# Home page
if st.session_state.current_page == "Home":
    st.subheader("🏠 Welcome!")
    st.write("Lock your secrets with a passkey and unlock them later! Please log in to store or retrieve secrets.")

# Store Data page
elif st.session_state.current_page == "Store Data" and st.session_state.authenticated_user:
    st.subheader("📂 Lock a Secret")
    user_data = st.text_area("Your Secret Message:")
    passkey = st.text_input("Your Passkey:", type="password")
    
    if st.button("Lock It"):
        if user_data and passkey:
            # Ensure user-specific storage
            if st.session_state.authenticated_user not in st.session_state.stored_data:
                st.session_state.stored_data[st.session_state.authenticated_user] = {}
            
            # Encrypt the message with the passkey
            encrypted_text = encrypt_message(user_data, passkey)
            hashed_passkey = hash_pbkdf2(passkey)
            st.session_state.stored_data[st.session_state.authenticated_user][hashed_passkey] = encrypted_text
            save_data()
            
            # Encrypt the passkey itself to generate the encrypted code
            encrypted_passkey = st.session_state.cipher_master.encrypt(passkey.encode()).decode()
            
            st.success("✅ Secret locked! Here’s your encrypted code:")
            st.text_input("Encrypted Code:", value=encrypted_passkey, disabled=True, key="encrypted_code")
        else:
            st.error("⚠️ Please fill in both fields!")

# Retrieve Data page
elif st.session_state.current_page == "Retrieve Data" and st.session_state.authenticated_user:
    st.subheader("🔍 Unlock a Secret")
    if is_locked_out():
        st.session_state.current_page = "Login"
    else:
        encrypted_code = st.text_input("Enter Encrypted Code:", type="password")
        
        if st.button("Unlock It"):
            if encrypted_code:
                try:
                    # Decrypt the encrypted code to get the original passkey
                    passkey = st.session_state.cipher_master.decrypt(encrypted_code.encode()).decode()
                    hashed_passkey = hash_pbkdf2(passkey)
                    
                    user_data = st.session_state.stored_data.get(st.session_state.authenticated_user, {})
                    if hashed_passkey in user_data:
                        encrypted_text = user_data[hashed_passkey]
                        decrypted_text = decrypt_message(encrypted_text, passkey)
                        with st.container(border=True):
                            st.markdown("**✅ Your Secret Message**")
                            st.markdown(f"{decrypted_text}")
                        st.session_state.failed_attempts = 0
                    else:
                        st.session_state.failed_attempts += 1
                        remaining_attempts = 3 - st.session_state.failed_attempts
                        if remaining_attempts > 0:
                            st.error(f"❌ No secret found for this encrypted code. Attempts remaining: {remaining_attempts}")
                        else:
                            st.session_state.lockout_until = datetime.now() + timedelta(minutes=5)
                            st.error("❌ Too many failed attempts. Account locked for 5 minutes.")
                            st.session_state.current_page = "Login"
                except:
                    st.session_state.failed_attempts += 1
                    remaining_attempts = 3 - st.session_state.failed_attempts
                    if remaining_attempts > 0:
                        st.error(f"❌ Invalid encrypted code! Attempts remaining: {remaining_attempts}")
                    else:
                        st.session_state.lockout_until = datetime.now() + timedelta(minutes=5)
                        st.error("❌ Too many failed attempts. Account locked for 5 minutes.")
                        st.session_state.current_page = "Login"
            else:
                st.error("⚠️ Please enter the encrypted code!")

# Login page
elif st.session_state.current_page == "Login":
    st.subheader("🔑 Login or Register")
    action = st.radio("Choose an action:", ["Login", "Register"])
    
    username = st.text_input("Username:", key="login_username")
    password = st.text_input("Password:", type="password", key="login_password")
    
    if st.button("Submit", key="login_button"):
        if action == "Login":
            if authenticate_user(username, password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.session_state.lockout_until = None
                st.session_state.current_page = "Home"
                st.success(f"✅ Welcome, {username}!")
            else:
                st.error("❌ Invalid username or password!")
        else:  # Register
            if username and password:
                if register_user(username, password):
                    st.success(f"✅ Registered successfully! Please log in.")
                else:
                    st.error("❌ Username already exists!")
            else:
                st.error("⚠️ Please fill in both fields!")