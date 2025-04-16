import streamlit as st
import hashlib
from cryptography.fernet import Fernet
from typing import Optional

# --- Session State Initialization ---
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

if 'authorized' not in st.session_state:
    st.session_state.authorized = False  # ❌ Don't start as logged in

if 'page' not in st.session_state:
    st.session_state.page = "Login"  # 🚪 Start at login page

# --- Generate Encryption Key for Session ---
if 'key' not in st.session_state:
    st.session_state.key = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.key)

# --- Utility Functions ---
def hash_passkey(passkey: str) -> str:
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text: str) -> str:
    return st.session_state.cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text: str, passkey: str) -> Optional[str]:
    hashed_passkey = hash_passkey(passkey)
    stored = st.session_state.stored_data.get(encrypted_text)

    if stored and stored["passkey"] == hashed_passkey:
        st.session_state.failed_attempts = 0
        return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()
    else:
        st.session_state.failed_attempts += 1
        return None

def login(password: str) -> bool:
    return password == "admin123"

def logout():
    st.session_state.authorized = False
    st.session_state.page = "Login"
    st.success("🔒 Logged out successfully!")

# --- Streamlit UI ---
st.set_page_config(page_title="Secure Data Vault 🔐")
st.title("🛡️ Secure Data Encryption System")

# --- Navigation Menu ---
if st.session_state.authorized:
    menu = ["Home", "Store Data", "Retrieve Data", "Logout"]
else:
    menu = ["Login"]

st.session_state.page = st.radio("📂 Menu", menu, horizontal=True)

# --- Handle Logout ---
if st.session_state.page == "Logout":
    logout()
    st.stop()

# --- Login Page ---
if st.session_state.page == "Login":
    st.subheader("🔑 Admin Login")
    login_pass = st.text_input("Enter Admin Password:", type="password")
    if st.button("Login"):
        if login(login_pass):
            st.session_state.authorized = True
            st.session_state.failed_attempts = 0
            st.success("✅ Login successful!")
            st.session_state.page = "Home"
            st.rerun()
        else:
            st.error("❌ Incorrect password.")

# --- Home Page ---
elif st.session_state.page == "Home" and st.session_state.authorized:
    st.subheader("🏠 Welcome!")
    st.write("Store and retrieve encrypted data securely using your own passkey.")

# --- Store Data Page ---
elif st.session_state.page == "Store Data" and st.session_state.authorized:
    st.subheader("📂 Store Encrypted Data")
    label = st.text_input("Optional label (e.g., your name or alias):", placeholder="e.g. solangi")
    user_text = st.text_area("Enter data to encrypt:")
    passkey = st.text_input("Enter a secure passkey:", type="password")

    if st.button("Encrypt and Store"):
        if user_text and passkey:
            encrypted_text = encrypt_data(user_text)
            hashed = hash_passkey(passkey)

            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed,
                "label": label or "no-label"
            }

            st.success("✅ Data encrypted and stored successfully!")
            st.code(encrypted_text, language='text')
            if label:
                st.info(f"🔖 You can refer to this as: **{label}**")
        else:
            st.warning("⚠️ Both fields are required.")

# --- Retrieve Data Page ---
elif st.session_state.page == "Retrieve Data" and st.session_state.authorized:
    st.subheader("🔍 Retrieve Encrypted Data")
    encrypted_input = st.text_area("Paste the encrypted text or label:")
    passkey_input = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey_input:
            encrypted_key = encrypted_input
            for key, value in st.session_state.stored_data.items():
                if value["label"] == encrypted_input:
                    encrypted_key = key
                    break

            result = decrypt_data(encrypted_key, passkey_input)
            if result:
                st.success("✅ Data decrypted successfully!")
                st.code(result, language='text')
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey. Attempts left: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.authorized = False
                    st.warning("🔐 Too many failed attempts! Redirecting to login...")
                    st.session_state.page = "Login"
                    st.rerun()
        else:
            st.warning("⚠️ Both fields are required.")

# --- If somehow unauthorized and accessing pages ---
elif not st.session_state.authorized:
    st.warning("🔒 Please login to access the app.")
    st.session_state.page = "Login"
    st.rerun()
