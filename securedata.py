import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --- Initialize Encryption Key Only Once ---
if "KEY" not in st.session_state:
    st.session_state.KEY = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.KEY)

# --- Session State Initialization ---
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = True

# --- Hashing Passkey ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# --- Encrypt Data ---
def encrypt_data(text):
    return st.session_state.cipher.encrypt(text.encode()).decode()

# --- Decrypt Data ---
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    for key, value in st.session_state.stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None

# --- UI: Streamlit App ---
st.set_page_config(page_title="Secure Data Encryption", page_icon="🔒")
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("📁 Navigation", menu)

# --- Home Page ---
if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("This app lets you securely **store and retrieve encrypted data** with a passkey.")

# --- Store Data Page ---
elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter the text you want to store securely:")
    passkey = st.text_input("Create a Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_pass = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_pass
            }
            st.success("✅ Data encrypted and saved!")
            st.code(encrypted_text, language='text')
        else:
            st.warning("⚠️ Both fields are required!")

# --- Retrieve Data Page ---
elif choice == "Retrieve Data":
    if not st.session_state.is_logged_in:
        st.warning("🔐 You must login again due to too many failed attempts.")
        st.experimental_rerun()

    st.subheader("🔍 Retrieve Encrypted Data")
    encrypted_input = st.text_area("Paste Encrypted Text:")
    passkey_input = st.text_input("Enter Your Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and passkey_input:
            result = decrypt_data(encrypted_input, passkey_input)
            if result:
                st.success("✅ Data decrypted successfully:")
                st.code(result, language='text')
            else:
                attempts_left = 3 - st.session_state.failed_attempts
                st.error(f"❌ Wrong passkey. Attempts remaining: {attempts_left}")
                if st.session_state.failed_attempts >= 3:
                    st.session_state.is_logged_in = False
                    st.warning("🚫 Too many failed attempts. Redirecting to login.")
                    st.experimental_rerun()
        else:
            st.warning("⚠️ Both fields are required!")

# --- Login Page ---
elif choice == "Login":
    st.subheader("🔑 Reauthentication Required")
    login_input = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_input == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.is_logged_in = True
            st.success("✅ Login successful. You may now decrypt again.")
        else:
            st.error("❌ Incorrect password.")
