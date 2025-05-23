import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import uuid


# set page config
st.set_page_config(
    page_title="Secure Data System",
    page_icon="🛡️",
    layout="centered"
)

# Custom CSS for styling
def local_css():
    st.markdown(
        """
        <style>
        .main {
            background-color: #f0f2f6;
            padding: 20px;
        }
        .stButton>button {
            background-color: #f0f2f6;
            color: black;
            border-radius: 5px;
            padding: 8px 16px;
            border: none;
            font-weight: bold;
        }
        .stTextInput, .stTextArea {
            background-color: #ffffff;
            color: black;
            border: 1px solid #ccc;
            border-radius: 5px;
            padding: 5px;
        }
        .header {
            text-align: center;
            padding: 20px;
            background-color: #007bff;
            color: white;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .error-box {
            background-color: #f8d7da;
            color: #721c24;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 10px;
            }
        .success-box {
            background-color: #d4edda;
            color: #155724;
            padding: 10px;
            border-radius: 5px;
            margin-bottom: 10px;
            }
        </style>
        """,
        unsafe_allow_html=True
    )

# Apply custom CSS
local_css()

# Initialize session state
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}   # {date_id: {encrypted_text: "...", "passkey": "hashed_passkey"}}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "current_page" not in st.session_state:
    st.session_state.current_page = "Home"

# Generate Fernet key
if "cipher" not in st.session_state:
    st.session_state.cipher = Fernet(Fernet.generate_key())

# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Function to encrypt text
def encrypt_data(text, passkey):
    return st.session_state.cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    data_entry = st.session_state.stored_data.get(encrypted_text)

    if data_entry and data_entry["passkey"] == hashed_passkey:
        try:
            decrypted_text = st.session_state.cipher.decrypt(encrypted_text.encode()).decode()
            return decrypted_text
        except:
            return None
    st.session_state.failed_attempts += 1
    return None

# Streamlit UI
st.markdown(
    """
    <div class="header">
        <h1>🔒 Secure Data Encryption System</h1>
        <p>Store and retrieve sensitive data with unique passkeys</p>
    </div>
    """,
    unsafe_allow_html=True
)

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.current_page))

# Handle page redirection after Login
if st.session_state.failed_attempts >= 3 and choice != "Login":
    st.session_state.current_page = "Login"

# Home page
if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    st.markdown("""
        - **Store Data**: Encrypt and save your data with a passkey.
        - **Retrieve Data**: Decrypt your data using the correct passkey.
        - **Security**: Three failed decryption attempts will require reauthorization.
        """
    )
    if st.button("Clear All Data (For Testing)"):
        st.session_state.stored_data = {}
        st.session_state.failed_attempts = 0
        st.success("All data cleared!")

# Store Data page
elif choice == "Store Data":
    st.session_state.current_page = "Store Data"
    st.subheader("📂 Store Data Securely")
    with st.form("store_form"):
        user_data = st.text_area("Enter Data to Encrypt")
        passkey = st.text_input("Enter Passkey:", type="password")
        submitted = st.form_submit_button("Encrypt & Save")

        if submitted:
            if user_data and passkey:
                encrypted_text = encrypt_data(user_data, passkey)
                hashed_passkey = hash_passkey(passkey)
                data_id = str(uuid.uuid4())  # Unique ID for each data entry
                st.session_state.stored_data[data_id] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                }
                st.markdown(
                    f'<div class="success-box">✅ Data stored securely! Your Data ID: <strong>{data_id}</strong></div>',
                    unsafe_allow_html=True
                )
                st.info("Save this data ID to retrieve your data later.")
            else:
                st.markdown(
                    '<div class="error-box">⚠️ Both data and passkey are required!</div>',
                    unsafe_allow_html=True
                )

# Retrieve Data page
elif choice == "Retrieve Data":
    st.session_state.current_page = "Retrieve Data"
    st.subheader("🔍 Retrieve Your Data")
    st.markdown(
        f'<div>Attempts remaining: <strong>{3 - st.session_state.failed_attempts}</strong></div>',
        unsafe_allow_html=True
    )
    with st.form("retrieve_form"):
        data_id = st.text_input("Enter Data ID:")
        passkey = st.text_input("Enter Passkey:", type="password")
        submitted = st.form_submit_button("Decrypt")

        if submitted:
            if data_id and passkey:
                data_entry = st.session_state.stored_data.get(data_id)
                if data_entry:
                    decrypted_text = decrypt_data(data_entry["encrypted_text"], passkey)
                    if decrypted_text:
                        st.markdown(
                            f'<div class="success-box">✅ Decrypted data: <strong>{decrypted_text}</strong></div>',
                            unsafe_allow_html=True
                        )
                    else:
                        st.markdown(
                            f'<div class="error-box">🔒 Too many failed attempts! Redirecting to Login Page...</div>',
                            unsafe_allow_html=True
                        )
                        st.session_state.current_page = "Login"
                        st.rerun()
            else:
                st.markdown(
                    '<div class="error-box"> ❌ Invalid Data ID!</div>',
                    unsafe_allow_html=True
                )
        else:
            st.markdown(
                '<div class="error-box">⚠️ Both data ID and passkey are required!</div>',
                unsafe_allow_html=True
            )

# Login page
elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    with st.form("login_form"):
        login_pass = st.text_input("Enter Master Password:", type="password")
        submitted = st.form_submit_button("Login")

        if submitted:
            if login_pass == "admin123":    #Hardcoded for demo
                st.session_state.failed_attempts = 0
                st.session_state.current_page = "Retrieve Data"
                st.markdown(
                    '<div class="success-box">✅ Reauthorization successful! Redirecting to Retrieve Data...</div>',
                    unsafe_allow_html=True
                )
                st.rerun()
            else:
                st.markdown(
                    '<div class="error-box">❌ Incorrect Password!</div>',
                unsafe_allow_html=True
                )

# Footer
st.markdown(
    """
    <hr>
    <p style="text-align: center; color: #666;">
        © 2025 Secure Data System | Built with Streamlit
    </p>
    """,
    unsafe_allow_html=True
)