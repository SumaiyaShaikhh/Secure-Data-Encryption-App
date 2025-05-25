import streamlit as st
from cryptography.fernet import Fernet

st.set_page_config(page_title="🔐 Secure Data Encryption System", layout="centered")

st.title("🔐 Secure Data Encryption System")
st.caption("Encrypt and decrypt confidential messages using Fernet encryption (AES-128 with HMAC).")


st.subheader("🔑 Encryption Key")

key_action = st.radio("Choose key option:", ["Generate New Key", "Use Your Own Key"])

if key_action == "Generate New Key":
    key = Fernet.generate_key()
    st.session_state['fernet'] = Fernet(key)
    st.success("New encryption key generated.")
    st.code(key.decode(), language='text')
else:
    user_key = st.text_input("Paste your base64 key here:")
    if user_key:
        try:
            fernet = Fernet(user_key.encode())
            st.session_state['fernet'] = fernet
            st.success("Valid key loaded.")
        except Exception as e:
            st.error("Invalid key format.")


st.subheader("📤 Encrypt Your Message")
message = st.text_area("Enter the message to encrypt:")

if st.button("Encrypt"):
    if message and 'fernet' in st.session_state:
        encrypted = st.session_state.fernet.encrypt(message.encode())
        st.session_state['encrypted'] = encrypted
        st.success("Message encrypted:")
        st.code(encrypted.decode(), language='text')
    else:
        st.warning("Please enter a message and ensure a valid key is loaded.")


st.subheader("📥 Decrypt Your Message")
decrypt_input = st.text_area("Paste the encrypted text here:")

if st.button("Decrypt"):
    if decrypt_input and 'fernet' in st.session_state:
        try:
            decrypted = st.session_state.fernet.decrypt(decrypt_input.encode()).decode()
            st.success("Message decrypted:")
            st.code(decrypted, language='text')
        except Exception as e:
            st.error("Decryption failed: " + str(e))
    else:
        st.warning("Please paste encrypted text and ensure a valid key is loaded.")
