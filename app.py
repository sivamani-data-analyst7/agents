import streamlit as st
from cryptography.fernet import Fernet

# Generate a key for encryption/decryption (store this securely in a real application)
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Function to encrypt a message
def encrypt_message(message):
    return cipher_suite.encrypt(message.encode())

# Function to decrypt a message
def decrypt_message(encrypted_message):
    return cipher_suite.decrypt(encrypted_message).decode()

# Streamlit App
st.title("Secure Message Delivery")

# Input message
message = st.text_area("Enter your message:")

if st.button("Encrypt and Send"):
    if message:
        encrypted_message = encrypt_message(message)
        st.success("Message encrypted successfully!")
        st.write("Encrypted Message:", encrypted_message.decode())

        # Simulate sending the encrypted message to another user
        st.session_state['encrypted_message'] = encrypted_message
    else:
        st.error("Please enter a message.")

# Decrypt message when the recipient interacts with it
if 'encrypted_message' in st.session_state:
    if st.button("Decrypt Message"):
        decrypted_message = decrypt_message(st.session_state['encrypted_message'])
        st.success("Message decrypted successfully!")
        st.write("Decrypted Message:", decrypted_message)
