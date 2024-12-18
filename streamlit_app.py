import streamlit as st
from PIL import Image
import numpy as np
from steganography import hide_message, reveal_message

st.title("LSB Steganography with AES Encryption")

st.header("Hide Message in Image")
upload_image = st.file_uploader("Choose an image...", type="png")
message = st.text_input("Enter the message to hide:")
key = st.text_input("Enter a 16-byte key:")
if st.button("Hide Message"):
    if upload_image and message and len(key) == 16:
        image = Image.open(upload_image)
        encoded_image = hide_message(image, message, key.encode())
        st.image(encoded_image, caption="Encoded Image")
        st.download_button("Download Encoded Image", encoded_image, file_name="encoded_image.png")
    else:
        st.warning("Please upload an image, enter a message, and ensure the key is 16 bytes long.")

st.header("Reveal Message from Image")
upload_encoded_image = st.file_uploader("Choose an encoded image...", type="png", key="encoded")
key_reveal = st.text_input("Enter the key to reveal the message:", key="reveal")
if st.button("Reveal Message"):
    if upload_encoded_image and len(key_reveal) == 16:
        encoded_image = Image.open(upload_encoded_image)
        decoded_message = reveal_message(encoded_image, key_reveal.encode())
        st.text(f"Hidden Message: {decoded_message}")
    else:
        st.warning("Please upload an encoded image and ensure the key is 16 bytes long.")
