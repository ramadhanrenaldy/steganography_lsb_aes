from PIL import Image
import numpy as np
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64

def message_to_binary(message):
    return ''.join([format(ord(i), "08b") for i in message])

def binary_to_message(binary_data):
    message = ""
    for i in range(0, len(binary_data), 8):
        byte = binary_data[i:i+8]
        message += chr(int(byte, 2))
    return message

def encrypt_message(message, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode(), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def decrypt_message(encrypted_message, key):
    iv = base64.b64decode(encrypted_message[:24])
    ct = base64.b64decode(encrypted_message[24:])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    return pt

def hide_message(image, message, key):
    img_data = np.array(image)

    encrypted_message = encrypt_message(message, key)
    binary_message = message_to_binary(encrypted_message)
    binary_message += '1111111111111110'  # Delimiter

    data_flat = img_data.flatten()
    for i in range(len(binary_message)):
        data_flat[i] = int(format(data_flat[i], "08b")[:-1] + binary_message[i], 2)

    img_data_reshaped = data_flat.reshape(img_data.shape)
    encoded_image = Image.fromarray(img_data_reshaped.astype(np.uint8))
    return encoded_image

def reveal_message(image, key):
    img_data = np.array(image)

    binary_data = ""
    for value in img_data.flatten():
        binary_data += format(value, "08b")[-1]

    decoded_message = binary_to_message(binary_data.split('1111111111111110')[0])
    decrypted_message = decrypt_message(decoded_message, key)
    return decrypted_message
