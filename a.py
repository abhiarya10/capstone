from flask import Flask, render_template, request
from PIL import Image
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import io
import os
import time
import secrets
import base64

app = Flask(__name__)

def split_image(image):
    width, height = image.size
    fragment_width = width // 10
    fragments = []
    for i in range(10):
        left = i * fragment_width
        right = (i + 1) * fragment_width
        fragment = image.crop((left, 0, right, height))
        fragments.append(fragment)
    return fragments

def save_image(image, filename):
    directory = os.path.join(os.getcwd(), "encrypted_images")
    if not os.path.exists(directory):
        os.makedirs(directory)
    filepath = os.path.join(directory, filename)
    image.save(filepath)

def pad_data(data):
    block_size = AES.block_size  # Get the AES block size (16 bytes)
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def strip_padding(data):
    padding_length = data[-1]
    return data[:-padding_length]

def ecc_encrypt(fragment):
    # Generate ECC key pair
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    # Use ECDH to derive shared secret
    shared_key = private_key.exchange(ec.ECDH(), public_key)

    # Use the shared secret to derive encryption key
    encryption_key = shared_key[:16]  # Use the first 16 bytes of the shared key as encryption key

    # Pad the fragment data
    padded_data = pad_data(fragment.tobytes())

    # Encrypt the padded data using AES
    cipher = AES.new(encryption_key, AES.MODE_ECB)
    encrypted_bytes = cipher.encrypt(padded_data)

    # Create a new Image object for the encrypted fragment
    encrypted_fragment = Image.frombytes('RGB', fragment.size, encrypted_bytes)

    # Return the encrypted fragment
    return encrypted_fragment

def aes_encrypt(fragment):
    # Generate a random encryption key
    encryption_key = secrets.token_bytes(16)  # You should use a proper encryption key

    # Pad the fragment data
    padded_data = pad_data(fragment.tobytes())

    # Encrypt the padded data using AES
    cipher = AES.new(encryption_key, AES.MODE_ECB)
    encrypted_bytes = cipher.encrypt(padded_data)

    # Create a new Image object for the encrypted fragment
    encrypted_fragment = Image.frombytes('RGB', fragment.size, encrypted_bytes)

    # Return the encrypted fragment
    return encrypted_fragment

def ecc_aes_encrypt(fragment):
    # Encrypt fragment using ECC
    ecc_encrypted_fragment = ecc_encrypt(fragment)
    
    # Encrypt the ECC-encrypted fragment using AES
    encrypted_bytes = aes_encrypt(ecc_encrypted_fragment)
    
    # Return the doubly encrypted bytes
    return encrypted_bytes

# def aes_decrypt(encrypted_bytes, encryption_key):
#     cipher = AES.new(encryption_key, AES.MODE_ECB)
#     decrypted_bytes = cipher.decrypt(encrypted_bytes)

#     # Strip padding from decrypted data
#     decrypted_data = strip_padding(decrypted_bytes)

#     return decrypted_data

# def ecc_decrypt(encrypted_fragment):
#     # Decrypt the ECC-encrypted fragment using ECC private key
#     private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())

#     # Use ECDH to derive shared secret
#     public_key = private_key.public_key()
#     shared_key = private_key.exchange(ec.ECDH(), public_key)

#     # Use the shared secret to derive encryption key
#     encryption_key = shared_key[:16]  # Use the first 16 bytes of the shared key as encryption key

#     # Decrypt the encrypted bytes using AES
#     decrypted_bytes = aes_decrypt(encrypted_fragment.tobytes(), encryption_key)

#     # Create a new Image object for the decrypted fragment
#     decrypted_fragment = Image.frombytes('RGB', encrypted_fragment.size, decrypted_bytes)

#     # Return the decrypted fragment
#     return decrypted_fragment

# def ecc_aes_decrypt(encrypted_image):
#     decrypted_fragments = []
#     width, height = encrypted_image.size
#     fragment_width = width // 10
#     for i in range(10):
#         left = i * fragment_width
#         right = (i + 1) * fragment_width
#         fragment = encrypted_image.crop((left, 0, right, height))
#         if i % 2 == 0:
#             decrypted_fragment = ecc_decrypt(fragment)
#         else:
#             decrypted_fragment = aes_decrypt(fragment)
#         decrypted_fragments.append(decrypted_fragment)
#     return decrypted_fragments

@app.route('/', methods=['GET', 'POST'])
def index():
    encryption_method = None  # Initialize encryption method variable
    encryption_time = None  # Initialize encryption time variable
    if request.method == 'POST':
        uploaded_image = request.files['image']
        image = Image.open(uploaded_image)
        
        # Separate encryption functions for even and odd fragments
        if 'ecc_button' in request.form:
            start_time = time.time()  # Record start time
            encrypted_fragments = [ecc_encrypt(fragment) if i % 2 == 0 else fragment for i, fragment in enumerate(split_image(image))]
            encryption_time = time.time() - start_time  # Calculate encryption time
            encryption_method = "Encrypted using ECC"
        elif 'aes_button' in request.form:
            start_time = time.time()  # Record start time
            encrypted_fragments = [aes_encrypt(fragment) if i % 2 != 0 else fragment for i, fragment in enumerate(split_image(image))]
            encryption_time = time.time() - start_time  # Calculate encryption time
            encryption_method = "Encrypted using AES"
        elif 'ecc_aes_button' in request.form:  # New button for ECC + AES encryption
            start_time = time.time()  # Record start time
            encrypted_fragments = [ecc_aes_encrypt(fragment) for fragment in split_image(image)]
            encryption_time = time.time() - start_time  # Calculate encryption time
            encryption_method = "Encrypted using ECC + AES"

        # Combine encrypted fragments into a single image
        encrypted_image = Image.new('RGB', (image.width, image.height))
        current_x = 0  # Track the current x-coordinate for pasting fragments
        for fragment in encrypted_fragments:
            encrypted_image.paste(fragment, (current_x, 0))
            current_x += fragment.width

        # Save the encrypted image to a file
        save_image(encrypted_image, "encrypted_image.png")
        
        # Convert encrypted image to base64 for display
        buffered = io.BytesIO()
        encrypted_image.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode('utf-8')
        return render_template('index.html', img_data=img_str, encryption_method=encryption_method, encryption_time=encryption_time)
    return render_template('index.html')

# # Route for decrypting the image
# @app.route('/decrypt', methods=['POST'])
# def decrypt():
#     uploaded_image = request.files['encrypted_image']
#     encrypted_image = Image.open(uploaded_image)
    
#     # Decrypt the encrypted image
#     decrypted_fragments = ecc_aes_decrypt(encrypted_image)

#     # Combine decrypted fragments into a single image
#     decrypted_image = Image.new('RGB', (sum(fragment.width for fragment in decrypted_fragments), decrypted_fragments[0].height))
#     current_x = 0
#     for fragment in decrypted_fragments:
#         decrypted_image.paste(fragment, (current_x, 0))
#         current_x += fragment.width

#     # Save the decrypted image to a file
#     save_image(decrypted_image, "decrypted_image.png")

#     # Convert decrypted image to base64 for display
#     buffered = io.BytesIO()
#     decrypted_image.save(buffered, format="PNG")
#     decrypted_img_str = base64.b64encode(buffered.getvalue()).decode('utf-8')

#     return render_template('decryption.html', decrypted_img_data=decrypted_img_str)

if __name__ == '__main__':
    app.run(debug=True)
