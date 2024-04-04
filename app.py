from flask import Flask, render_template, request, send_from_directory
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

def ecc_aes_encrypt(fragment, index):
    if index % 2 == 0:
        # Encrypt fragment using ECC
        encrypted_bytes = ecc_encrypt(fragment)
    else:
        # Encrypt fragment using AES
        encrypted_bytes = aes_encrypt(fragment)
    
    # Return the encrypted bytes
    return encrypted_bytes

def decrypt_fragments(encrypted_fragments, private_key):
    decrypted_fragments = []
    for i, fragment in enumerate(encrypted_fragments):
        if i % 2 == 0:
            # Decrypt ECC-encrypted fragment using ECC private key
            decrypted_fragment = decrypt_fragment_ecc(fragment, private_key)
        else:
            # Decrypt AES-encrypted fragment
            decrypted_fragment = decrypt_fragment_aes(fragment)
        decrypted_fragments.append(decrypted_fragment)
    return decrypted_fragments

def decrypt_fragment_ecc(encrypted_fragment, private_key):
    # Use ECDH to derive shared secret
    public_key = private_key.public_key()
    shared_key = public_key.exchange(ec.ECDH(), private_key)

    # Use the shared secret to derive encryption key
    encryption_key = shared_key[:16]  # Use the first 16 bytes of the shared key as encryption key

    # Decrypt the encrypted bytes using AES
    cipher = AES.new(encryption_key, AES.MODE_ECB)
    decrypted_bytes = cipher.decrypt(encrypted_fragment.tobytes())

    # Strip padding from decrypted data
    decrypted_data = strip_padding(decrypted_bytes)

    # Create a new Image object for the decrypted fragment
    decrypted_fragment = Image.frombytes('RGB', encrypted_fragment.size, decrypted_data)

    return decrypted_fragment

def decrypt_fragment_aes(encrypted_fragment):
    # Decryption process for AES-encrypted fragment
    # You need to implement this part based on your AES encryption method
    pass

def save_decrypted_image(decrypted_image, filename):
    directory = os.path.join(os.getcwd(), "decrypted_images")
    if not os.path.exists(directory):
        os.makedirs(directory)
    filepath = os.path.join(directory, filename)
    decrypted_image.save(filepath)

@app.route('/', methods=['GET', 'POST'])
def index():
    encryption_method = None
    encryption_time = None
    decryption_method = None
    decryption_time = None
    img_data = None
    decrypted_img_data = None
    encrypted_fragments = None  # Initialize encrypted_fragments variable

    if request.method == 'POST':
        uploaded_image = request.files['image']
        image = Image.open(uploaded_image)

        if 'ecc_button' in request.form:
            start_time = time.time()
            encrypted_fragments = [ecc_encrypt(fragment) if i % 2 == 0 else fragment for i, fragment in enumerate(split_image(image))]
            encryption_time = time.time() - start_time
            encryption_method = "Encrypted using ECC"
        elif 'aes_button' in request.form:
            start_time = time.time()
            encrypted_fragments = [aes_encrypt(fragment) if i % 2 != 0 else fragment for i, fragment in enumerate(split_image(image))]
            encryption_time = time.time() - start_time
            encryption_method = "Encrypted using AES"
        elif 'ecc_aes_button' in request.form:
            start_time = time.time()
            encrypted_fragments = [ecc_aes_encrypt(fragment, i) for i, fragment in enumerate(split_image(image))]
            encryption_time = time.time() - start_time
            encryption_method = "Encrypted using ECC + AES"
        elif 'decrypt_button' in request.form:
            # First, check if encrypted_fragments is defined
            if encrypted_fragments is None:
                return render_template('index.html', decryption_method="No image uploaded for decryption")

            start_time = time.time()
            private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            decrypted_fragments = decrypt_fragments(encrypted_fragments, private_key)
            decryption_time = time.time() - start_time
            decryption_method = "Decrypted using ECC and AES"

            # Combine decrypted fragments into a single image
            decrypted_image = Image.new('RGB', (image.width, image.height))
            current_x = 0
            for fragment in decrypted_fragments:
                decrypted_image.paste(fragment, (current_x, 0))
                current_x += fragment.width

            # Save the decrypted image to a file
            save_decrypted_image(decrypted_image, "decrypted_image.png")

            # Convert decrypted image to base64 for display
            buffered = io.BytesIO()
            decrypted_image.save(buffered, format="PNG")
            decrypted_img_data = base64.b64encode(buffered.getvalue()).decode('utf-8')

        # Combine encrypted fragments into a single image
        encrypted_image = Image.new('RGB', (image.width, image.height))
        current_x = 0
        for fragment in encrypted_fragments:
            encrypted_image.paste(fragment, (current_x, 0))
            current_x += fragment.width

        # Save the encrypted image to a file
        save_image(encrypted_image, "encrypted_image.png")

        # Convert encrypted image to base64 for display
        buffered = io.BytesIO()
        encrypted_image.save(buffered, format="PNG")
        img_data = base64.b64encode(buffered.getvalue()).decode('utf-8')

    return render_template('index.html', img_data=img_data, encryption_method=encryption_method, encryption_time=encryption_time, decrypted_img_data=decrypted_img_data, decryption_method=decryption_method, decryption_time=decryption_time)

@app.route('/download_decrypted_image')
def download_decrypted_image():
    directory = os.path.join(os.getcwd(), "decrypted_images")
    filename = "decrypted_image.png"
    return send_from_directory(directory, filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
