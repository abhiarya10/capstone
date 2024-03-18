from flask import Flask, render_template, request
from PIL import Image, ImageDraw
from Crypto.Cipher import AES
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import io
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

# Function to perform ECC encryption
def ecc_encrypt(fragment):
    # Store the original fragment size
    width, height = fragment.size
    
    # Generate ECC key pair
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()

    # Use ECDH to derive shared secret
    shared_key = private_key.exchange(ec.ECDH(), public_key)

    # Use the shared secret to derive encryption key
    encryption_key = shared_key[:16]  # Use the first 16 bytes of the shared key as encryption key

    # Encrypt the fragment using AES
    cipher = AES.new(encryption_key, AES.MODE_ECB)
    encrypted_bytes = cipher.encrypt(fragment.tobytes())

    # Create a new Image object for the encrypted fragment
    encrypted_fragment = Image.frombytes('RGB', (width, height), encrypted_bytes)

    # Return the encrypted fragment
    return encrypted_fragment

def encrypt_image(image):
    fragments = split_image(image)
    encrypted_fragments = []
    for i, fragment in enumerate(fragments):
        if i % 2 == 0:  # Apply ECC on even-indexed fragments
            encrypted_fragment = ecc_encrypt(fragment)
            encrypted_fragments.append(encrypted_fragment)
        else:  # Odd-indexed fragments remain unchanged
            encrypted_fragments.append(fragment)
    return encrypted_fragments

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        uploaded_image = request.files['image']
        image = Image.open(uploaded_image)
        encrypted_fragments = encrypt_image(image)
        
        # Create a new image to store the encrypted fragments
        encrypted_image = Image.new('RGB', (image.width, image.height))
        current_x = 0  # Track the current x-coordinate for pasting fragments
        
        # Paste each encrypted fragment into the encrypted image
        for fragment in encrypted_fragments:
            encrypted_image.paste(fragment, (current_x, 0, current_x + fragment.width, image.height))
            current_x += fragment.width
        
        # Convert encrypted image to base64 for display
        buffered = io.BytesIO()
        encrypted_image.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode('utf-8')
        return render_template('index.html', img_data=img_str)
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
