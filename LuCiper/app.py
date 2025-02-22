from flask import Flask, request, jsonify, render_template
import base64
import json
import numpy as np
import secrets
from typing import List, Tuple
from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes


# --------------------------
# 1. Initialize Flask App
# --------------------------
app = Flask(__name__)

# --------------------------
# 2. Constants and Parameters
# --------------------------

MODULUS = 2**32 - 5  # A Mersenne prime: 2^32 - 5
DEGREE = 512     # Degree of polynomials (must be a power of two for NTT)
ETA = 2          # Small error bound for noise

W = pow(3, (MODULUS - 1) // DEGREE, MODULUS)  # Primitive root of unity modulo MODULUS for NTT
W_INV = pow(W, -1, MODULUS)  # Inverse of W modulo MODULUS
INV_DEGREE = pow(DEGREE, -1, MODULUS)  # Inverse of DEGREE modulo MODULUS


# --------------------------
# 3. Helper Functions
# --------------------------

def convert_to_standard_int(obj):
    """
    Recursively convert NumPy integers to standard Python integers.
    """
    if isinstance(obj, list):
        return [convert_to_standard_int(item) for item in obj]
    elif isinstance(obj, tuple):
        return tuple(convert_to_standard_int(item) for item in obj)
    elif isinstance(obj, np.integer):
        return int(obj)
    elif isinstance(obj, dict):
        return {key: convert_to_standard_int(value) for key, value in obj.items()}
    else:
        return obj

def serialize_key(pk: Tuple[List[int], List[int]], sk: List[List[int]], a1: List[int], a2: List[int]) -> str:
    """
    Serialize the public and secret keys along with a1 and a2 into a JSON string.
    """
    key_dict = {
        'pk': [list(part) for part in pk],
        'sk': [list(part) for part in sk],
        'a1': a1,
        'a2': a2
    }
    # Convert all elements to standard Python ints
    key_dict = convert_to_standard_int(key_dict)
    serialized = json.dumps(key_dict)
    return serialized

def deserialize_key(serialized_key: str) -> Tuple[Tuple[List[int], List[int]], List[List[int]], List[int], List[int]]:
    """
    Deserialize the JSON string back into public and secret keys along with a1 and a2.
    """
    try:
        key_dict = json.loads(serialized_key)
        pk = tuple(list(part) for part in key_dict['pk'])
        sk = [list(part) for part in key_dict['sk']]
        a1 = key_dict['a1']
        a2 = key_dict['a2']
        return pk, sk, a1, a2
    except (json.JSONDecodeError, KeyError, TypeError):
        raise ValueError("Invalid serialized key format.")

# --------------------------
# 4. Polynomial Operations
# --------------------------

def poly_add(a: List[int], b: List[int], modulus: int) -> List[int]:
    """
    Add two polynomials modulo q.
    """
    result = list((np.array(a) + np.array(b)) % modulus)
    return result

def poly_sub(a: List[int], b: List[int], modulus: int) -> List[int]:
    """
    Subtract two polynomials modulo q.
    """
    result = list((np.array(a) - np.array(b)) % modulus)
    return result

def poly_mul(a: List[int], b: List[int], modulus: int) -> List[int]:
    """
    Multiply two polynomials and reduce modulo q at each step.
    """
    
    degree = len(a)
    result = [0] * degree
    for i in range(degree):
        for j in range(degree):
            result[(i + j) % degree] = (result[(i + j) % degree] + a[i] * b[j]) % modulus
    
    return result

def poly_mod(a: List[int], modulus: int) -> List[int]:
    """
    Reduce polynomial coefficients modulo q.
    """
    result = [x % modulus for x in a]
    return result

def generate_secure_random_poly(degree: int, modulus: int) -> List[int]:
    """
    Generate a secure random polynomial with coefficients in [0, q-1].
    """
    poly = [secrets.randbelow(modulus) for _ in range(degree)]
    return poly

def generate_error_poly(degree: int, eta: int) -> List[int]:
    """
    Generate an error polynomial with coefficients in [-eta, eta].
    """
    poly = [secrets.randbelow(2*eta + 1) - eta for _ in range(degree)]
    return poly

# --------------------------
# 5. Number Theoretic Transform (NTT) and Inverse NTT (INTT)
# --------------------------

def ntt(a: List[int], q: int, w: int) -> List[int]:
    """
    Perform the Number Theoretic Transform on a polynomial.
    """
    n = len(a)
    A = a.copy()
    log_n = int(np.log2(n))
    
    for s in range(1, log_n + 1):
        m = 2 ** s
        wm = pow(w, n // m, q)
        for k in range(0, n, m):
            w_m = 1
            for j in range(m // 2):
                t = (w_m * A[k + j + m//2]) % q
                u = (A[k + j] + t) % q
                A[k + j] = u
                A[k + j + m//2] = (A[k + j] - t) % q
                w_m = (w_m * wm) % q
    return A

def intt(a: List[int], q: int, w_inv: int) -> List[int]:
    """
    Perform the Inverse Number Theoretic Transform on a polynomial.
    """
    n = len(a)
    A = a.copy()
    log_n = int(np.log2(n))
    
    for s in range(1, log_n + 1):
        m = 2 ** s
        wm = pow(w_inv, n // m, q)
        for k in range(0, n, m):
            w_m = 1
            for j in range(m // 2):
                t = (w_m * A[k + j + m//2]) % q
                u = (A[k + j] + t) % q
                A[k + j] = u
                A[k + j + m//2] = (A[k + j] - t) % q
                w_m = (w_m * wm) % q
    
    # Multiply by INV_DEGREE to finalize the inverse NTT
    A = [(x * INV_DEGREE) % q for x in A]
    return A

# --------------------------
# 6. Compression and Decompression
# --------------------------

def compress2d(poly: List[int], q: int, eta: int) -> List[int]:
    """
    Compress polynomial coefficients.
    """
    compressed = [(x + eta) % q // (2 * eta) for x in poly]
    return compressed

def decompress2d(poly: List[int], q: int, eta: int) -> List[int]:
    """
    Decompress polynomial coefficients.
    """
    decompressed = [(x * 2 * eta) % q for x in poly]
    return decompressed

# --------------------------
# 7. Key Generation
# --------------------------

def key_generation(n: int, q: int, eta: int) -> Tuple[Tuple[List[int], List[int]], List[List[int]], List[int], List[int], bytes]:
    """
    Generate public and secret keys for the lattice-based cryptosystem.
    """
    
    sk = [generate_error_poly(n, eta) for _ in range(3)]
    sk = convert_to_standard_int(sk)
    
    a1 = generate_secure_random_poly(n, q)
    a2 = generate_secure_random_poly(n, q)
    e1 = generate_error_poly(n, eta)
    e2 = generate_error_poly(n, eta)
    
    sk_ntt = [ntt(poly, q, W) for poly in sk]
    a1_ntt = ntt(a1, q, W)
    a2_ntt = ntt(a2, q, W)
    
    b00 = poly_add(poly_mul(a1_ntt, sk_ntt[0], q), e1, q)
    b01 = poly_add(poly_mul(a2_ntt, sk_ntt[0], q), e2, q)
    
    b00 = convert_to_standard_int(b00)
    b01 = convert_to_standard_int(b01)
    
    pk = (compress2d(b00, q, eta), compress2d(b01, q, eta))
    
    # Removed the use of the AES key here
    return pk, sk, a1, a2, None  # Removed AES key

# --------------------------
# 8. Encryption and Decryption
# --------------------------

def encrypt(pk: Tuple[List[int], List[int]], message: List[int], q: int, eta: int, a1: List[int], a2: List[int]) -> Tuple[List[int], List[int]]:
    """
    Encrypt a message using the public key.
    """
    
    b00, b01 = pk
    n = len(b00)
    
    r = generate_error_poly(n, eta)
    e1 = generate_error_poly(n, eta)
    e2 = generate_error_poly(n, eta)
    
    r_ntt = ntt(r, q, W)
    a1_ntt = ntt(a1, q, W)
    a2_ntt = ntt(a2, q, W)
    
    u = poly_add(poly_mul(a1_ntt, r_ntt, q), e1, q)
    v = poly_add(poly_mul(a2_ntt, r_ntt, q), e2, q)
    
    v = poly_add(v, poly_add(poly_mul(b00, r_ntt, q), b01, q), q)
    v = poly_add(v, message, q)
    
    return u, v

def decrypt(c: Tuple[List[int], List[int]], sk: List[List[int]], q: int, eta: int) -> List[int]:
    """
    Decrypt a ciphertext using the secret key.
    """
    u, v = c
    
    plaintext = v
    
    sk_ntt = [ntt(poly, q, W) for poly in sk]
    
    mul = poly_mul(u, sk_ntt[0], q)
    m_prime = poly_sub(plaintext, mul, q)
    
    decompressed = decompress2d(m_prime, q, eta)
    
    return decompressed

# --------------------------
# 9. AES Integration and Custom S-Box
# --------------------------

# Character to Name Mapping
char_to_name = {
    'A': 'Alice', 'B': 'Benjamin', 'C': 'Charlotte', 'D': 'Daniel', 'E': 'Emma',
    'F': 'Fiona', 'G': 'Gabriel', 'H': 'Hannah', 'I': 'Isaac', 'J': 'Jessica',
    'K': 'Kevin', 'L': 'Lily', 'M': 'Michael', 'N': 'Natalie', 'O': 'Oliver',
    'P': 'Penelope', 'Q': 'Quentin', 'R': 'Rebecca', 'S': 'Samuel', 'T': 'Taylor',
    'U': 'Ursula', 'V': 'Victor', 'W': 'William', 'X': 'Xavier', 'Y': 'Yvonne', 'Z': 'Zachary',
    'a': 'Alicia', 'b': 'Ben', 'c': 'Charlie', 'd': 'Danny', 'e': 'Emily',
    'f': 'Frank', 'g': 'Gina', 'h': 'Harry', 'i': 'Ivy', 'j': 'Jack',
    'k': 'Kara', 'l': 'Liam', 'm': 'Mia', 'n': 'Nina', 'o': 'Oscar',
    'p': 'Paul', 'q': 'Quinn', 'r': 'Riley', 's': 'Sophie', 't': 'Tom',
    'u': 'Uma', 'v': 'Vera', 'w': 'Will', 'x': 'Xander', 'y': 'Yara', 'z': 'Zane',
    '0': 'Zero', '1': 'One', '2': 'Two', '3': 'Three', '4': 'Four',
    '5': 'Five', '6': 'Six', '7': 'Seven', '8': 'Eight', '9': 'Nine',
    ' ': 'Space', '!': 'Exclamation', '"': 'Quote', '#': 'Hash', '$': 'Dollar',
    '%': 'Percent', '&': 'Ampersand', '\'': 'Apostrophe', '(': 'LeftParen', ')': 'RightParen',
    '*': 'Asterisk', '+': 'Plus', ',': 'Comma', '-': 'Dash', '.': 'Dot',
    '/': 'Slash', ':': 'Colon', ';': 'Semicolon', '<': 'LessThan', '=': 'Equals',
    '>': 'GreaterThan', '?': 'Question', '@': 'At', '[': 'LeftBracket', '\\': 'Backslash',
    ']': 'RightBracket', '^': 'Caret', '_': 'Underscore', '`': 'Grave', '{': 'LeftBrace',
    '|': 'Pipe', '}': 'RightBrace', '~': 'Tilde'
}

name_to_char = {v: k for k, v in char_to_name.items()}

def transform_message(message: str) -> str:
    """
    Transform message by replacing characters with their mapped names.
    """
    transformed = ''.join(char_to_name.get(c, c) for c in message)
    return transformed

def reverse_transform_message(message: str) -> str:
    """
    Reverse the transformation by replacing mapped names back to their characters.
    """
    result = []
    i = 0
    while i < len(message):
        found = False
        for name in char_to_name.values():
            if message.startswith(name, i):
                result.append(name_to_char[name])
                i += len(name)
                found = True
                break
        if not found:
            result.append(message[i])
            i += 1
    original = ''.join(result)
    return original

def generate_dynamic_sbox(key: bytes) -> List[int]:
    """
    Generate a dynamic S-box based on the AES key.
    """
    key_hash = SHA256.new(key).digest()
    # Extract the first 4 bytes to form a 32-bit seed
    seed = int.from_bytes(key_hash[:4], 'big')
    
    # Initialize a local random generator with the seed
    rng = np.random.default_rng(seed)
    
    sbox = list(range(256))
    rng.shuffle(sbox)
    return sbox

def apply_sbox(data: bytes, sbox: List[int]) -> bytes:
    """
    Apply the S-box substitution to the data.
    """
    substituted = bytes([sbox[b] for b in data])
    return substituted

def reverse_sbox(data: bytes, sbox: List[int]) -> bytes:
    """
    Reverse the S-box substitution on the data.
    """
    reverse = [0] * 256
    for i, val in enumerate(sbox):
        reverse[val] = i
    reversed_data = bytes([reverse[b] for b in data])
    return reversed_data

def generate_message_hash(message: str) -> str:
    """
    Generate SHA-256 hash of the message.
    """
    return sha256(message.encode()).hexdigest()

def detailed_aes_encrypt(key: bytes, plaintext: str) -> Tuple[str, dict]:
    """
    Encrypt the plaintext using AES-GCM with detailed logging.
    """
    details = {}
    
    # Compute hash of plaintext
    hash_obj = SHA256.new(plaintext.encode())
    message_hash = hash_obj.hexdigest()
    details['message_hash'] = message_hash
    
    # Append hash to the message before encryption
    plaintext_with_hash = f"{plaintext}|{message_hash}"
    details['plaintext_with_hash'] = plaintext_with_hash
    
    # Generate a dynamic S-box based on the AES key
    sbox = generate_dynamic_sbox(key)
    details['sbox'] = sbox
    
    # Transform the plaintext
    transformed_plaintext = transform_message(plaintext_with_hash)
    details['transformed_plaintext'] = transformed_plaintext
    
    # Convert transformed plaintext to bytes
    transformed_bytes = transformed_plaintext.encode('utf-8')
    details['transformed_bytes'] = list(transformed_bytes)
    
    # Apply the dynamic S-box
    sbox_applied = apply_sbox(transformed_bytes, sbox)
    details['sbox_applied'] = list(sbox_applied)
    
    # Generate a random nonce (IV) for AES-GCM
    nonce = get_random_bytes(12)  # 96-bit nonce
    details['nonce'] = list(nonce)
    
    # Initialize AES-GCM cipher
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    # Encrypt the data
    ciphertext, tag = cipher.encrypt_and_digest(sbox_applied)
    details['ciphertext'] = list(ciphertext)
    details['tag'] = list(tag)
    
    # Encode nonce, tag, and ciphertext in base64 for transmission/storage
    final_ciphertext = base64.b64encode(nonce + tag + ciphertext).decode('utf-8')
    details['final_ciphertext'] = final_ciphertext
    
    return final_ciphertext, details

def detailed_aes_decrypt(key: bytes, ciphertext_b64: str) -> Tuple[str, dict]:
    """
    Decrypt the ciphertext using AES-GCM with detailed logging.
    """
    details = {}
    
    # Decode the base64 ciphertext
    try:
        decoded_data = base64.b64decode(ciphertext_b64)
    except base64.binascii.Error:
        raise ValueError("Invalid base64-encoded ciphertext.")
    
    if len(decoded_data) < 28:  # 12 bytes nonce + 16 bytes tag
        raise ValueError("Ciphertext is too short.")
    
    nonce = decoded_data[:12]
    tag = decoded_data[12:28]
    ciphertext = decoded_data[28:]
    details['nonce'] = list(nonce)
    details['tag'] = list(tag)
    details['ciphertext'] = list(ciphertext)
    
    # Initialize AES-GCM cipher for decryption
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    
    try:
        # Decrypt and verify the ciphertext
        decrypted_sbox_bytes = cipher.decrypt_and_verify(ciphertext, tag)
        details['decrypted_sbox_bytes'] = list(decrypted_sbox_bytes)
    except ValueError:
        raise ValueError("Decryption failed or data integrity compromised.")
    
    # Generate the dynamic S-box based on the AES key
    sbox = generate_dynamic_sbox(key)
    details['sbox'] = sbox
    
    # Reverse the dynamic S-box
    reverse_sbox_bytes = reverse_sbox(decrypted_sbox_bytes, sbox)
    details['reverse_sbox_applied'] = list(reverse_sbox_bytes)
    
    # Convert bytes back to transformed plaintext
    try:
        transformed_plaintext = reverse_sbox_bytes.decode('utf-8')
        details['transformed_plaintext'] = transformed_plaintext
    except UnicodeDecodeError:
        raise ValueError("Decrypted data is not valid UTF-8.")
    
    # Reverse the transformation to get the original plaintext
    original_message_with_hash = reverse_transform_message(transformed_plaintext)
    details['original_message_with_hash'] = original_message_with_hash
    
    # Split the original message and its hash
    if "|" in original_message_with_hash:
        message, received_hash = original_message_with_hash.rsplit("|", 1)
        details['received_hash'] = received_hash
        
        # Verify the hash
        hash_obj = SHA256.new(message.encode())
        computed_hash = hash_obj.hexdigest()
        details['computed_hash'] = computed_hash
        
        if received_hash == computed_hash:
            details['hash_verified'] = True
            return message, details
        else:
            details['hash_verified'] = False
            raise ValueError("Message integrity check failed.")
    else:
        raise ValueError("Invalid decrypted data format: missing hash separator '|'.")

# --------------------------
# 10. Key Derivation
# --------------------------

def derive_shared_aes_key(shared_secret_poly: List[int]) -> bytes:
    """
    Derive a shared AES key from the shared secret polynomial.
    """
    
    # Convert the shared_secret_poly to bytes
    mapped_secret = [x % 256 for x in shared_secret_poly]
    shared_secret_bytes = bytes(mapped_secret)
    
    # Hash the shared secret to derive a 256-bit AES key
    aes_key = SHA256.new(shared_secret_bytes).digest()  # 32 bytes for AES-256
    aes_key_b64 = base64.b64encode(aes_key).decode('utf-8')
    
    return aes_key

# --------------------------
# 11. Flask Routes
# --------------------------

@app.route('/key_exchange', methods=['GET'])
def key_exchange():
    """
    Perform a key exchange between Alice and Bob and derive a shared AES key.
    """
    try:
        # Alice generates her key pair
        alice_pk, alice_sk, alice_a1, alice_a2, _ = key_generation(DEGREE, MODULUS, ETA)
        
        # Bob generates his key pair
        bob_pk, bob_sk, bob_a1, bob_a2, _ = key_generation(DEGREE, MODULUS, ETA)
        
        # Alice generates the shared secret
        shared_secret_poly = generate_secure_random_poly(DEGREE, MODULUS)
        
        # Alice encrypts the shared secret using Bob's public key (lattice-based encryption)
        encrypted_key = encrypt(bob_pk, shared_secret_poly, MODULUS, ETA, bob_a1, bob_a2)
        
        # Bob decrypts the shared secret using his secret key
        decapsulated_key = decrypt(encrypted_key, bob_sk, MODULUS, ETA)
        
        # Both derive the shared AES key from the shared secret
        alice_aes_key = derive_shared_aes_key(shared_secret_poly)
        bob_aes_key = derive_shared_aes_key(decapsulated_key)
        
        # Serialize public keys if needed (optional)
        serialized_alice_pk = serialize_key(alice_pk, alice_sk, alice_a1, alice_a2)
        serialized_bob_pk = serialize_key(bob_pk, bob_sk, bob_a1, bob_a2)
        
        return jsonify({
            'key': base64.b64encode(alice_aes_key).decode('utf-8'),  # Return the key as a string
            'alice_public_key': serialized_alice_pk,
            'bob_public_key': serialized_bob_pk
        }), 200

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/', methods=['GET'])
def index():
    """
    Render the home page.
    """
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    """
    Encrypt a message using the provided AES key.
    """
    try:
        aes_key_b64 = request.json.get('aes_key')
        plaintext = request.json.get('message')

        # Check if parameters exist
        if aes_key_b64 is None or plaintext is None:
            return jsonify({'error': 'Missing required parameters.'}), 400

        # Handle empty message - allow it as valid input
        if plaintext == '':
            plaintext = ' '  # Use a single space as minimum valid input
            
        try:
            aes_key = base64.b64decode(aes_key_b64)
        except base64.binascii.Error:
            return jsonify({'error': 'Invalid base64 encoding for AES key.'}), 500
        
        # Check key length
        if len(aes_key) != 32:
            return jsonify({'error': 'Invalid AES key length. Expected 32 bytes for AES-256.'}), 500
        
        ciphertext, details = detailed_aes_encrypt(aes_key, plaintext)
        return jsonify({'ciphertext': ciphertext, 'details': details}), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    """
    Decrypt a ciphertext using the provided AES key.
    """
    try:
        aes_key_b64 = request.json.get('aes_key')
        ciphertext_b64 = request.json.get('ciphertext')
        
        # Check if parameters exist
        if aes_key_b64 is None or ciphertext_b64 is None:
            return jsonify({'error': 'Missing required parameters.'}), 400
            
        try:
            aes_key = base64.b64decode(aes_key_b64)
        except base64.binascii.Error:
            return jsonify({'error': 'Invalid base64 encoding for AES key.'}), 500
        
        # Check key length
        if len(aes_key) != 32:
            return jsonify({'error': 'Invalid AES key length. Expected 32 bytes for AES-256.'}), 500
        
        plaintext, details = detailed_aes_decrypt(aes_key, ciphertext_b64)
        
        # Handle the empty message case
        if plaintext.strip() == '':
            plaintext = ''
            
        return jsonify({'plaintext': plaintext, 'details': details}), 200
        
    except ValueError as ve:
        return jsonify({'error': str(ve)}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
# --------------------------
# 12. Run the Flask App
# --------------------------
if __name__ == '__main__':
    app.run(debug=True)