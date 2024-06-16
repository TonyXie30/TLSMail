import os

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

def generate_seed():
    return os.urandom(32)

def hkdf_extract_expand(secret, info):
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'\x00' * 32,
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(secret)

def save_to_file(directory, filename, data):
    path = os.path.join(directory, filename)
    with open(path, 'wb') as file:
        file.write(data)

def generate_and_store_keys(directory):
    # Create directory if it doesn't exist
    os.makedirs(directory, exist_ok=True)

    # Generate 32-byte secret seed
    secret_seed = generate_seed()
    save_to_file(directory, 'secret_seed.bin', secret_seed)

    # Use HKDF to generate different 32-byte keys
    private_x25519 = hkdf_extract_expand(secret_seed, b"Zoombase-2-ClientOnly-KDF-PerUserX25519")
    save_to_file(directory, 'private_x25519.bin', private_x25519)

    email_seed = hkdf_extract_expand(secret_seed, b"Zoombase-2-ClientOnly-KDF-PerUserEmailSeed")
    save_to_file(directory, 'email_seed.bin', email_seed)

    private_email_x25519 = hkdf_extract_expand(email_seed, b"Zoombase-2-ClientOnly-KDF-PerUserEmailX25519")
    save_to_file(directory, 'private_email_x25519.bin', private_email_x25519)

    voicemail_seed = hkdf_extract_expand(secret_seed, b"Zoombase-2-ClientOnly-KDF-PerUserVoicemailSeed")
    save_to_file(directory, 'voicemail_seed.bin', voicemail_seed)

    private_voicemail_x25519 = hkdf_extract_expand(voicemail_seed, b"Zoombase-2-ClientOnly-KDF-PerUserVoicemailX25519")
    save_to_file(directory, 'private_voicemail_x25519.bin', private_voicemail_x25519)

    symmetric_key = hkdf_extract_expand(secret_seed, b"Zoombase-2-ClientOnly-KDF-PerUserSymmetricKey")
    save_to_file(directory, 'symmetric_key.bin', symmetric_key)

    # Generate Ed25519 key pair for email
    private_key_email = x25519.X25519PrivateKey.from_private_bytes(private_email_x25519)
    public_key_email = private_key_email.public_key()

    # Save the public key as binary
    save_to_file(directory, 'public_email_x25519.bin', public_key_email.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))






