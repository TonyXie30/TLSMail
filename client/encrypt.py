from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os


def cake_aes_encrypt(plaintext, key):
    backend = default_backend()
    nonce = os.urandom(24)  # Generate a random 24-byte nonce
    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=64,
        salt=None,
        info=b'key_commitment',
        backend=backend
    )
    key_material = hkdf.derive(key + nonce)
    one_time_key = key_material[:32]
    key_commitment = key_material[32:]

    chunk_size = 16 * 1024  # Split the message into 16 KiB chunks
    encrypted_chunks = []
    for i in range(0, len(plaintext), chunk_size):
        chunk = plaintext[i:i + chunk_size]
        # Calculate the nonce for each chunk
        chunk_nonce = ((i // chunk_size) * 2).to_bytes(12, 'little')
        if i + chunk_size >= len(plaintext):  # Adjust nonce for the final chunk
            chunk_nonce = (((i // chunk_size) * 2 + 1).to_bytes(12, 'little'))
        cipher = Cipher(algorithms.AES(one_time_key), modes.GCM(chunk_nonce), backend=backend)
        encryptor = cipher.encryptor()
        encrypted_chunk = encryptor.update(chunk) + encryptor.finalize() + encryptor.tag
        encrypted_chunks.append(encrypted_chunk)

    # Concatenate all parts to produce the final ciphertext
    return nonce + key_commitment + b''.join(encrypted_chunks)


def create_manifest(pieces):
    manifest = b''
    ciphertexts = []
    for piece in pieces:
        key = os.urandom(32)  # Generate a fresh 32-byte key for each piece
        ciphertext = cake_aes_encrypt(piece.encode('utf-8'), key)
        ciphertexts.append(ciphertext)
        hash_digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        hash_digest.update(ciphertext)
        piece_hash = hash_digest.finalize()

        manifest += key + piece_hash

    return manifest, ciphertexts


def main_encrypt(pieces, bcc, puks, user_ids, version, sender_device_key=None):
    # puks 第一个是发送者的puk，后面是接收者的puk 是x25519公钥[]
    # user_ids 和 puks同样结构
    # sender_device_key是发送者的私钥

    manifest, ciphertexts = create_manifest(pieces)
    shared_symmetric_key = os.urandom(32)  # Shared symmetric key for the manifest
    manifest_encrypted = cake_aes_encrypt(manifest, shared_symmetric_key)
    bcc_commitment, commitment_key = generate_bcc_commitment(bcc)
    private_key, public_key = generate_ephemeral_keys()

    manifest_encrypted_hash = hashes.Hash(hashes.SHA256(), backend=default_backend())
    manifest_encrypted_hash.update(manifest_encrypted)
    manifest_encrypted_hash = manifest_encrypted_hash.finalize()
    recipient_digests = []
    recipient_ciphertexts = []
    xcha_nonces = []

    for puk in puks:
        recipient_box_ciphertext, xcha_nonce, recipient_digest = process_recipient(
            private_key, puk, user_ids, manifest_encrypted_hash, bcc_commitment, version, shared_symmetric_key,
            sender_device_key
        )
        recipient_digests.append(recipient_digest)
        recipient_ciphertexts.append(recipient_box_ciphertext)
        xcha_nonces.append(xcha_nonce)

    recipient_digests_signature = None  # create_recipient_list_signature(sender_device_key, recipient_digests)
    return ciphertexts, bcc_commitment, commitment_key, recipient_digests_signature, public_key, recipient_ciphertexts, manifest_encrypted, manifest_encrypted_hash, xcha_nonces


def create_recipient_list_signature(private_key, recipient_digests):
    """
    Sign the concatenated recipient-associated digests to produce the recipient list signature.

    Args:
    private_key (ed25519.Ed25519PrivateKey): The sender's private signing key.
    recipient_digests (list[bytes]): A list of digests associated with each recipient.

    Returns:
    bytes: The signature for the list of recipient-associated digests.
    """
    # Concatenate all recipient-associated digests into one byte string
    concatenated_digests = b''.join(recipient_digests)

    # Sign the concatenated digests
    signature = private_key.sign(concatenated_digests)

    return signature


def generate_bcc_commitment(bcc_header):
    # 生成一个随机的32字节密钥
    commitment_key = os.urandom(32)

    # 使用HMAC SHA-256计算BCC头的提交哈希
    hmac = HMAC(commitment_key, hashes.SHA256(), backend=default_backend())
    hmac.update(bcc_header.encode())  # 假设BCC头字符串已经是str类型并需要编码为bytes
    bcc_commitment = hmac.finalize()

    return bcc_commitment, commitment_key


# 生成随机临时公私钥对
def generate_ephemeral_keys():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def process_recipient(ephemeral_private_key, puk, user_ids, manifest_hash, bcc_commitment,
                      version, shared_symmetric_key, sender_device_key=None):
    # (a) Diffie-Hellman shared secret

    shared_secret = ephemeral_private_key.exchange(puk)

    # (b) Compute recipient-associated digest
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(','.join(str(uid) for uid in user_ids).encode())  # Convert integers to strings and then encode
    digest.update(puk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))
    digest.update(manifest_hash)
    digest.update(bcc_commitment)
    digest.update(str(version).encode())  # Version as a string
    recipient_digest = digest.finalize()

    # (c) Sign the hash (optional)
    signature = b''
    if sender_device_key:
        signature = sender_device_key.sign(recipient_digest)

    # (d) Derive key using HMACSHA256 with the shared secret
    hmac_key = hmac.HMAC(shared_secret, hashes.SHA256(), backend=default_backend())
    hmac_key.update(recipient_digest)
    derived_key = hmac_key.finalize()

    # (e) Encrypt the shared symmetric key
    # Assuming we have some symmetric key to encrypt
    cipher = ChaCha20Poly1305(derived_key)
    xcha_nonce = os.urandom(12)

    data_to_encrypt = shared_symmetric_key + signature
    recipient_box_ciphertext = cipher.encrypt(xcha_nonce, data_to_encrypt, None)

    return recipient_box_ciphertext, xcha_nonce, recipient_digest

# 示例用法
