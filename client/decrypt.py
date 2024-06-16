from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from encrypt import main_encrypt


def cake_aes_decrypt(ciphertext, key):
    backend = default_backend()
    nonce = ciphertext[:24]
    key_commitment = ciphertext[24:56]
    encrypted_data = ciphertext[56:]

    hkdf = HKDF(
        algorithm=hashes.SHA512(),
        length=64,
        salt=None,
        info=b'key_commitment',
        backend=backend
    )
    key_material = hkdf.derive(key + nonce)
    assert key_commitment == key_material[32:], "Key commitment mismatch"
    one_time_key = key_material[:32]

    chunk_size = 16 * 1024 + 16  # 16 KiB + 16 bytes GCM tag
    plaintext = b''
    for i in range(0, len(encrypted_data), chunk_size):
        chunk = encrypted_data[i:i + chunk_size]
        chunk_nonce = ((i // chunk_size) * 2).to_bytes(12, 'little')
        if i + chunk_size >= len(encrypted_data):  # Adjust nonce for the final chunk
            chunk_nonce = (((i // chunk_size) * 2 + 1).to_bytes(12, 'little'))
        cipher = Cipher(algorithms.AES(one_time_key), modes.GCM(chunk_nonce, chunk[-16:]), backend=backend)
        decryptor = cipher.decryptor()
        plaintext += decryptor.update(chunk[:-16]) + decryptor.finalize()

    return plaintext


def decrypt_email(ciphertexts, recipient_box_ciphertext, ephemeral_public_key, private_user_key, puk,
                  manifest_encrypted, manifest_hash, bcc_commitment, version, xcha_nonce, user_ids,
                  sender_device_key=None, ):
    # (a) Compute recipient-associated digest and Diffie-Hellman shared secret

    shared_secret = private_user_key.exchange(ephemeral_public_key)

    # (b) Derive key using HMACSHA256 with the shared secret
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(user_ids.encode())
    digest.update(puk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ))
    digest.update(manifest_hash)
    digest.update(bcc_commitment)
    digest.update(version.encode())
    recipient_digest = digest.finalize()

    hmac_key = hmac.HMAC(shared_secret, hashes.SHA256(), backend=default_backend())
    hmac_key.update(recipient_digest)
    derived_key = hmac_key.finalize()

    # (c) Decrypt the recipient box ciphertext using XChaCha20-Poly1305
    cipher = ChaCha20Poly1305(derived_key)
    data_decrypted = cipher.decrypt(xcha_nonce, recipient_box_ciphertext, None)

    # Split the data into shared symmetric key and signature
    shared_symmetric_key = data_decrypted[:32]
    signature = data_decrypted[32:]

    # (d) Verify the signature if present
    if sender_device_key:
        sender_device_key.verify(signature, recipient_digest)

    # (e) Decrypt the manifest using the shared symmetric key
    manifest = cake_aes_decrypt(manifest_encrypted, shared_symmetric_key)
    decrypted_pieces = parse_manifest_and_decrypt(manifest, ciphertexts)

    return decrypted_pieces


def parse_manifest_and_decrypt(manifest, ciphertexts):
    decrypted_pieces = []
    backend = default_backend()

    for i in range(len(ciphertexts)):
        key_start = i * (32 + 32)  # 每个条目包含32字节的密钥和32字节的哈希
        key = manifest[key_start:key_start + 32]
        piece_hash = manifest[key_start + 32:key_start + 64]

        # 验证 hash
        hash_digest = hashes.Hash(hashes.SHA256(), backend=backend)
        hash_digest.update(ciphertexts[i])
        calculated_hash = hash_digest.finalize()
        assert calculated_hash == piece_hash, "Hash mismatch"

        # 解密 piece
        decrypted_piece = cake_aes_decrypt(ciphertexts[i], key)
        decrypted_pieces.append(decrypted_piece)

    return decrypted_pieces


# sender_device_private_key = ed25519.Ed25519PrivateKey.generate()
# sender_device_public_key = sender_device_private_key.public_key()
#
# # 用于加密的示例数据
# pieces = [b"Hello World!", b"This is a test email."]
# bcc = "bcc@example.com"
# # 假设第一个公钥是发送者的，其余的是接收者的
# private_keys = [(x25519.X25519PrivateKey.generate()) for _ in range(3)]
#
# # 将私钥和公钥分别存储在列表中
#
# public_keys = [private_key.public_key() for private_key in private_keys]
#
# user_ids = "sender@example.com,recipient1@example.com,recipient2@example.com"
# version = "1.0"
#
# ciphertexts, bcc_commitment, commitment_key, recipient_digests_signature, public_key, recipient_ciphertexts, manifest_encrypted, manifest_encrypted_hash, xcha_nonces = main_encrypt(
#     pieces, bcc, public_keys, user_ids, version, sender_device_private_key
# )
#
# print("Ciphertexts:", ciphertexts)
# print("BCC Commitment:", bcc_commitment.hex())
# print("Commitment Key:", commitment_key.hex())
# print("Recipient Digests Signature:", recipient_digests_signature.hex())
# print("Ephemeral Public Key:",
#       public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex())
# print("Recipient Ciphertexts:", [ciphertext.hex() for ciphertext in recipient_ciphertexts])
#
# decrypted_pieces = decrypt_email(ciphertexts, recipient_ciphertexts[0], public_key, private_keys[0], public_keys[0],
#                                 manifest_encrypted, manifest_encrypted_hash,
#                              bcc_commitment, version, xcha_nonces[0], user_ids, sender_device_key=sender_device_public_key)
#
# print("Decrypted Manifest:", decrypted_pieces)
