import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

import gnupg
import psycopg2
import Config

pg_host = Config.get_pg_host()
pg_port = Config.get_pg_port()
pg_database = Config.get_pg_database()
pg_user = Config.get_pg_user()
pg_password = Config.get_pg_password()
pg_localhost = Config.get_local_pg_host()
pg_localPassword = Config.get_localPassword()


class AES:

    def __init__(self):
        pass

    def generate_key(self, username, passphrase):
        # Connect to the database and insert the public key
        conn = psycopg2.connect(host=pg_host, port=pg_port, database=pg_database, user=pg_user, password=pg_password)

        # check if the user's key already exists
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM public.pkey WHERE username = %s", (username,))
            result = cur.fetchone()
            if result is not None:
                return "Key already exists."


        key = os.urandom(32)

        key_encode = base64.b64encode(key).decode('utf-8')

        # print('key generate type')
        # print(key)
        # print('\n')

        with conn.cursor() as cur:
            cur.execute("DELETE FROM public.pkey WHERE username = %s", (username,))
            conn.commit()
            cur.execute("INSERT INTO public.pkey (username, public_key) VALUES (%s, %s)", (username, key_encode))
            conn.commit()
        conn.close()
        return

    def encrypt_message(self, message, username):
        conn = psycopg2.connect(host=pg_host, port=pg_port, database=pg_database, user=pg_user, password=pg_password)
        with conn.cursor() as cur:
            cur.execute("SELECT public_key FROM public.pkey WHERE username = %s", (username,))
            result = cur.fetchone()
            key_decode = result[0]

        key = base64.b64decode(key_decode)

        # print('key get from database:')
        # print(key)
        # print('\n')

        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        encrypt_message = iv + ciphertext
        return encrypt_message

    def decrypt_message(self, encrypted_message, username, passkey):
        conn = psycopg2.connect(host=pg_host, port=pg_port, database=pg_database, user=pg_user, password=pg_password)
        with conn.cursor() as cur:
            cur.execute("SELECT public_key FROM public.pkey WHERE username = %s", (username,))# sql 再议
            result = cur.fetchone()
            key_decode = result[0]

        key = base64.b64decode(key_decode)

        iv = encrypted_message[:16]
        ciphertext = encrypted_message[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return data



if __name__ == '__main__':
    # # Initialize the gnupg module
    # gpg = gnupg.GPG()
    #
    # # Generate keys for user1 and user2
    # key_data_user1 = gpg.gen_key_input(name_email='user1', passphrase='user1')
    # key_data_user2 = gpg.gen_key_input(name_email='user2', passphrase='user2')
    #
    # key_user1 = gpg.gen_key(key_data_user1)
    # key_user2 = gpg.gen_key(key_data_user2)
    #
    # # Export the public keys
    # public_key_user1 = gpg.export_keys(key_user1.fingerprint)
    # public_key_user2 = gpg.export_keys(key_user2.fingerprint)
    #
    # # Export the private key of user2
    # private_key_user2 = gpg.export_keys(key_user2.fingerprint, True, passphrase='user2')
    #
    # # Get the fingerprint of User2's public key
    # recipient_fingerprint = gpg.import_keys(public_key_user2).results[0]['fingerprint']
    #
    # # User1 encrypts a message with User2's public key
    # encrypted_data = gpg.encrypt('Hello, User2!', recipients=recipient_fingerprint)
    #
    # # User2 decrypts the message with their own private key
    # decrypted_data = gpg.decrypt(encrypted_data.data, passphrase='user2')
    #
    # print(f"Decrypted message: {decrypted_data.data.decode('utf-8')}")
    pg = AES()
    pg.generate_key('tony', '123456')
    pg.generate_key('tt', '123456')
    encrypted_data = pg.encrypt_message(b'Hello, User2!', 'tt')
    #encrypted_data = encrypted_data.decode('utf-8')
    decrypted_data = pg.decrypt_message(encrypted_data, 'tt', '123456')
    print(f"Decrypted message: {decrypted_data.decode('utf-8')}")
