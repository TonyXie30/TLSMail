import base64
import datetime
import json

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from flask import Flask, render_template, request, jsonify
from flask_bcrypt import generate_password_hash
import psycopg2

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from typing import List, Optional, Tuple
import PUKs
import Config
import gpg
import AES
import os

from decrypt import decrypt_email
from encrypt import main_encrypt

app = Flask(__name__)

current_user = None
current_password = None
current_skey = None
current_passphrase = None
gnupg = gpg.GPG()
aes = AES.AES()
pg_host = Config.get_pg_host()
pg_port = Config.get_pg_port()
pg_database = Config.get_pg_database()
pg_user = Config.get_pg_user()
pg_password = Config.get_pg_password()
pg_localhost = Config.get_local_pg_host()
pg_localPassword = Config.get_localPassword()
url = 'https://124.71.57.244:5000/'


def get_db_connection():
    return psycopg2.connect(host=pg_host, port=pg_port, database=pg_database, user=pg_user, password=pg_password)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/store_username', methods=['POST'])
def store_username():
    username = request.form.get('username')
    global current_user
    current_user = username
    global current_password
    global current_passphrase
    current_passphrase = request.form.get('password')
    conn = psycopg2.connect(host=pg_host, port=pg_port, database=pg_database, user=pg_user, password=pg_password)
    with conn.cursor() as cur:
        cur.execute("SELECT password FROM public.user WHERE username = %s", (username,))
        result = cur.fetchone()
        current_password = result[0]
    conn = psycopg2.connect(host='localhost', port=pg_port, database=pg_database, user=pg_user,
                            password=pg_localPassword)
    print('Username stored successfully')
    global current_skey
    with conn.cursor() as cur:
        cur.execute("SELECT private_key FROM public.skey WHERE username = %s", (username,))
        result = cur.fetchone()
        current_skey = result[0]
    return 'Username stored successfully'


@app.route('/access_username')
def access_username():
    global current_user
    return jsonify({'username': current_user, 'password': current_password})


@app.route('/mailbox')
def mailbox():
    return render_template('MailBox.html')

@app.route('/mailbox_cake')
def mailbox_cake():
    return render_template('MailBox-cake.html')

@app.route('/generate_key', methods=['POST'])
def generate_key():
    data = request.get_json()
    encrypt_method = data['encryption_method']
    username = data['username']
    passphrase = data['passphrase']
    private_key = 'Check your local storage for the private key.'
    if encrypt_method == 'OpenPGP':
        private_key = gnupg.generate_key(username=username, passphrase=passphrase)
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE public."user"
                SET encrypted_method = 1
                WHERE username = %s
            """, (username,))
            conn.commit()
    elif encrypt_method == 'AES':
        private_key = aes.generate_key(username=username, passphrase=passphrase)
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("""
                        UPDATE public."user"
                        SET encrypted_method = 2
                        WHERE username = %s
                    """, (username,))
            conn.commit()
    elif encrypt_method == 'Cake-AES':
        PUKs.generate_and_store_keys(username)
        public_key_email_bytes = read_from_file(username, 'public_email_x25519.bin')

        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE public."user"
                SET public_key_email_bytes = %s ,encrypted_method = 3
                WHERE username = %s
            """, (public_key_email_bytes, username))
            conn.commit()

    return jsonify({'private_key': private_key})


@app.route('/encrypt_message', methods=['POST'])
def encrypt_message():
    data = request.get_json()
    message = data['content']
    recipient = data['recipient']
    encrypted_method = None
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT encrypted_method FROM public.user WHERE username = %s", (recipient,))
        result = cur.fetchone()
        encrypted_method = result[0]

    encrypted_message = None
    try:
        if encrypted_method == 1:
            encrypted_message = gnupg.encrypt_message(message, recipient)
        elif encrypted_method == 2:
            encrypted_message = aes.encrypt_message(message, recipient)
        elif encrypted_method == 3:
            pass
    except ValueError:
        return 'Error, maybe wrong recipient'
    return jsonify({'encrypted_message': encrypted_message.decode('utf-8')})


@app.route('/decrypt_message', methods=['POST'])
def decrypt_message():
    data = request.get_json()
    encrypted_message = data['content']
    encrypted_method = None
    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("SELECT encrypted_method FROM public.user WHERE username = %s", (current_user,))
        result = cur.fetchone()
        encrypted_method = result[0]

    decrypted_message = None
    try:
        if encrypted_method == 1:
            decrypted_message = gnupg.decrypt_message(encrypted_message, current_passphrase).decode('utf-8')
        elif encrypted_method == 2:
            decrypted_message = aes.decrypt_message(encrypted_message, current_user, current_passphrase).decode('utf-8')
        elif encrypted_method == 3:
            pass
    except ValueError:
        return 'Error,maybe wrong password'
    return jsonify({'decrypted_message': decrypted_message})


def read_from_file(directory, filename):
    path = os.path.join(directory, filename)
    with open(path, 'rb') as file:
        return file.read()


def get_user_ids_and_public_keys(
        conn,
        from_address: str,
        to_address: List[str],
        cc_address: Optional[List[str]] = None,
        bcc_address: Optional[List[str]] = None
) -> Tuple[List[int], List[ed25519.Ed25519PublicKey]]:
    # Collect all relevant addresses into a single list
    addresses = [from_address] + to_address
    if cc_address:
        addresses += cc_address
    if bcc_address:
        addresses += bcc_address

    user_ids = []
    public_keys = []

    with conn.cursor() as cur:
        # Construct the SQL query with placeholders for the addresses
        query = """
            SELECT id, public_key_email_bytes
            FROM public."user"
            WHERE username = ANY(%s)
            ORDER BY id;
        """
        cur.execute(query, (addresses,))
        rows = cur.fetchall()

        for row in rows:
            user_id = row[0]
            public_key_bytes = row[1]
            public_key = x25519.X25519PublicKey.from_public_bytes(bytes(public_key_bytes))
            user_ids.append(user_id)
            public_keys.append(public_key)

    return user_ids, public_keys

@app.route('/send_mail_with_sender', methods=['POST'])
def send_mail_with_sender():
    data = request.get_json()
    from_address = data['from']
    to_address = data['to']
    cc_address = data.get('cc', [])
    bcc_address = data.get('bcc', [])
    subject = data['subject']
    content = data['content']
    pieces = [subject, content]

    to_address = [to_address]
    conn = get_db_connection()
    user_ids, public_keys = get_user_ids_and_public_keys(conn, from_address, to_address, cc_address, bcc_address)
    conn.close()

    ciphertexts, bcc_commitment, commitment_key, recipient_digests_signature, public_key, recipient_ciphertexts, manifest_encrypted, manifest_encrypted_hash, xcha_nonces = main_encrypt(
        pieces, bcc_address, public_keys, user_ids, 1.0
    )

    encryption_data = {
        'ciphertexts': ciphertexts,
        'bcc_commitment': bcc_commitment,
        'commitment_key': commitment_key,
        'recipient_digests_signature': recipient_digests_signature,
        'public_key': public_key,
        'recipient_ciphertexts': recipient_ciphertexts,
        'manifest_encrypted': manifest_encrypted,
        'manifest_encrypted_hash': manifest_encrypted_hash,
        'xcha_nonces': xcha_nonces,
        'user_ids': bytes(user_ids)
    }

    print("Ciphertexts:", ciphertexts)
    print("BCC Commitment:", bcc_commitment.hex())
    print("Commitment Key:", commitment_key.hex())
    print("Recipient Digests Signature:", recipient_digests_signature.hex())
    print("Ephemeral Public Key:",
          public_key.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw).hex())
    print("Recipient Ciphertexts:", [ciphertext.hex() for ciphertext in recipient_ciphertexts])


    def encode_item(item):
        if isinstance(item, bytes):
            return base64.b64encode(item).decode('utf-8')
        elif isinstance(item, list):
            return [base64.b64encode(i).decode('utf-8') for i in item]
        elif isinstance(item, X25519PublicKey):
            public_key_bytes = item.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            return base64.b64encode(public_key_bytes).decode('utf-8')
        else:
            return item

    encryption_data_encoded = {key: encode_item(value) for key, value in encryption_data.items()}

    # Check if cc_address and bcc_address are empty and replace with '{}'
    cc_address = cc_address if cc_address else '{}'
    bcc_address = bcc_address if bcc_address else '{}'

    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO public.mail (sender, recipient, cc, bcc, date, encryption_data)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (from_address, to_address[0], cc_address, bcc_address, datetime.datetime.now(), json.dumps(encryption_data_encoded)))
        conn.commit()

    # response = requests.post(url + '/send_mail_with_sender_cake', data=json.dumps(encryption_data),
    #                          headers={'Content-Type': 'application/json'})

    return 'Mail sent successfully'


@app.route('/receive_mail_with_receiver', methods=['POST'])
def receive_mail_with_receiver():
    data = request.form
    username = data.get('username')

    conn = get_db_connection()
    with conn.cursor() as cur:
        cur.execute("""
            SELECT sender, recipient, cc, bcc, date, encryption_data
            FROM public.mail
            WHERE recipient = %s
            ORDER BY date DESC
        """, (username,))
        mails = cur.fetchall()

    def decode_item(item):
        if isinstance(item, str):
            return base64.b64decode(item)
        elif isinstance(item, list):
            return [base64.b64decode(i) for i in item]
        else:
            return item

    decrypted_mails = []

    for mail in mails:
        sender = mail[0]
        receiver = mail[1]
        cc = mail[2]
        bcc = mail[3]
        date = mail[4]
        # read encryption data
        encryption_data_encoded = mail[5]
        encryption_data = {key: decode_item(value) for key, value in encryption_data_encoded.items()}
        public_key_bytes = encryption_data['public_key']
        public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)

        # Read the recipient's private key for decryption
        private_key_bytes = read_from_file(username, 'private_email_x25519.bin')
        private_key = x25519.X25519PrivateKey.from_private_bytes(bytes(private_key_bytes))

        # Read the receiver's public key from file
        receiver_public_key_bytes = read_from_file(username, 'public_email_x25519.bin')
        receiver_public_key = x25519.X25519PublicKey.from_public_bytes(bytes(receiver_public_key_bytes))

        # # Read the receiver's public key
        # with conn.cursor() as cur:
        #     cur.execute("""
        #                 SELECT public_key_email_bytes
        #                 FROM public."user"
        #                 WHERE username = %s
        #             """, (sender,))
        #     sender_public_key_bytes = cur.fetchone()[0]
        #     sender_public_key = x25519.X25519PublicKey.from_public_bytes(bytes(sender_public_key_bytes))

        print(encryption_data['xcha_nonces'])

        # Decrypt the email
        decrypted_pieces = decrypt_email(
            encryption_data['ciphertexts'],
            encryption_data['recipient_ciphertexts'][1],
            public_key,
            private_key,
            receiver_public_key,
            encryption_data['manifest_encrypted'],
            encryption_data['manifest_encrypted_hash'],
            encryption_data['bcc_commitment'],
            1.0,  # Assuming version 1.0 as used in encryption
            encryption_data['xcha_nonces'][1],
            encryption_data['user_ids'],
        )

        decrypted_mail = {
            'sender': sender,
            'receiver': receiver,
            'cc': cc,
            'date': date,
            'subject': decrypted_pieces[0].decode('utf-8'),
            'content': decrypted_pieces[1].decode('utf-8')
        }
        decrypted_mails.append(decrypted_mail)

    conn.close()
    print(decrypted_mails)
    return jsonify(decrypted_mails)


@app.route('/send_mail')
def send_mail():
    return 'Mail sent successfully'


if __name__ == '__main__':
    app.run()
