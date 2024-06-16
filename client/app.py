import datetime
import json

import requests
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
            public_key = x25519.X25519PublicKey.from_public_bytes(public_key_bytes)
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

    conn = get_db_connection()
    user_ids, public_keys = get_user_ids_and_public_keys(conn, from_address, to_address, cc_address, bcc_address)

    sender_device_private_key = read_from_file(from_address, 'private_email_x25519.bin')
    sender_device_private_key = x25519.X25519PrivateKey.from_private_bytes(sender_device_private_key)

    ciphertexts, bcc_commitment, commitment_key, recipient_digests_signature, public_key, recipient_ciphertexts, manifest_encrypted, manifest_encrypted_hash, xcha_nonces = main_encrypt(
        pieces, bcc_address, public_keys, user_ids, 1.0, sender_device_private_key
    )

    encryption_data = {
        'sender': from_address,
        'recipient': to_address,
        'cc': cc_address,
        'bcc': bcc_address,
        'ciphertexts': ciphertexts,
        'bcc_commitment': bcc_commitment,
        'commitment_key': commitment_key,
        'recipient_digests_signature': recipient_digests_signature,
        'public_key': public_key,
        'recipient_ciphertexts': recipient_ciphertexts,
        'manifest_encrypted': manifest_encrypted,
        'manifest_encrypted_hash': manifest_encrypted_hash,
        'xcha_nonces': xcha_nonces,
    }

    response = requests.post(url + '/send_mail_with_sender_cake', data=json.dumps(encryption_data),
                             headers={'Content-Type': 'application/json'})

    return response.json()


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

    decrypted_mails = []

    for mail in mails:
        sender = mail[0]
        receiver = mail[1]
        cc = mail[2]
        bcc = mail[3]
        date = mail[4]
        encryption_data = json.loads(mail[5])

        # Read the recipient's private key for decryption
        private_key_bytes = read_from_file(username, 'private_email_x25519.bin')
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_bytes)

        # Read the sender's public key
        cur.execute("""
            SELECT public_key_email_bytes
            FROM public."user"
            WHERE username = %s
        """, (sender,))
        sender_public_key_bytes = cur.fetchone()[0]
        sender_public_key = x25519.X25519PublicKey.from_public_bytes(sender_public_key_bytes)

        # Decrypt the email
        decrypted_pieces = decrypt_email(
            encryption_data['ciphertexts'],
            encryption_data['recipient_ciphertexts'][0],
            encryption_data['public_key'],
            private_key,
            sender_public_key,
            encryption_data['manifest_encrypted'],
            encryption_data['manifest_encrypted_hash'],
            encryption_data['bcc_commitment'],
            1.0,  # Assuming version 1.0 as used in encryption
            encryption_data['xcha_nonces'][0],
            encryption_data['user_ids'],
            sender_device_key=sender_public_key
        )

        decrypted_mail = {
            'sender': sender,
            'receiver': receiver,
            'cc': cc,
            'date': date,
            'subject': decrypted_pieces[0],
            'content': decrypted_pieces[1]
        }
        decrypted_mails.append(decrypted_mail)

    conn.close()

    return jsonify(decrypted_mails)


@app.route('/send_mail')
def send_mail():
    return 'Mail sent successfully'


if __name__ == '__main__':
    app.run()
