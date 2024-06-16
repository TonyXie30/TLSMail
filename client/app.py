from flask import Flask, render_template, request, jsonify
from flask_bcrypt import generate_password_hash
import psycopg2

import Config
import gpg
import AES

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


@app.route('/generate_key', methods=['POST'])
def generate_key():
    data = request.get_json()
    encrypt_method = data['encryption_method']
    username = data['username']
    passphrase = data['passphrase']
    private_key = None
    if encrypt_method == 'OpenPGP':
        private_key = gnupg.generate_key(username=username, passphrase=passphrase)
    elif encrypt_method == 'AES':
        private_key = aes.generate_key(username=username, passphrase=passphrase)
    return jsonify({'private_key': private_key})


@app.route('/encrypt_message', methods=['POST'])
def encrypt_message():
    data = request.get_json()
    message = data['content']
    recipient = data['recipient']
    try:
        encrypted_message = gnupg.encrypt_message(message, recipient)
    except ValueError:
        return 'Error, maybe wrong recipient'
    return jsonify({'encrypted_message': encrypted_message.decode('utf-8')})


@app.route('/decrypt_message', methods=['POST'])
def decrypt_message():
    data = request.get_json()
    encrypted_message = data['content']
    try:
        decrypted_message = gnupg.decrypt_message(encrypted_message, current_passphrase).decode('utf-8')
    except ValueError:
        return 'Error,maybe wrong password'
    return jsonify({'decrypted_message': decrypted_message})


@app.route('/send_mail')
def send_mail():
    return 'Mail sent successfully'


if __name__ == '__main__':
    app.run()
