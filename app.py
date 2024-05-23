import ssl

from flask import Flask, request, render_template, jsonify, request, redirect, url_for
from flask_bcrypt import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from smtplib import SMTP
from flask_cors import CORS
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import List, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519


import psycopg2
import Config

app = Flask(__name__)
app.secret_key = 'your secret key'
CORS(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = '/'


class User(UserMixin):
    def __init__(self, id, password):
        self.id = id
        self.password = password

    def get_id(self):
        return self.id

    def get_password(self):
        return self.password


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/mailbox')
@login_required
def mailbox():
    return render_template('mailBox.html')


@app.route('/send_mail', methods=['POST'])
@login_required
def send_mail():
    data = request.get_json()
    to = data['to']
    subject = data['subject']
    content = data['content']

    msg = MIMEMultipart()
    msg['From'] = current_user.id
    msg['To'] = to
    msg['Subject'] = subject
    msg.attach(MIMEText(content, 'plain'))

    client = SMTP(Config.get_smtp_server(), Config.get_smtp_port())
    client.starttls()
    client.login(current_user.id, current_user.password)
    client.send_message(msg)

    return 'Mail sent successfully'


@app.route('/receive_mail', methods=['GET'])
@login_required
def receive_mail():
    # return all emails in the database belong to login user
    conn = psycopg2.connect(host=Config.get_pg_host(), port=Config.get_pg_port(), dbname=Config.get_pg_database(),
                            user=Config.get_pg_user(), password=Config.get_pg_password())
    cur = conn.cursor()
    cur.execute("SELECT sender,date,subject,ep.content_type,ep.body FROM public.mail join public.email_parts ep on mail.id = ep.email_id WHERE recipient = %s",
                (current_user.id,))
    mails = cur.fetchall()
    return jsonify(mails)

@app.route('/send_mail_with_sender', methods=['POST'])
def send_mail_with_sender():
    data = request.get_json()
    from_email = data['from']
    to = data['to']
    subject = data['subject']
    content = data['content']
    from_password = data['password']

    conn = psycopg2.connect(host=Config.get_pg_host(), port=Config.get_pg_port(), dbname=Config.get_pg_database(),
                            user=Config.get_pg_user(), password=Config.get_pg_password())
    cur = conn.cursor()
    cur.execute("SELECT * FROM public.User WHERE username = %s", (from_email,))
    user_record = cur.fetchone()
    if user_record is not None and user_record[2] == from_password:
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to
        msg['Subject'] = subject
        msg.attach(MIMEText(content, 'plain'))

        client = SMTP(Config.get_smtp_server(), Config.get_smtp_port())
        client.starttls()
        client.login(from_email, from_password)
        client.send_message(msg)

        return 'Mail sent successfully'
    return 'Invalid username or password'

@app.route('/receive_mail_with_receiver', methods=['POST'])
def receive_mail_with_receiver():
    receiver = request.form.get('username')
    password = request.form.get('password')
    # return all emails in the database belong to login user
    conn = psycopg2.connect(host=Config.get_pg_host(), port=Config.get_pg_port(), dbname=Config.get_pg_database(),
                            user=Config.get_pg_user(), password=Config.get_pg_password())
    cur = conn.cursor()
    cur.execute("SELECT * FROM public.User WHERE username = %s", (receiver,))
    user_record = cur.fetchone()
    if user_record is not None and user_record[2] == password:
        cur.execute(
            "SELECT sender,date,subject,ep.body FROM public.mail join public.email_parts ep on mail.id = ep.email_id WHERE recipient = %s",
            (receiver,))
        mails = cur.fetchall()
        return jsonify(mails)
    return 'Invalid username or password'

@app.route('/get_user_ids_and_public_keys', methods=['POST'])
def get_user_ids_and_public_keys() -> Tuple[List[int], List[ed25519.Ed25519PublicKey]]:
    data = request.get_json()
    from_address = data['from']
    to_address = data['to']
    cc_address = data.get('cc')
    bcc_address = data.get('bcc')
    # Collect all relevant addresses into a single list
    addresses = [from_address] + to_address
    if cc_address:
        addresses += cc_address
    if bcc_address:
        addresses += bcc_address

    user_ids = []
    public_keys = []

    conn = psycopg2.connect(host=Config.get_pg_host(), port=Config.get_pg_port(), dbname=Config.get_pg_database(),
                            user=Config.get_pg_user(), password=Config.get_pg_password())
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

@app.route('/upload_pkey', methods=['POST'])
def upload_pkey():
    data = request.get_json()
    username = data['username']
    pkey = data['pkey']
    conn = psycopg2.connect(host=Config.get_pg_host(), port=Config.get_pg_port(), dbname=Config.get_pg_database(),
                            user=Config.get_pg_user(), password=Config.get_pg_password())
    with conn.cursor() as cur:
        cur.execute("INSERT INTO public.User (public_key_email_bytes,username) VALUES (%s,%s)", (pkey,username))

    conn.commit()
    return 'Upload Successfully'


@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    password = request.form.get('password')
    conn = psycopg2.connect(host=Config.get_pg_host(), port=Config.get_pg_port(), dbname=Config.get_pg_database(),
                            user=Config.get_pg_user(), password=Config.get_pg_password())
    cur = conn.cursor()
    cur.execute("SELECT * FROM public.User WHERE username = %s", (username,))
    if cur.fetchone() is not None:
        return 'User already exists'
    hashed_password = generate_password_hash(password, 10).decode('utf-8')
    cur.execute("INSERT INTO public.User (username, password) VALUES (%s, %s)", (username, hashed_password))
    conn.commit()
    return 'Registered successfully'


@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    conn = psycopg2.connect(host=Config.get_pg_host(), port=Config.get_pg_port(), dbname=Config.get_pg_database(),
                            user=Config.get_pg_user(), password=Config.get_pg_password())
    cur = conn.cursor()
    cur.execute("SELECT * FROM public.User WHERE username = %s", (username,))
    user_record = cur.fetchone()
    if user_record is not None and check_password_hash(user_record[2], password):
        user = User(username, user_record[2])
        login_user(user)
        return redirect(url_for('mailbox'))
    return 'Invalid username or password'


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return 'Logged out successfully'


@login_manager.user_loader
def load_user(user_id):
    conn = psycopg2.connect(host=Config.get_pg_host(), port=Config.get_pg_port(), dbname=Config.get_pg_database(),
                            user=Config.get_pg_user(), password=Config.get_pg_password())
    cur = conn.cursor()
    cur.execute("SELECT * FROM public.User WHERE username = %s", (user_id,))
    user_record = cur.fetchone()
    if user_record is not None:
        return User(user_id, user_record[2])
    raise Exception('User not found')


if __name__ == '__main__':
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain('certificates/certificate.crt', 'certificates/private.key')
    app.run(host=Config.get_flask_host(),ssl_context=context,debug=True)
