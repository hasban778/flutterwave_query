from flask import Flask, request, jsonify, session
from flask_session import Session
import requests
import os
import sqlite3
import string
import random
from dotenv import load_dotenv
import logging

load_dotenv()

app = Flask(__name__)

# Secret key for session management
app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')
app.config['SESSION_TYPE'] = 'filesystem'

Session(app)

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Dummy user data
USER_DATA = {
    "username": "testusercorniche",
    "password": "password890/CSG![HELLO}Street"
}

# Initialize the SQLite database
def init_db():
    conn = sqlite3.connect('transactions.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tx_ref TEXT UNIQUE
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def generate_unique_transaction_reference():
    while True:
        tx_ref = ''.join(random.choices(string.ascii_uppercase + string.digits, k=14))
        if not tx_ref_exists(tx_ref):
            return tx_ref

def tx_ref_exists(tx_ref):
    conn = sqlite3.connect('transactions.db')
    cursor = conn.cursor()
    cursor.execute('SELECT 1 FROM transactions WHERE tx_ref = ?', (tx_ref,))
    exists = cursor.fetchone() is not None
    conn.close()
    return exists

# @app.before_request
# def log_request_info():
#     logger.info('Headers: %s', request.headers)
#     logger.info('Body: %s', request.get_data())

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    username = data.get('username')
    password = data.get('password')

    if username == USER_DATA['username'] and password == USER_DATA['password']:
        session['user'] = username
        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/logout', methods=['GET'])
def logout():
    session.pop('user', None)
    return jsonify({'message': 'Logged out successfully'}), 200

def login_required(f):
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/create', methods=['POST'])
@login_required
def create():
    data = request.get_json()

    name = data.get('name')
    email = data.get('email')
    phone = data.get('phone')
    amount = data.get('amount')
    currency = data.get('currency')
    redirect_url = data.get('redirect_url')
    title = data.get('title')

    if not all([name, email, phone, amount, currency,redirect_url,title]):
        return jsonify({'error': 'Missing data'}), 400

    tx_ref = generate_unique_transaction_reference()

    # Save the transaction reference to the database
    conn = sqlite3.connect('transactions.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO transactions (tx_ref) VALUES (?)', (tx_ref,))
    conn.commit()
    conn.close()

    flutterwave_payload = {
        'tx_ref': tx_ref,
        'amount': amount,
        'currency': currency,
        'redirect_url': redirect_url,
        'customer': {
            'email': email,
            'name': name,
            'phonenumber': phone
        },
        'customizations': {
            'title': title
        }
    }

    try:
        response = requests.post(
            'https://api.flutterwave.com/v3/payments',
            json=flutterwave_payload,
            headers={
                'Authorization': f'Bearer {os.getenv("FLW_SECRET_KEY")}',
                'Content-Type': 'application/json'
            }
        )
        response.raise_for_status()  # This will raise an HTTPError if the HTTP request returned an unsuccessful status code
        data = response.json()
        return jsonify(data), response.status_code

    except requests.exceptions.RequestException as err:
        return jsonify({
            'error': 'Request failed',
            'status_code': err.response.status_code if err.response else "No response",
            'message': err.response.text if err.response else str(err)
        }), 500

    except Exception as e:
        return jsonify({
            'error': 'An error occurred',
            'message': str(e)
        }), 500

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'error': 'Bad request'}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized'}), 401

@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
