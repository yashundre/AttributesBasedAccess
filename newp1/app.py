from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from base64 import b64encode, b64decode
from datetime import timedelta, datetime
import json, os
from flask import Flask, render_template, request

app = Flask(__name__)

# Create an empty dictionary as the static database
static_database = {}

#Phase 1 Algorithm
def UPDATE_PUBLICATION(pkgu, CID, SID, wu):
    # Generate a unique token to identify the update
    T_okenu = (SHA256.new(pkgu.encode()).hexdigest(), CID, SID)

    # Generate a secret key for the update
    ku = get_random_bytes(16)
    ku_encrypted = b64encode(ku).decode()

    # Encrypt the access policy (wu)
    wu_encrypted = encrypt_aes(json.dumps(wu).encode(), ku)

    # Store the token, secret key, and encrypted access policy in the static database
    static_database[T_okenu] = {'ku': ku_encrypted, 'wu': wu_encrypted}

    # Encrypt the publisher's public key
    pkgu_encrypted = encrypt_aes(pkgu.encode(), ku)

    # Store the encrypted update, payloads, and revocation list in the static database
    static_database[T_okenu]['pkgu_encrypted'] = pkgu_encrypted
    static_database[T_okenu]['revocation_list'] = []


def encrypt_aes(plaintext, key):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    iv = cipher.iv
    encrypted_data = iv + ciphertext
    encrypted_data_base64 = b64encode(encrypted_data).decode()
    return encrypted_data_base64


def REVOKE(Attri, T_okenu):
    if T_okenu in static_database:
        static_database[T_okenu]['revocation_list'].append(Attri)
    else:
        raise Exception("Update not found in the static database")


def save_static_database(static_database, file_name):
    static_database_str = {str(key): value for key, value in static_database.items()}
    parent_dir = os.path.dirname(os.getcwd())
    file_path = os.path.join(parent_dir, file_name)

    os.makedirs(os.path.dirname(file_path), exist_ok=True)  # Create the parent directory if it doesn't exist
    print("line 60")
    try:
        with open(file_path, 'w+') as file:
            json.dump(static_database_str, file, indent=4)
    except:
        print("error")


@app.route('/', methods=['GET', 'POST'])
def display_database():
    if request.method == 'POST':
        pkgu = request.form['pkgu']
        CID = request.form['CID']
        SID = request.form['SID']
        wu = {
            "Manufacturing_year": request.form['Manufacturing_year'],
            "model": request.form['model']
        }
        UPDATE_PUBLICATION(pkgu, CID, SID, wu)
        save_static_database(static_database,'Combined\static_database.json')
    return render_template('index.html', static_database=static_database)


if __name__ == '__main__':
    app.run(debug=True)
