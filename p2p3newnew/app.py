from flask import Flask, request, render_template
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from base64 import b64decode
import json
import ast, os

app = Flask(__name__)

#Phase 2 Update Selection
def read_static_database(filename):
    parent_dir = os.path.dirname(os.getcwd())
    file_path = os.path.join(parent_dir, filename)

    with open(file_path, 'r') as file:
        static_database_str = json.load(file)

    # Convert the keys back to their original tuple format
    static_database = {tuple(eval(key)): value for key, value in static_database_str.items()}

    return static_database


# Specify the filename of the JSON file
filename = 'Combined\static_database.json'

# Call the read_static_database function
static_database = read_static_database(filename)

def UPDATE_SELECTION(N, consumer_vehicle_attributes):
    # Retrieve the set of available updates from phase one (static_database)
    update_set = static_database.values()

    # Initialize a list of candidate updates
    candidate_updates = []

    # Iterate through each update and check if it meets the desired criteria
    for update in update_set:
        access_policy_encrypted = update['wu']
        access_policy = decrypt_aes(access_policy_encrypted, update['ku'])
        access_policyd = ast.literal_eval(access_policy)
        
        if meets_criteria(access_policyd, consumer_vehicle_attributes):
            candidate_updates.append(update)

    # Return the top N updates from the sorted list
    return candidate_updates

def meets_criteria(access_policy, consumer_vehicle_attributes):
    for key, value in access_policy.items():
        if key not in consumer_vehicle_attributes or consumer_vehicle_attributes[key] != value:
            return False
    return True

def decrypt_aes(encrypted_data_base64, ku_encrypted):
    encrypted_data = b64decode(encrypted_data_base64)
    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    key = b64decode(ku_encrypted)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

# AES decryption function
def decrypt_aes2(ciphertext_base64, key):
    ciphertext = b64decode(ciphertext_base64)
    iv = ciphertext[:AES.block_size]
    ciphertext = ciphertext[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
    decrypted_data = decrypted_data.decode()
    return decrypted_data

def decrypt_updates(updates):
    decrypted_updatess = []
    for update in updates:
        pkgu_encrypted = update['pkgu_encrypted']
        ku_encrypted = update['ku']
        ku = b64decode(ku_encrypted)
        try:
            pkgu = decrypt_aes2(pkgu_encrypted, ku)
        except Exception as e:
            print("Decryption error:", str(e))
            pkgu = None

        decrypted_update = {
            'pkgu': pkgu
        }

        decrypted_updatess.append(decrypted_update)

    return decrypted_updatess


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    # Retrieve the consumer vehicle attributes from the form submitted by the browser
    manufacturing_year = request.form.get('manufacturing_year')
    model = request.form.get('model')

    # Construct the consumer vehicle attributes dictionary
    consumer_vehicle_attributes = {
        "Manufacturing_year": manufacturing_year,
        "model": model
    }

    # Call the UPDATE_SELECTION function from Phase 2
    N = 5  # Number of updates to retrieve
    selected_updates = UPDATE_SELECTION(N, consumer_vehicle_attributes)

    # Decrypt the selected updates
    decrypted_updates = decrypt_updates(selected_updates)

    if not decrypted_updates:
        message = "No latest update for you."
        return render_template('result.html', message=message)

    return render_template('result.html', updates=decrypted_updates)


if __name__ == '__main__':
    app.run(debug=True,port=8080)
