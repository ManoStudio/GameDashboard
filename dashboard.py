import os
import json
from flask import Flask, render_template, request, redirect, url_for
import firebase_admin
from firebase_admin import credentials, firestore

app = Flask(__name__)

# --- Firebase Initialization with Environment Variables ---
try:
    # Read private key from environment variable, replacing escaped newlines
    private_key_content = os.getenv('FIREBASE_PRIVATE_KEY', 'default_value').replace('\\n', '\n')

    # Construct the credentials dictionary from environment variables
    cred_dict = {
        "type": os.getenv('FIREBASE_TYPE', ''),
        "project_id": os.getenv('FIREBASE_PROJECT_ID', ''),
        "private_key_id": os.getenv('FIREBASE_PRIVATE_KEY_ID', ''),
        "private_key": private_key_content,
        "client_email": os.getenv('FIREBASE_CLIENT_EMAIL', ''),
        "client_id": os.getenv('FIREBASE_CLIENT_ID', ''),
        "auth_uri": os.getenv('FIREBASE_AUTH_URI', ''),
        "token_uri": os.getenv('FIREBASE_TOKEN_URI', ''),
        "auth_provider_x509_cert_url": os.getenv('FIREBASE_AUTH_PROVIDER_X509_CERT_URL', ''),
        "client_x509_cert_url": os.getenv('FIREBASE_CLIENT_X509_CERT_URL', '')
    }
    
    if not firebase_admin._apps:
        cred = credentials.Certificate(cred_dict)
        firebase_admin.initialize_app(cred)
    db = firestore.client()
except Exception as e:
    print(f"Failed to initialize Firebase with environment variables: {e}")
    exit()

@app.route('/')
def index():
    """Display the list of games and their status."""
    games = db.collection('games').stream()
    game_list = [{
        'id': game.id,
        'info': game.to_dict()
    } for game in games]
    return render_template('index.html', games=game_list)

@app.route('/update_status/<game_id>', methods=['POST'])
def update_status(game_id):
    """Update the status of a game."""
    new_status = request.form.get('status')
    if new_status in ['ready', 'dev']:
        db.collection('games').document(game_id).update({'status': new_status})
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)