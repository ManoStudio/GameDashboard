import os
import json
from flask import Flask, render_template, request, redirect, url_for
import firebase_admin
from firebase_admin import credentials, firestore

app = Flask(__name__)

# --- Firebase Initialization with Vercel's Environment Variables ---
try:
    # Read private key from environment variable, replacing escaped newlines
    private_key_content = os.getenv('private_key', '').replace('\\n', '\n')

    # Construct the credentials dictionary from environment variables
    cred_dict = {
        "type": os.getenv('type', ''),
        "project_id": os.getenv('project_id', ''),
        "private_key_id": os.getenv('private_key_id', ''),
        "private_key": private_key_content,
        "client_email": os.getenv('client_email', ''),
        "client_id": os.getenv('client_id', ''),
        "auth_uri": os.getenv('auth_uri', ''),
        "token_uri": os.getenv('token_uri', ''),
        "auth_provider_x509_cert_url": os.getenv('auth_provider_x509_cert_url', ''),
        "client_x509_cert_url": os.getenv('client_x509_cert_url', '')
    }

    if not cred_dict.get('type') or cred_dict.get('type') != 'service_account':
        raise ValueError('Invalid service account certificate. Certificate must contain a "type" field set to "service_account".')

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