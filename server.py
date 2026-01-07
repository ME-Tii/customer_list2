from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room
from werkzeug.utils import secure_filename
import sqlite3
import os

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize database and uploads folder
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, from_user TEXT, to_user TEXT, message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('INSERT OR IGNORE INTO users VALUES (?, ?)', ('admin', 'password'))
    conn.commit()
    conn.close()
    os.makedirs('uploads', exist_ok=True)

init_db()

online_users = set()

init_db()

def get_user(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT password FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None

def add_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users VALUES (?, ?)', (username, password))
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    conn.close()
    return success

@app.route('/')
def index():
    return send_from_directory('.', 'login.html')

@app.route('/register.html')
def register_page():
    return send_from_directory('.', 'register.html')

@app.route('/chat.html')
def chat_page():
    return send_from_directory('.', 'chat.html')

@app.route('/users')
def get_users():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT username FROM users')
    users = [row[0] for row in c.fetchall()]
    conn.close()
    return jsonify(users)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join('uploads', filename)
        try:
            file.save(filepath)
            return jsonify({'url': f'/uploads/{filename}'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

@app.route('/uploads/<path:filename>')
def serve_upload(filename):
    return send_from_directory('uploads', filename)

@app.route('/messages')
def get_messages():
    username = request.args.get('username')
    to_user = request.args.get('to')
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    if to_user:
        c.execute('SELECT from_user, message, timestamp FROM messages WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?) ORDER BY timestamp', (username, to_user, to_user, username))
    else:
        c.execute('SELECT from_user, message, timestamp FROM messages WHERE to_user IS NULL ORDER BY timestamp')
    messages = [{'from': row[0], 'message': row[1], 'timestamp': row[2]} for row in c.fetchall()]
    conn.close()
    return jsonify(messages)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    stored_password = get_user(username)
    if stored_password and stored_password == password:
        return jsonify({'success': True, 'message': 'Login successful'})
    else:
        return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    confirm_password = data.get('confirm_password')
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'}), 400
    if password != confirm_password:
        return jsonify({'success': False, 'message': 'Passwords do not match'}), 400
    if get_user(username):
        return jsonify({'success': False, 'message': 'User already exists'}), 409
    add_user(username, password)
    return jsonify({'success': True, 'message': 'Registration successful'})

@socketio.on('join')
def on_join(data):
    username = data['username']
    online_users.add(username)
    join_room(username)
    emit('user_online', username, broadcast=True, skip_sid=request.sid)
    emit('online_users', list(online_users))

@socketio.on('leave')
def on_leave(data):
    username = data['username']
    online_users.discard(username)
    emit('user_offline', username, broadcast=True, skip_sid=request.sid)

@socketio.on('send_message')
def on_send_message(data):
    username = data['username']
    message = data['message']
    to_user = data.get('to')
    # Store in db
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO messages (from_user, to_user, message) VALUES (?, ?, ?)', (username, to_user, message))
    conn.commit()
    conn.close()
    if to_user:
        # Private message
        emit('private_message', {'from': username, 'message': message, 'to': to_user}, room=to_user)
        emit('private_message', {'from': username, 'message': message, 'to': to_user}, room=username)
    else:
        # Public message
        emit('public_message', {'from': username, 'message': message}, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, debug=True, allow_unsafe_werkzeug=True, port=3000)