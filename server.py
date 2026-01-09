from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room
from werkzeug.utils import secure_filename
import sqlite3
import os
import random

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize database and uploads folder
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Check if users table exists and has the correct structure
    c.execute('''SELECT sql FROM sqlite_master WHERE type='table' AND name='users' ''')
    table_info = c.fetchone()
    
    if table_info and 'verified' not in table_info[0]:
        # Drop old table and create new one with verified column
        c.execute('DROP TABLE users')
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, verified INTEGER DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, from_user TEXT, to_user TEXT, message TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, read INTEGER DEFAULT 0)''')
    
    # Check if read column exists in messages table
    c.execute('''PRAGMA table_info(messages)''')
    columns = [row[1] for row in c.fetchall()]
    if 'read' not in columns:
        c.execute('''ALTER TABLE messages ADD COLUMN read INTEGER DEFAULT 0''')
    c.execute('INSERT OR IGNORE INTO users VALUES (?, ?, ?)', ('admin', 'password', 1))
    c.execute('INSERT OR IGNORE INTO users VALUES (?, ?, ?)', ('user1', 'user1', 1))
    c.execute('INSERT OR IGNORE INTO users VALUES (?, ?, ?)', ('user2', 'user2', 1))
    c.execute('INSERT OR IGNORE INTO users VALUES (?, ?, ?)', ('user3', 'user3', 1))
    c.execute('INSERT OR IGNORE INTO users VALUES (?, ?, ?)', ('grok', 'grok', 1))
    c.execute('INSERT OR IGNORE INTO users VALUES (?, ?, ?)', ('big_5', 'big_5', 1))
    c.execute('INSERT OR IGNORE INTO users VALUES (?, ?, ?)', ('claude', 'claude', 1))
    c.execute('INSERT OR IGNORE INTO users VALUES (?, ?, ?)', ('gemini', 'gemini', 1))
    conn.commit()
    conn.close()
    os.makedirs('uploads', exist_ok=True)

init_db()

online_users = set()

def get_user(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT password, verified FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()
    return result if result else None

def add_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users VALUES (?, ?, ?)', (username, password, 0))
        conn.commit()
        success = True
    except sqlite3.IntegrityError:
        success = False
    conn.close()
    return success

@app.route('/')
def index():
    return send_from_directory('.', 'login.html')

@app.route('/login.html')
def login_page():
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
    if file and file.filename:
        filename = secure_filename(file.filename)
        filepath = os.path.join('uploads', filename)
        try:
            file.save(filepath)
            return jsonify({'url': f'/uploads/{filename}'})
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'File processing failed'}), 400

@app.route('/uploads/<filename>')
def serve_upload(filename):
    return send_from_directory('uploads', filename)

@app.route('/icons/<path:filename>')
def serve_icons(filename):
    return send_from_directory('icons', filename)


@app.route('/test_route')
def test_route():
    return jsonify({'message': 'Test route working'})

@app.route('/messages')
def get_messages():
    username = request.args.get('username')
    to_user = request.args.get('to')
    from_user = request.args.get('from')
    admin_user = request.args.get('admin_user')  # New parameter for admin request
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    if admin_user:
        # Admin requesting all messages from a specific user
        c.execute('SELECT from_user, to_user, message, timestamp FROM messages WHERE from_user = ? ORDER BY timestamp', (admin_user,))
        rows = c.fetchall()
        messages = []
        for row in rows:
            messages.append({
                'from': row[0], 
                'to': row[1] if row[1] else 'Public', 
                'message': row[2], 
                'timestamp': row[3]
            })
    elif from_user:
        # Get all messages from a specific user (both public and private)
        c.execute('SELECT from_user, to_user, message, timestamp FROM messages WHERE from_user = ? ORDER BY timestamp', (from_user,))
        rows = c.fetchall()
        messages = []
        for row in rows:
            messages.append({
                'from': row[0], 
                'to': row[1] if row[1] else 'Public', 
                'message': row[2], 
                'timestamp': row[3]
            })
    elif to_user:
        c.execute('SELECT from_user, message, timestamp FROM messages WHERE (from_user = ? AND to_user = ?) OR (from_user = ? AND to_user = ?) ORDER BY timestamp', (username, to_user, to_user, username))
        messages = [{'from': row[0], 'message': row[1], 'timestamp': row[2]} for row in c.fetchall()]
        # Mark messages as read
        c.execute('UPDATE messages SET read = 1 WHERE from_user = ? AND to_user = ? AND read = 0', (to_user, username))
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
    user_data = get_user(username)
    if user_data:
        stored_password, verified = user_data
        if stored_password == password:
            if verified:
                return jsonify({'success': True, 'message': 'Login successful'})
            else:
                return jsonify({'success': False, 'message': 'Account pending admin verification'})
    return jsonify({'success': False, 'message': 'Invalid credentials'}), 401

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    confirm_password = data.get('confirm_password')
    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password required'})
    if password != confirm_password:
        return jsonify({'success': False, 'message': 'Passwords do not match'})
    if get_user(username):
        return jsonify({'success': False, 'message': 'User already exists'})
    add_user(username, password)
    return jsonify({'success': True, 'message': 'Registration successful. Awaiting admin verification.'})

@app.route('/admin.html')
def admin_page():
    return send_from_directory('.', 'admin.html')

@app.route('/admin/delete_user/<username>', methods=['DELETE'])
def delete_user(username):
    if username == 'admin':
        return jsonify({'message': 'Cannot delete admin user'})
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DELETE FROM users WHERE username = ?', (username,))
    c.execute('DELETE FROM messages WHERE from_user = ? OR to_user = ?', (username, username))
    conn.commit()
    conn.close()
    return jsonify({'message': f'User {username} deleted successfully'})

@app.route('/admin/delete_all_messages', methods=['DELETE'])
def delete_all_messages():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DELETE FROM messages')
    conn.commit()
    conn.close()
    return jsonify({'message': 'All messages deleted successfully'})

@app.route('/admin/delete_all_users', methods=['DELETE'])
def delete_all_users():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DELETE FROM users WHERE username != ?', ('admin',))
    c.execute('DELETE FROM messages WHERE from_user != ? AND to_user != ?', ('admin', 'admin'))
    conn.commit()
    conn.close()
    return jsonify({'message': 'All users (except admin) deleted successfully'})

@app.route('/admin/reset_db', methods=['DELETE'])
def reset_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DELETE FROM users WHERE username != ?', ('admin',))
    c.execute('DELETE FROM messages')
    conn.commit()
    conn.close()
    return jsonify({'message': 'Database reset successfully'})

@app.route('/admin/get_users')
def get_users_with_verification():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT username, verified FROM users')
    users = [{'username': row[0], 'verified': bool(row[1])} for row in c.fetchall()]
    conn.close()
    return jsonify(users)

@app.route('/admin/verify_user/<username>', methods=['POST'])
def verify_user(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('UPDATE users SET verified = 1 WHERE username = ?', (username,))
    conn.commit()
    conn.close()
    return jsonify({'message': f'User {username} verified successfully'})

@app.route('/unread')
def get_unread():
    username = request.args.get('username')
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT DISTINCT from_user FROM messages WHERE to_user = ? AND read = 0', (username,))
    unread = [row[0] for row in c.fetchall()]
    conn.close()
    return jsonify(unread)

@app.route('/settings.html')
def settings_page():
    return send_from_directory('.', 'settings.html')

@app.route('/change_password', methods=['POST'])
def change_password():
    data = request.get_json()
    username = data.get('username')
    current_password = data.get('currentPassword')
    new_password = data.get('newPassword')
    
    stored_password = get_user(username)
    if not stored_password:
        return jsonify({'success': False, 'message': 'User not found'}), 400
    
    stored_password_hash, verified = stored_password
    if stored_password_hash != current_password:
        return jsonify({'success': False, 'message': 'Current password incorrect'}), 400
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('UPDATE users SET password = ? WHERE username = ?', (new_password, username))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Password changed successfully'})

@app.route('/delete_account', methods=['DELETE'])
def delete_account():
    data = request.get_json()
    username = data.get('username')
    
    if username == 'admin':
        return jsonify({'success': False, 'message': 'Cannot delete admin account'})
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('DELETE FROM users WHERE username = ?', (username,))
    c.execute('DELETE FROM messages WHERE from_user = ? OR to_user = ?', (username, username))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'message': 'Account deleted successfully'})

@socketio.on('join')
def on_join(data):
    username = data['username']
    online_users.add(username)
    join_room(username)
    # Save join message to db
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO messages (from_user, to_user, message) VALUES (?, ?, ?)', ('System', None, f'{username} has joined the chat.'))
    conn.commit()
    conn.close()
    emit('user_online', username, broadcast=True, include_self=False)
    emit('online_users', list(online_users))

@socketio.on('leave')
def on_leave(data):
    username = data['username']
    online_users.discard(username)
    # Save leave message to db
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO messages (from_user, to_user, message) VALUES (?, ?, ?)', ('System', None, f'{username} has left the chat.'))
    conn.commit()
    conn.close()
    emit('user_offline', username, broadcast=True, include_self=False)
    emit('online_users', list(online_users))

@socketio.on('send_message')
def on_send_message(data):
    username = data['username']
    message = data['message']
    to_user = data.get('to')
    print(f"Send message: from {username} to {to_user}: {message}")
    # Store in db
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('INSERT INTO messages (from_user, to_user, message) VALUES (?, ?, ?)', (username, to_user, message))
    conn.commit()
    conn.close()
    if to_user:
        # Private message
        emit('private_message', {'from': username, 'message': message, 'to': to_user}, to=to_user)
        emit('private_message', {'from': username, 'message': message, 'to': to_user}, to=username)
        # Predefined response lists
        general_responses = [
            "That's cool!",
            "Tell me more.",
            "Interesting!",
            "I agree.",
            "What do you think?",
            "Nice one!",
            "Good point.",
            "Hmm, okay.",
            "Sounds fun!",
            "Let's chat more."
        ]

        programms_responses = [
            "That's a solid algorithm!",
            "Have you tried debugging?",
            "Nice code snippet!",
            "Version control is key.",
            "Optimization matters.",
            "Error handling is important.",
            "Clean code rocks!",
            "Testing is crucial.",
            "Great use of libraries!",
            "Keep coding!"
        ]

        # Check if messaging a pre-programmed chat
        if to_user == 'grok':
            ai_msg = random.choice(general_responses)
        elif to_user == 'big_5':
            ai_msg = random.choice(programms_responses)
        elif to_user == 'claude':
            ai_msg = random.choice(general_responses)  # Placeholder, can customize later
        elif to_user == 'gemini':
            ai_msg = random.choice(general_responses)  # Placeholder
        else:
            return  # Not a pre-programmed chat

        # Store AI response
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO messages (from_user, to_user, message) VALUES (?, ?, ?)', (to_user, username, ai_msg))
        conn.commit()
        conn.close()
        # Emit AI response
        emit('private_message', {'from': to_user, 'message': ai_msg, 'to': username}, to=username)
    else:
        # Public message
        emit('public_message', {'from': username, 'message': message}, broadcast=True)
        emit('public_message', {'from': username, 'message': message}, to=username)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    socketio.run(app, host='0.0.0.0', debug=False, allow_unsafe_werkzeug=True, port=port)