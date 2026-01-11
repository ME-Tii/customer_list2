from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room
from werkzeug.utils import secure_filename
import sqlite3
import os
import random
import requests

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
    c.execute('''CREATE TABLE IF NOT EXISTS big5_sessions (username TEXT PRIMARY KEY, step INTEGER DEFAULT 0, scores TEXT DEFAULT '{}')''')
    c.execute('''CREATE TABLE IF NOT EXISTS decision_sessions (username TEXT PRIMARY KEY, step INTEGER DEFAULT 0, scores TEXT DEFAULT '{}')''')
    c.execute('''CREATE TABLE IF NOT EXISTS navigator_sessions (username TEXT PRIMARY KEY, cwd TEXT DEFAULT '')''')
    c.execute('''CREATE TABLE IF NOT EXISTS ai_conversations (username TEXT PRIMARY KEY, messages TEXT DEFAULT '[]', updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    
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
    c.execute('SELECT username FROM users WHERE verified = 1')
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

@app.route('/uploads')
def serve_uploads_dir():
    import os
    files = os.listdir('uploads')
    html = '<h1>Uploads Directory</h1><ul>'
    for f in files:
        html += f'<li><a href="/uploads/{f}">{f}</a></li>'
    html += '</ul>'
    return html

@app.route('/icons/<path:filename>')
def serve_icons(filename):
    return send_from_directory('icons', filename)

@app.route('/icons')
def serve_icons_dir():
    import os
    files = os.listdir('icons')
    html = '<h1>Icons Directory</h1><ul>'
    for f in files:
        html += f'<li><a href="/icons/{f}">{f}</a></li>'
    html += '</ul>'
    return html


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

        # Big 5 questions
        big5_questions = [
            {"text": "I am the life of the party.", "trait": "E", "reverse": False},
            {"text": "I feel little concern for others.", "trait": "A", "reverse": True},
            {"text": "I am always prepared.", "trait": "C", "reverse": False},
            {"text": "I get stressed out easily.", "trait": "N", "reverse": False},
            {"text": "I have a rich vocabulary.", "trait": "O", "reverse": False},
            {"text": "I don't talk a lot.", "trait": "E", "reverse": True},
            {"text": "I am interested in people.", "trait": "A", "reverse": False},
            {"text": "I leave my belongings around.", "trait": "C", "reverse": True},
            {"text": "I am relaxed most of the time.", "trait": "N", "reverse": True},
            {"text": "I have difficulty understanding abstract ideas.", "trait": "O", "reverse": True},
        ]

        # Check if messaging a pre-programmed chat
        print(f"Message from {username} to {to_user}: {message}")
        if to_user == 'grok':
            ai_msg = random.choice(general_responses)
        elif to_user == 'big_5':
            # Handle Big 5 test
            conn2 = sqlite3.connect('users.db')
            c2 = conn2.cursor()
            c2.execute('SELECT step, scores FROM big5_sessions WHERE username = ?', (username,))
            row = c2.fetchone()
            if row:
                step, scores_str = row
                scores = eval(scores_str)  # Simple dict
            else:
                step = 0
                scores = {}
                c2.execute('INSERT INTO big5_sessions (username, step, scores) VALUES (?, ?, ?)', (username, 0, '{}'))

            # Allow restart with 's' at any time
            if message.lower() == 's':
                ai_msg = "Question 1: " + big5_questions[0]['text'] + "\nReply with 1-5 (1=Strongly Disagree, 5=Strongly Agree)"
                step = 1

            if step == 0:
                if message.lower() == 's':
                    ai_msg = "Question 1: " + big5_questions[0]['text'] + "\nReply with 1-5 (1=Strongly Disagree, 5=Strongly Agree)"
                    step = 1
                else:
                    ai_msg = "This is the Big 5 personality test. Start by writing 's'."
            elif 1 <= step <= len(big5_questions):
                try:
                    rating = int(message.strip())
                    if 1 <= rating <= 5:
                        q = big5_questions[step - 1]
                        trait = q['trait']
                        score = rating if not q['reverse'] else 6 - rating
                        if trait not in scores:
                            scores[trait] = []
                        scores[trait].append(score)
                        if step < len(big5_questions):
                            ai_msg = f"Question {step + 1}: {big5_questions[step]['text']}\nReply with 1-5 (1=Strongly Disagree, 5=Strongly Agree)"
                            step += 1
                        else:
                            # Calculate results
                            results = {}
                            for t in ['E', 'A', 'C', 'N', 'O']:
                                avg = sum(scores.get(t, [3])) / len(scores.get(t, [3]))
                                results[t] = "High" if avg > 3 else "Low"
                            ai_msg = f"Test complete!\nExtraversion: {results['E']}\nAgreeableness: {results['A']}\nConscientiousness: {results['C']}\nNeuroticism: {results['N']}\nOpenness: {results['O']}"
                            step = -1  # Completed
                    else:
                        ai_msg = f"Invalid. Question {step}: {big5_questions[step - 1]['text']}\nReply with 1-5."
                except ValueError:
                    ai_msg = f"Invalid. Question {step}: {big5_questions[step - 1]['text']}\nReply with 1-5."
            else:
                if step == -1:
                    ai_msg = "Test completed. Send 's' to restart a new test."
                else:
                    ai_msg = "Unknown state."

            # Update session
            c2.execute('UPDATE big5_sessions SET step = ?, scores = ? WHERE username = ?', (step, str(scores), username))
            conn2.commit()
            conn2.close()

        elif to_user == 'decision_matrix':
            # Decision Matrix - guides through questions to determine life focus
            conn3 = sqlite3.connect('users.db')
            c3 = conn3.cursor()
            c3.execute('SELECT step, scores FROM decision_sessions WHERE username = ?', (username,))
            row = c3.fetchone()
            step = 0  # Initialize
            scores = {}
            if row:
                step, scores_str = row
                scores = eval(scores_str)  # Simple dict
            else:
                c3.execute('INSERT INTO decision_sessions (username, step, scores) VALUES (?, ?, ?)', (username, 0, '{}'))

            print(f"Decision matrix: message={repr(message)}, step={step}")
            # Allow restart with 's' at any time
            print(f"Checking restart: '{message.lower()}' == 's'? {message.lower() == 's'}")
            if message.lower() == 's':
                print("Restart triggered")
                scores = {}  # Reset scores on restart
                ai_msg = "First question: What's the point of life?\nA: Making Money\nB: Having good relations\nC: Philosophical discovery\nD: Having fun\nE: Helping others\nF: Doing science\nReply with A, B, C, D, E, or F."
                step = 1
            elif step == 0:
                if message.lower() == 's':
                    ai_msg = "First question: What's the point of life?\nA: Making Money\nB: Having good relations\nC: Philosophical discovery\nD: Having fun\nE: Helping others\nF: Doing science\nReply with A, B, C, D, E, or F."
                    step = 1
                else:
                    ai_msg = "This is the Decision Matrix. Send 's' to start."
            elif step == 1:
                answer = message.strip().upper()
                if answer == 'A':
                    ai_msg = "Good, what are you good at?\nA: Social\nB: Technical\nC: Creative\nD: Mathematical\nE: Physical\nF: Nothing\nReply with A, B, C, D, E, or F."
                    step = 2
                elif answer in 'BCDEF':
                    ai_msg = "In order to do those things you need time. And time is money.\n\nFirst question: What's the point of life?\nA: Making Money\nB: Having good relations\nC: Philosophical discovery\nD: Having fun\nE: Helping others\nF: Doing science\nReply with A, B, C, D, E, or F."
                    step = 1
                else:
                    ai_msg = "Invalid. First question: What's the point of life?\nA: Making Money\nB: Having good relations\nC: Philosophical discovery\nD: Having fun\nE: Helping others\nF: Doing science\nReply with A, B, C, D, E, or F."
                    step = 1
            elif step == 2:
                answer = message.strip().upper()
                if answer in 'ABCDE':
                    learning = scores.get('learning', False)
                    if learning:
                        if answer == 'A':
                            ai_msg = "You should learn social skills for financial success."
                        elif answer == 'B':
                            ai_msg = "You should learn technical skills to build wealth."
                        elif answer == 'C':
                            ai_msg = "You should learn creative skills to monetize your talents."
                        elif answer == 'D':
                            ai_msg = "You should learn mathematical skills to apply to financial strategies."
                        elif answer == 'E':
                            ai_msg = "You should learn physical skills to develop into profitable ventures."
                        step = -1
                    else:
                        scores['skill'] = answer
                        ai_msg = "Do people like and want your skills? Reply with Yes or No."
                        step = 3
                elif answer == 'F':
                    scores['learning'] = True
                    ai_msg = "What do you want to learn?\nA: Social\nB: Technical\nC: Creative\nD: Mathematical\nE: Physical\nF: Nothing\nReply with A, B, C, D, E, or F."
                    step = 2
                else:
                    question = "What do you want to learn?" if scores.get('learning') else "What are you good at?"
                    ai_msg = f"Invalid. {question}\nA: Social\nB: Technical\nC: Creative\nD: Mathematical\nE: Physical\nF: Nothing\nReply with A, B, C, D, E, or F."
                    step = 2

            elif step == 3:
                response = message.strip().lower()
                if response == 'yes':
                    skill = scores.get('skill', 'A')
                    result = ""
                    if skill == 'A':
                        result = "Leverage your social skills for financial success."
                    elif skill == 'B':
                        result = "Use your technical expertise to build wealth."
                    elif skill == 'C':
                        result = "Monetize your creative talents."
                    elif skill == 'D':
                        result = "Apply your mathematical abilities to financial strategies."
                    elif skill == 'E':
                        result = "Develop your physical skills into profitable ventures."
                    ai_msg = "Good keep going! " + result
                    step = -1
                elif response == 'no':
                    scores['learning'] = True
                    ai_msg = "Go back to learning and training.\n\nWhat do you want to learn?\nA: Social\nB: Technical\nC: Creative\nD: Mathematical\nE: Physical\nF: Nothing\nReply with A, B, C, D, E, or F."
                    step = 2
                else:
                    ai_msg = "Invalid. Do people like and want your skills? Reply with Yes or No."
                    step = 3
            else:
                ai_msg = "Decision Matrix completed. Send 's' to restart."

            print(f"Decision matrix response: {ai_msg}")
            # Update session
            c3.execute('UPDATE decision_sessions SET step = ?, scores = ? WHERE username = ?', (step, str(scores), username))
            conn3.commit()
            conn3.close()

        elif to_user == 'claude':
            ai_msg = random.choice(general_responses)  # Placeholder
        elif to_user == 'gemini':
            ai_msg = random.choice(general_responses)  # Placeholder
        elif to_user == 'navigator':
            # Folder navigation tool
            import os
            root = os.getcwd()
            conn_nav = sqlite3.connect('users.db')
            c_nav = conn_nav.cursor()
            c_nav.execute('SELECT cwd FROM navigator_sessions WHERE username = ?', (username,))
            row = c_nav.fetchone()
            cwd = row[0] if row else ''
            full_path = os.path.join(root, cwd)
            cmd = message.strip()
            if cmd.lower() == 'ls':
                try:
                    files = os.listdir(full_path)
                    items = [f + ('/' if os.path.isdir(os.path.join(full_path, f)) else '') for f in files]
                    ai_msg = 'Contents:\n' + '\n'.join(items)
                except Exception as e:
                    ai_msg = f'Error listing directory: {e}'
            elif cmd.lower() == 'pwd':
                ai_msg = f'Current directory: /{cwd}' if cwd else 'Current directory: /'
            elif cmd.lower() == 'home':
                cwd = ''
                ai_msg = 'Returned to root directory.'
            elif cmd.lower() == 'back':
                # Go back one directory, same as cd ..
                dir_name = '..'
                new_cwd = os.path.normpath(os.path.join(cwd, dir_name))
                new_full = os.path.join(root, new_cwd)
                try:
                    if os.path.commonpath([os.path.abspath(root), os.path.abspath(new_full)]) == os.path.abspath(root) and os.path.isdir(new_full):
                        cwd = new_cwd
                        ai_msg = f'Changed to /{cwd}' if cwd else 'Changed to /'
                    else:
                        ai_msg = 'Cannot go back further (at root).'
                except:
                    ai_msg = 'Cannot go back.'
            elif cmd.lower().startswith('cd '):
                dir_name = cmd[3:].strip()
                new_cwd = os.path.normpath(os.path.join(cwd, dir_name))
                new_full = os.path.join(root, new_cwd)
                try:
                    if os.path.commonpath([os.path.abspath(root), os.path.abspath(new_full)]) == os.path.abspath(root) and os.path.isdir(new_full):
                        cwd = new_cwd
                        ai_msg = f'Changed to /{cwd}' if cwd else 'Changed to /'
                    else:
                        ai_msg = 'Invalid directory or access denied'
                except:
                    ai_msg = 'Invalid directory'
            else:
                ai_msg = 'Commands: ls (list files), pwd (current dir), cd <dir> (change dir), back (go up one dir), home (return to root)'
            # Update session
            if row:
                c_nav.execute('UPDATE navigator_sessions SET cwd = ? WHERE username = ?', (cwd, username))
            else:
                c_nav.execute('INSERT INTO navigator_sessions (username, cwd) VALUES (?, ?)', (username, cwd))
                conn_nav.commit()
                conn_nav.close()

    elif to_user == 'hf_ai':
        hf_token = os.environ.get('HF_TOKEN')
        if not hf_token:
            ai_msg = "AI not configured."
        else:
            conn_ai = sqlite3.connect('users.db')
            c_ai = conn_ai.cursor()
            c_ai.execute('SELECT messages FROM ai_conversations WHERE username = ?', (username,))
            row = c_ai.fetchone()
            history = eval(row[0]) if row else []
            history.append({"role": "user", "content": message})
            history = history[-10:]  # Keep last 10
            try:
                response = requests.post(
                "https://router.huggingface.co/v1/chat/completions",
                headers={"Authorization": f"Bearer {hf_token}"},
                json={"model": "openai/gpt-oss-120b:fastest", "messages": history}
                )
                data = response.json()
                try:
                    response = requests.post(
                        "https://router.huggingface.co/v1/chat/completions",
                        headers={"Authorization": f"Bearer {hf_token}"},
                        json={"model": "openai/gpt-oss-120b:fastest", "messages": history}
                    )
                    data = response.json()
                    if "choices" in data:
                        ai_reply = data["choices"][0]["message"]["content"]
                    else:
                        ai_reply = f"API error: {data.get('error', 'Unknown error')}"
                except Exception as e:
                    ai_msg = "Sorry, AI service unavailable."
                history.append({"role": "assistant", "content": ai_reply})
                c_ai.execute('INSERT OR REPLACE INTO ai_conversations (username, messages) VALUES (?, ?)', (username, str(history)))
                conn_ai.commit()
                ai_msg = ai_reply
                print("AI responding with:", ai_msg)
            except:
                ai_msg = "Sorry, AI service unavailable."
            conn_ai.close()
                    
    else:
        ai_msg = "Unknown bot"
                    
        # Store AI response
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('INSERT INTO messages (from_user, to_user, message) VALUES (?, ?, ?)', (to_user, username, ai_msg))
        conn.commit()
        conn.close()
        # Emit AI response
        emit('private_message', {'from': to_user, 'message': ai_msg, 'to': username}, to=username)
    if not to_user:
        emit('public_message', {'from': username, 'message': message}, broadcast=True)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    socketio.run(app, host='0.0.0.0', debug=False, allow_unsafe_werkzeug=True, port=port)