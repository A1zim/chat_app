from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import sqlite3
import bcrypt
import random
import string
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a secure key

# Database setup
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name TEXT,
        surname TEXT,
        age INTEGER,
        interests TEXT
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS friends (
        user_id INTEGER,
        friend_id INTEGER,
        status TEXT,  -- 'pending' or 'accepted'
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(friend_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER,
        receiver_id INTEGER,
        content TEXT,
        timestamp TEXT,
        is_group BOOLEAN,
        group_id INTEGER,
        FOREIGN KEY(sender_id) REFERENCES users(id),
        FOREIGN KEY(receiver_id) REFERENCES users(id),
        FOREIGN KEY(group_id) REFERENCES groups(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        creator_id INTEGER,
        FOREIGN KEY(creator_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS group_members (
        group_id INTEGER,
        user_id INTEGER,
        FOREIGN KEY(group_id) REFERENCES groups(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS verification_codes (
        email TEXT,
        code TEXT,
        timestamp TEXT
    )''')
    conn.commit()
    conn.close()

# Mock email verification (in real app, use an email service)
def send_verification_email(email):
    code = ''.join(random.choices(string.digits, k=6))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("INSERT INTO verification_codes (email, code, timestamp) VALUES (?, ?, ?)",
              (email, code, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()
    print(f"Verification code for {email}: {code}")  # For demo purposes
    return code

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form['username_or_email']
        password = request.form['password'].encode('utf-8')
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? OR email = ?", (username_or_email, username_or_email))
        user = c.fetchone()
        conn.close()
        if user and bcrypt.checkpw(password, user[3].encode('utf-8')):
            session['user_id'] = user[0]
            session['username'] = user[2]
            return redirect(url_for('chats'))
        return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        confirm_password = request.form['confirm_password'].encode('utf-8')
        if password != confirm_password:
            return render_template('register.html', error="Passwords do not match")
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (email, username, password) VALUES (?, ?, ?)",
                      (email, username, hashed_password.decode('utf-8')))
            conn.commit()
            send_verification_email(email)
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('register.html', error="Email or username already exists")
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/chats')
def chats():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    # Get accepted friends
    c.execute("SELECT friend_id, status FROM friends WHERE user_id = ? AND status = 'accepted'", (session['user_id'],))
    friends = c.fetchall()
    friend_list = []
    for friend in friends:
        c.execute("SELECT username FROM users WHERE id = ?", (friend[0],))
        friend_list.append(c.fetchone()[0])
    # Get pending friend requests (incoming)
    c.execute("SELECT user_id FROM friends WHERE friend_id = ? AND status = 'pending'", (session['user_id'],))
    pending_requests = c.fetchall()
    pending_list = []
    for req in pending_requests:
        c.execute("SELECT username FROM users WHERE id = ?", (req[0],))
        pending_list.append(c.fetchone()[0])
    conn.close()
    return render_template('chats.html', friends=friend_list, pending_requests=pending_list)

@app.route('/chats/<username>')
def chat_user(username):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    friend = c.fetchone()
    if not friend:
        conn.close()
        return redirect(url_for('chats'))
    c.execute("SELECT * FROM messages WHERE ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)) AND is_group = 0",
              (session['user_id'], friend[0], friend[0], session['user_id']))
    messages = c.fetchall()
    last_message_id = messages[-1][0] if messages else 0
    # Get accepted friends for sidebar
    c.execute("SELECT friend_id, status FROM friends WHERE user_id = ? AND status = 'accepted'", (session['user_id'],))
    friends = c.fetchall()
    friend_list = []
    for friend in friends:
        c.execute("SELECT username FROM users WHERE id = ?", (friend[0],))
        friend_list.append(c.fetchone()[0])
    conn.close()
    return render_template('chat_user.html', username=username, messages=messages, friends=friend_list, last_message_id=last_message_id)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    receiver_username = request.form['receiver']
    content = request.form['content']
    is_group = request.form.get('is_group', '0') == '1'
    group_id = request.form.get('group_id')
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if is_group:
        c.execute("INSERT INTO messages (sender_id, content, is_group, group_id, timestamp) VALUES (?, ?, ?, ?, ?)",
                  (session['user_id'], content, 1, group_id, datetime.now().strftime('%H:%M')))
    else:
        c.execute("SELECT id FROM users WHERE username = ?", (receiver_username,))
        receiver = c.fetchone()
        if not receiver:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        c.execute("INSERT INTO messages (sender_id, receiver_id, content, is_group, timestamp) VALUES (?, ?, ?, ?, ?)",
                  (session['user_id'], receiver[0], content, 0, datetime.now().strftime('%H:%M')))
    c.execute("SELECT last_insert_rowid()")
    new_message_id = c.fetchone()[0]
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'message_id': new_message_id})

@app.route('/get_new_messages', methods=['POST'])
def get_new_messages():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    last_message_id = int(request.form['last_message_id'])
    receiver_username = request.form.get('receiver')
    is_group = request.form.get('is_group', '0') == '1'
    group_id = request.form.get('group_id')
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    if is_group:
        c.execute("SELECT * FROM messages WHERE id > ? AND is_group = 1 AND group_id = ?",
                  (last_message_id, group_id))
        new_messages = c.fetchall()
    else:
        c.execute("SELECT id FROM users WHERE username = ?", (receiver_username,))
        receiver = c.fetchone()
        if not receiver:
            conn.close()
            return jsonify({'error': 'User not found'}), 404
        c.execute("SELECT * FROM messages WHERE id > ? AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)) AND is_group = 0",
                  (last_message_id, session['user_id'], receiver[0], receiver[0], session['user_id']))
        new_messages = c.fetchall()
    conn.close()
    return jsonify({'messages': [{
        'id': msg[0],
        'sender_id': msg[1],
        'content': msg[3],
        'timestamp': msg[4],
        'is_group': msg[5]
    } for msg in new_messages]})

@app.route('/groups')
def groups():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT g.id, g.name FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.user_id = ?", (session['user_id'],))
    groups = c.fetchall()
    conn.close()
    return render_template('groups.html', groups=groups)

@app.route('/groups/<group>')
def group_chat(group):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id FROM groups WHERE name = ?", (group,))
    group_data = c.fetchone()
    if not group_data:
        conn.close()
        return redirect(url_for('groups'))
    c.execute("SELECT * FROM messages WHERE is_group = 1 AND group_id = ?", (group_data[0],))
    messages = c.fetchall()
    last_message_id = messages[-1][0] if messages else 0
    # Get groups for sidebar
    c.execute("SELECT g.id, g.name FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.user_id = ?", (session['user_id'],))
    groups = c.fetchall()
    conn.close()
    return render_template('group_chat.html', group=group, messages=messages, group_id=group_data[0], groups=groups, last_message_id=last_message_id)

@app.route('/create_group', methods=['POST'])
def create_group():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    group_name = request.form['group_name']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("INSERT INTO groups (name, creator_id) VALUES (?, ?)", (group_name, session['user_id']))
    group_id = c.lastrowid
    c.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success', 'group_name': group_name})

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    conn.close()
    return render_template('settings.html', user=user)

@app.route('/update_profile', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    name = request.form['name']
    surname = request.form['surname']
    age = request.form['age']
    interests = request.form['interests']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("UPDATE users SET name = ?, surname = ?, age = ?, interests = ? WHERE id = ?",
              (name, surname, age, interests, session['user_id']))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/update_account', methods=['POST'])
def update_account():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    email = request.form['email']
    username = request.form['username']
    password = request.form['password'].encode('utf-8')
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    try:
        if password:
            hashed_password = bcrypt.hashpw(password, bcrypt.gensalt()).decode('utf-8')
            c.execute("UPDATE users SET email = ?, username = ?, password = ? WHERE id = ?",
                      (email, username, hashed_password, session['user_id']))
        else:
            c.execute("UPDATE users SET email = ?, username = ? WHERE id = ?",
                      (email, username, session['user_id']))
        conn.commit()
        return jsonify({'status': 'success'})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'error': 'Email or username already exists'}), 400
    finally:
        conn.close()

@app.route('/search', methods=['GET', 'POST'])
def search():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        query = request.form.get('query', '')
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE username LIKE ? AND id != ?",
                  (f'%{query}%', session['user_id']))
        users = c.fetchall()
        conn.close()
        return jsonify({'users': [user[0] for user in users]})
    return render_template('search.html')

@app.route('/send_friend_request', methods=['POST'])
def send_friend_request():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    username = request.form['username']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    # Check if request already exists
    c.execute("SELECT * FROM friends WHERE user_id = ? AND friend_id = ?",
              (session['user_id'], user[0]))
    if c.fetchone():
        conn.close()
        return jsonify({'error': 'Friend request already sent or user is already a friend'}), 400
    c.execute("INSERT INTO friends (user_id, friend_id, status) VALUES (?, ?, ?)",
              (session['user_id'], user[0], 'pending'))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/accept_friend_request', methods=['POST'])
def accept_friend_request():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    username = request.form['username']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    if not user:
        conn.close()
        return jsonify({'error': 'User not found'}), 404
    c.execute("UPDATE friends SET status = 'accepted' WHERE user_id = ? AND friend_id = ? AND status = 'pending'",
              (user[0], session['user_id']))
    # Add reciprocal friendship
    c.execute("INSERT INTO friends (user_id, friend_id, status) VALUES (?, ?, ?)",
              (session['user_id'], user[0], 'accepted'))
    conn.commit()
    conn.close()
    return jsonify({'status': 'success'})

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)