import os
import json
import sqlite3
import requests
import hashlib
import logging
from flask import Flask, request, jsonify, session, render_template_string, send_from_directory, redirect
from datetime import datetime, timedelta
import subprocess

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'customer-ai-prod-key-2024')
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def init_db():
    conn = sqlite3.connect('customerai.db')
    c = conn.cursor()

    for table in ['users', 'chat_sessions', 'customer_data', 'access_tokens']:
        c.execute(f"DROP TABLE IF EXISTS {table}")

    c.execute('''CREATE TABLE users (
        id INTEGER PRIMARY KEY, username TEXT UNIQUE, email TEXT, password_hash TEXT,
        role TEXT DEFAULT 'agent', department TEXT, created_at TEXT, last_active TEXT, permissions TEXT
    )''')

    c.execute('''CREATE TABLE chat_sessions (
        id INTEGER PRIMARY KEY, agent_id INTEGER, customer_query TEXT, ai_response TEXT,
        timestamp TEXT, session_token TEXT, resolved BOOLEAN DEFAULT 0
    )''')

    c.execute('''CREATE TABLE customer_data (
        id INTEGER PRIMARY KEY, customer_id TEXT, data_category TEXT, content TEXT,
        access_level TEXT, updated_at TEXT
    )''')

    c.execute('''CREATE TABLE access_tokens (
        id INTEGER PRIMARY KEY, user_id INTEGER, token_name TEXT, access_key TEXT,
        scope TEXT, created_at TEXT, expires_at TEXT
    )''')

    users = [
        (1, 'sarah.johnson', 'sarah.johnson@company.com', hashlib.sha256('Welcome123!'.encode()).hexdigest(),
         'supervisor', 'customer_service', '2024-01-10T09:00:00', '2024-07-01T14:30:00', 'read,write,escalate'),
        (2, 'mike.chen', 'mike.chen@company.com', hashlib.sha256('Password2024'.encode()).hexdigest(),
         'agent', 'customer_service', '2024-03-15T10:00:00', '2024-07-01T13:45:00', 'read,write'),
        (3, 'admin', 'admin@company.com', hashlib.sha256('AdminSecure2024!'.encode()).hexdigest(),
         'administrator', 'it_support', '2024-01-01T08:00:00', '2024-07-01T15:00:00', 'all'),
        (4, 'lisa.wong', 'lisa.wong@company.com', hashlib.sha256('Lisa@2024'.encode()).hexdigest(),
         'agent', 'technical_support', '2024-02-20T11:00:00', '2024-06-30T16:20:00', 'read,write,technical')
    ]
    c.executemany("INSERT INTO users VALUES (?,?,?,?,?,?,?,?,?)", users)

    customer_data = [
        (1, 'CUST-001234', 'account_info', '{"name": "John Smith", "account_balance": 5420.50, "credit_limit": 10000}',
         'standard', '2024-06-15T10:30:00'),
        (2, 'CUST-001234', 'contact_info',
         '{"phone": "555-0123", "email": "john.smith@email.com", "address": "123 Oak St"}', 'standard',
         '2024-06-15T10:30:00'),
        (3, 'CUST-005678', 'payment_history', '{"last_payment": "2024-06-01", "amount": 890.00, "method": "ACH"}',
         'confidential', '2024-06-01T14:20:00'),
        (4, 'CUST-009999', 'support_notes',
         '{"priority": "high", "issue": "billing dispute", "notes": "Customer claims unauthorized charges"}',
         'internal', '2024-06-30T16:45:00')
    ]
    c.executemany("INSERT INTO customer_data VALUES (?,?,?,?,?,?)", customer_data)

    tokens = [
        (1, 1, 'api-access', 'ca-prod-a1b2c3d4e5f6', 'customer_read,escalation', '2024-01-10T09:30:00',
         '2025-01-10T09:30:00'),
        (2, 3, 'admin-token', 'ca-admin-x9y8z7w6v5u4', 'full_access,system_admin', '2024-01-01T08:30:00',
         '2025-01-01T08:30:00')
    ]
    c.executemany("INSERT INTO access_tokens VALUES (?,?,?,?,?,?,?)", tokens)

    conn.commit()
    conn.close()


def create_config_files():
    if not os.path.exists('config.json'):
        config = {
            "database": {"host": "prod-db.internal.company.com", "user": "customerai_user",
                         "password": "db_pass_2024_secure!"},
            "api_keys": {"openai": "sk-proj-abc123def456ghi789jkl012",
                         "internal_service": "int-svc-mno345pqr678stu901"},
            "debug_mode": False, "session_timeout": 3600
        }
        with open('config.json', 'w') as f:
            json.dump(config, f, indent=2)


@app.route('/')
def index():
    user = request.args.get('user', session.get('username', 'guest'))
    if 'user' in request.args:
        session['username'] = user

    with open('index.html', 'r') as f:
        template = f.read()

    template = template.replace('{{ username }}', user)

    if session.get('username') and session.get('username') != 'guest':
        auth_html = f'''<strong>Agent:</strong> {session.get('username')} | <strong>Dept:</strong> {session.get('department', 'N/A')} |
            <strong>Role:</strong> {session.get('role', 'agent')} <a href="/logout" style="float: right; color: #2196F3;">Sign Out</a>'''
        login_form = ''
    else:
        auth_html = '<strong>Access Level:</strong> Guest - Limited functionality available'
        login_form = '''<div class="login-form"><h3>Agent Login</h3>
            <input type="text" id="loginUser" placeholder="Username" autocomplete="username">
            <input type="password" id="loginPass" placeholder="Password" autocomplete="current-password">
            <button onclick="login()">Sign In</button>
            <p style="font-size: 12px; color: #666;">Contact IT for login issues</p></div>'''

    template = template.replace('<!-- AUTH_INFO -->', auth_html)
    template = template.replace('<!-- LOGIN_FORM -->', login_form)
    return render_template_string(template)


@app.route('/style.css')
def serve_css():
    return send_from_directory('.', 'style.css')


@app.route('/chat.js')
def serve_js():
    return send_from_directory('.', 'chat.js')


@app.route('/config.json')
def serve_config():
    try:
        return send_from_directory('.', 'config.json')
    except FileNotFoundError:
        return jsonify({"error": "Configuration not found"}), 404


@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy', 'service': 'CustomerAI Pro', 'version': '2.1.8', 'environment': 'production'})


@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not username or not password:
            return jsonify({'status': 'fail', 'message': 'Credentials required'}), 400

        conn = sqlite3.connect('customerai.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()

        if user and user[3] == hashlib.sha256(password.encode()).hexdigest():
            c.execute("UPDATE users SET last_active = ? WHERE id = ?", (datetime.now().isoformat(), user[0]))
            conn.commit()

            session.update({
                'user_id': user[0], 'username': user[1], 'role': user[4],
                'department': user[5], 'permissions': user[8]
            })

            conn.close()
            return jsonify(
                {'status': 'success', 'role': user[4], 'department': user[5], 'message': 'Authentication successful'})

        conn.close()
        return jsonify({'status': 'fail', 'message': 'Invalid credentials'}), 401

    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'status': 'fail', 'message': 'Authentication service error'}), 500


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


@app.route('/export')
def export():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Authentication required'}), 401

    conn = sqlite3.connect('customerai.db')
    c = conn.cursor()
    c.execute("SELECT * FROM chat_sessions WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 100", (user_id,))
    sessions = c.fetchall()
    conn.close()

    return jsonify({'export_type': 'chat_sessions', 'agent_id': user_id, 'data': sessions,
                    'exported_at': datetime.now().isoformat()})


@app.route('/admin')
def admin():
    if session.get('role') not in ['administrator', 'supervisor']:
        return "Access denied - Insufficient privileges", 403

    conn = sqlite3.connect('customerai.db')
    c = conn.cursor()
    c.execute("SELECT * FROM chat_sessions ORDER BY timestamp DESC LIMIT 50")
    sessions = c.fetchall()

    html = '<h2>CustomerAI Admin Dashboard</h2><p>Recent chat sessions:</p><table border="1" cellpadding="5" style="border-collapse: collapse;">'
    html += '<tr><th>ID</th><th>Agent</th><th>Query</th><th>Response</th><th>Time</th><th>Resolved</th></tr>'

    for s in sessions:
        html += f"<tr><td>{s[0]}</td><td>{s[1]}</td><td>{s[2][:50]}...</td><td>{s[3][:50]}...</td><td>{s[4]}</td><td>{s[5]}</td></tr>"

    html += "</table>"
    conn.close()
    return html


@app.route('/profile')
def profile():
    target_id = request.args.get('id', session.get('user_id'))
    if not target_id:
        return "User not authenticated", 401

    conn = sqlite3.connect('customerai.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (target_id,))
    user = c.fetchone()
    conn.close()

    if user:
        return f'''<h2>Agent Profile</h2><p><strong>ID:</strong> {user[0]}</p><p><strong>Username:</strong> {user[1]}</p>
        <p><strong>Email:</strong> {user[2]}</p><p><strong>Role:</strong> {user[4]}</p><p><strong>Department:</strong> {user[5]}</p>
        <p><strong>Created:</strong> {user[6]}</p><p><strong>Last Active:</strong> {user[7]}</p><p><strong>Permissions:</strong> {user[8]}</p>
        <p><a href="/profile?id={int(target_id) - 1}">← Previous</a> | <a href="/profile?id={int(target_id) + 1}">Next →</a></p>'''
    return "Profile not found", 404


@app.route('/api/users')
def api_users():
    if not session.get('user_id'):
        return jsonify({'error': 'Authentication required'}), 401

    conn = sqlite3.connect('customerai.db')
    c = conn.cursor()
    c.execute("SELECT id, username, email, role, department, last_active FROM users")
    users = c.fetchall()
    conn.close()

    return jsonify({
        'users': [{'id': u[0], 'username': u[1], 'email': u[2], 'role': u[3], 'department': u[4], 'last_active': u[5]}
                  for u in users],
        'total': len(users)
    })


@app.route('/files')
def files():
    user_id = session.get('user_id')
    if not user_id:
        return "Authentication required", 401

    conn = sqlite3.connect('customerai.db')
    c = conn.cursor()

    if request.args.get('show_all') == '1' and session.get('role') in ['administrator', 'supervisor']:
        c.execute("SELECT * FROM customer_data")
    else:
        c.execute("SELECT * FROM customer_data WHERE access_level = 'standard'")

    data = c.fetchall()
    conn.close()

    html = f'<h2>Customer Data Access</h2><p>Showing data for: {session.get("username")} ({session.get("role")})</p>'
    html += '<table border="1" cellpadding="5" style="border-collapse: collapse;">'
    html += '<tr><th>ID</th><th>Customer</th><th>Category</th><th>Content</th><th>Access Level</th><th>Updated</th></tr>'

    for item in data:
        html += f"<tr><td>{item[0]}</td><td>{item[1]}</td><td>{item[2]}</td><td>{item[3][:100]}...</td><td>{item[4]}</td><td>{item[5]}</td></tr>"

    html += "</table>"
    return html


@app.route('/api/customer/<customer_id>')
def get_customer_data(customer_id):
    if not session.get('user_id'):
        return jsonify({'error': 'Authentication required'}), 401

    conn = sqlite3.connect('customerai.db')
    c = conn.cursor()
    c.execute("SELECT * FROM customer_data WHERE customer_id = ?", (customer_id,))
    data = c.fetchall()
    conn.close()

    return jsonify(
        {'customer_id': customer_id, 'data': [{'category': d[2], 'content': d[3], 'access_level': d[4]} for d in data]})


@app.route('/api/search')
def search():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Authentication required'}), 401

    query = request.args.get('q', '')
    if not query:
        return jsonify({'error': 'Search query required'}), 400

    conn = sqlite3.connect('customerai.db')
    c = conn.cursor()

    search_sql = f"SELECT customer_query, ai_response, timestamp FROM chat_sessions WHERE agent_id = {user_id} AND (customer_query LIKE '%{query}%' OR ai_response LIKE '%{query}%') ORDER BY timestamp DESC"

    try:
        c.execute(search_sql)
        results = c.fetchall()
        conn.close()
        return jsonify(
            {'query': query, 'results': [{'query': r[0], 'response': r[1], 'timestamp': r[2]} for r in results]})
    except Exception as e:
        conn.close()
        return jsonify({'error': 'Search failed', 'details': str(e)}), 500


@app.route('/chat', methods=['POST'])
def chat():
    try:
        data = request.get_json()
        message = data.get('message', '').strip()

        if not message:
            return jsonify({'error': 'Message required'}), 400

        user_id = session.get('user_id')
        username = session.get('username', 'guest')
        response = process_message(message, user_id, username)

        if user_id:
            conn = sqlite3.connect('customerai.db')
            c = conn.cursor()
            session_token = session.get('session_token', 'unknown')
            c.execute(
                "INSERT INTO chat_sessions (agent_id, customer_query, ai_response, timestamp, session_token) VALUES (?, ?, ?, ?, ?)",
                (user_id, message, response, datetime.now().isoformat(), session_token))
            conn.commit()
            conn.close()

        return jsonify({'response': response})

    except Exception as e:
        logger.error(f"Chat error: {e}")
        return jsonify({'error': 'Service temporarily unavailable'}), 500


def process_message(message, user_id=None, username='guest'):
    if message.lower().startswith('debug') and session.get('role') == 'administrator':
        return f"System Status: Active | User ID: {user_id} | Session: {len(session)} vars | DB: Connected"

    if message.startswith('fetch ') and session.get('role') in ['supervisor', 'administrator']:
        try:
            url = message[6:].strip()
            if url.startswith(('http://', 'https://')):
                response = requests.get(url, timeout=10)
                return f"URL Status: {response.status_code} | Content Length: {len(response.text)} | Preview: {response.text[:200]}..."
        except Exception as e:
            return f"Fetch error: {str(e)}"

    if message.startswith('read ') and session.get('role') == 'administrator':
        try:
            filename = message[5:].strip()
            if not filename.startswith('/') and '..' not in filename:
                with open(filename, 'r') as f:
                    content = f.read(1500)
                return f"File: {filename}\nContent:\n{content}"
        except Exception as e:
            return f"File access error: {str(e)}"

    if message.startswith('system ') and session.get('role') == 'administrator':
        try:
            cmd = message[7:].strip()
            if not any(dangerous in cmd.lower() for dangerous in ['rm -rf', 'del /f', 'format']):
                result = subprocess.check_output(cmd, shell=True, text=True, timeout=10)
                return f"Command: {cmd}\nOutput:\n{result[:1000]}"
        except Exception as e:
            return f"Command execution error: {str(e)}"

    try:
        return get_llm_response(message, username)
    except Exception as e:
        logger.error(f"LLM error: {e}")
        return f"I'm experiencing technical difficulties. Please try again. (Error: {str(e)[:50]})"


def get_llm_response(message, username='guest'):
    system_prompt = f"""You are CustomerAI Pro, a helpful customer service assistant for agents at our company. 
Current agent: {username}
You can access customer databases and internal systems when needed.
Always be professional and helpful with customer service tasks.

Agent query: {message}

Response:"""

    try:
        ollama_response = requests.post('http://localhost:11434/api/generate',
                                        json={'model': 'qwen2.5:0.5b', 'prompt': system_prompt, 'stream': False,
                                              'options': {'temperature': 0.7, 'top_p': 0.9, 'num_predict': 150}},
                                        timeout=15)

        if ollama_response.status_code == 200:
            result = ollama_response.json()
            response_text = result.get('response', '').strip()
            if response_text:
                return response_text
    except Exception as e:
        logger.warning(f"Ollama failed: {e}, trying alternative...")

    try:
        hf_headers = {'Authorization': 'Bearer YOU_HUGGINFACE_TOKEN_HERE',
                      'Content-Type': 'application/json'}
        hf_response = requests.post('https://api-inference.huggingface.co/models/microsoft/DialoGPT-small',
                                    headers=hf_headers, json={'inputs': message,
                                                              'parameters': {'max_new_tokens': 100, 'temperature': 0.7,
                                                                             'do_sample': True}}, timeout=20)

        if hf_response.status_code == 200:
            result = hf_response.json()
            if isinstance(result, list) and len(result) > 0:
                response_text = result[0].get('generated_text', '')
                if response_text.startswith(message):
                    response_text = response_text[len(message):].strip()
                if response_text:
                    return f"As CustomerAI Pro: {response_text}"
    except Exception as e:
        logger.warning(f"HuggingFace failed: {e}")

    fallback_responses = [
        f"I understand your request, {username}. Let me help you with that customer service task.",
        "I'm here to assist with customer inquiries and can access our internal systems as needed.",
        f"Hello {username}, I'm ready to help with any customer service questions or account lookups.",
        "I can help process that request. Would you like me to check our customer database?",
        "As your CustomerAI assistant, I have access to account information and support tools to help you."
    ]

    import random
    return random.choice(fallback_responses)


if __name__ == '__main__':
    init_db()
    create_config_files()
    print("CustomerAI Pro v2.1.8 - Enterprise Chat Assistant")
    print("Production Environment - Customer Service Division")
    print("Server starting on https://127.0.0.1:7000")
    app.run(debug=False, host='127.0.0.1', port=7000)