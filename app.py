"""
TAR Honeypot - backend API server.

Serves the dashboard's REST API on top of the Cowrie honeypot log that
sync_logs.py pulls down from the cloud host. Responsibilities:

  * parse hacker_data.json into a cached pandas DataFrame
  * classify each captured event into a physical-impact risk level
  * expose the aggregates each page needs (dashboard, logs, analytics,
    attacker profiles) as JSON, plus CSV export
  * manage users in users.json and guard every endpoint with a session token
  * run two background workers: hourly email alerts and Geo-IP resolution
"""

from flask import Flask, jsonify, request, Response
from flask_cors import CORS
import pandas as pd
import os
import threading
import io
import requests
import time
import json
import smtplib
import secrets
from functools import wraps
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

app = Flask(__name__)
CORS(app)

# ==========================================
# GLOBAL CACHE AND LOCKS
# The log file is large, so it is parsed once and re-parsed only when its
# modification time changes. Locks keep the worker threads from racing.
# ==========================================
cached_df = None
last_mtime = 0
data_lock = threading.Lock()
from collections import OrderedDict
ip_country_cache = OrderedDict()
MAX_CACHE_SIZE = 5000

USERS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'users.json')
users_lock = threading.Lock()

# ==========================================
# CORE SECURITY: ACTIVE SESSION TOKEN POOL
# Tokens live in memory only, so a server restart invalidates every session.
# ==========================================
ACTIVE_TOKENS = {}

def token_required(f):
    """
    Decorator guarding every private endpoint.

    A request is allowed through only when it carries a token that is still
    in ACTIVE_TOKENS; otherwise it gets a 401 and the front end redirects
    the user back to the login page.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # 1. Look for a Bearer token in the request headers (the front-end
        #    API guard attaches it to every fetch)
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if len(auth_header.split(" ")) == 2:
                token = auth_header.split(" ")[1]
        
        # 2. A CSV download is a plain browser navigation and cannot carry
        #    headers, so the token is also accepted as a URL parameter
        if not token:
            token = request.args.get('token')
            
        # 3. Reject the request if there is no token, or it is not active
        if not token or token not in ACTIVE_TOKENS:
            return jsonify({"error": "🚨 Unauthorized Access! API is secured by TAR Honeypot."}), 401
            
        return f(*args, **kwargs)
    return decorated

# ==========================================
# BACKGROUND EMAIL ALERT ENGINE
# Mails a digest of high-risk events to every active user who has
# notifications enabled.
# ==========================================
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SENDER_EMAIL = "neoch-w23@student.tarc.edu.my"   
SENDER_PASSWORD = "mvwxhppmqvcbqdtv" 

def format_email_html(events_df):
    """
    Render a set of captured events as the HTML bullet list used in the
    alert email. Each line is tagged CRITICAL (a command or payload was
    executed) or HIGH (authentication was bypassed).
    """
    summary_html = "<ul style='line-height: 1.8; padding-left: 20px; margin: 0;'>"
    for _, row in events_df.iterrows():
        has_input = str(row.get('input', '')) not in ['nan', '', 'N/A']
        is_cmd = str(row.get('eventid', '')).startswith('cowrie.command.')
        
        risk = "CRITICAL" if (is_cmd or has_input) else "HIGH"
        color = "#b91c1c" if risk == "CRITICAL" else "#d97706"
        ip = row.get('src_ip', 'Unknown')
        port = row.get('dst_port', 23)
        device = "Smart Door Lock" if port in [22, 2222] else "Smart Plug"
        payload = row.get('input', 'Authentication Bypass')
        time_str = row['timestamp'].strftime('%Y-%m-%d %H:%M:%S')
        
        summary_html += f"<li><span style='color: #64748b; font-size: 0.9em;'>[{time_str}]</span> <strong style='color: {color};'>[{risk}]</strong> {device} targeted by IP <strong>{ip}</strong>. Action: <code>{payload}</code></li>"
    summary_html += "</ul>"
    return summary_html

def send_email_alert(recipient_email, events_summary):
    """
    Send one threat-digest email through Gmail SMTP. Failures are logged
    and swallowed so a mail problem can never take the API down.
    """
    try:
        msg = MIMEMultipart()
        msg['From'] = f"TAR Honeypot <{SENDER_EMAIL}>"
        msg['To'] = recipient_email
        msg['Subject'] = "[ALERT] 🚨 TAR Honeypot Security Threat Digest"

        body = f"""
        <div style="font-family: Arial, sans-serif; color: #333; max-width: 800px; margin: 0 auto;">
            <h2 style="color: #b91c1c; border-bottom: 2px solid #b91c1c; padding-bottom: 10px;">TAR Honeypot Security Alert</h2>
            <p>Dear System User,</p>
            <p>New high-risk physical-impact threats have been intercepted by the honeypot system. Below is the latest threat digest (up to 100 recent events).</p>
            
            <div style="background: #f8fafc; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0; border-radius: 4px;">
                <h3 style="margin-top: 0; color: #0f172a;">Threat Detail Summary:</h3>
                {events_summary}
            </div>
            
            <p>Please log in to the <a href="http://127.0.0.1:5000/dashboard.html" style="color: #2563eb; text-decoration: none; font-weight: bold;">TAR Honeypot Dashboard</a> to review full attacker details.</p>
            <br>
            <p style="font-size: 0.8em; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 10px;">This is an automated alert generated by the IoT Monitoring System. If you wish to stop receiving these alerts, you can disable them in your Account Settings.</p>
        </div>
        """
        msg.attach(MIMEText(body, 'html'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.send_message(msg)
        server.quit()
        print(f"Success: Threat Digest sent to {recipient_email}")
    except Exception as e:
        print(f"Failed to send real email to {recipient_email}. (Error: {e})")

def email_alert_worker():
    """
    Background thread. Sends one digest at startup, then wakes every hour
    and mails only the high-risk events captured since the last scan.
    Recipients are active users who have notifications enabled.
    """
    print("Hourly Email Alert Engine Started...")
    
    try:
        df = get_fresh_dataframe()
        if not df.empty:
            if 'input' in df.columns:
                critical_mask = df['eventid'].str.startswith('cowrie.command.', na=False) | (df['input'] != '') | (df['eventid'] == 'cowrie.login.success')
            else:
                critical_mask = df['eventid'].str.startswith('cowrie.command.', na=False) | (df['eventid'] == 'cowrie.login.success')
                
            critical_events = df[critical_mask].sort_values(by='timestamp', ascending=False).head(100)
            
            if not critical_events.empty:
                summary_html = format_email_html(critical_events)
                users = load_users()
                for u in users:
                    if u.get('status') == 'Active' and u.get('notification') == 'Enabled':
                        threading.Thread(target=send_email_alert, args=(u['email'], summary_html)).start()
    except Exception as e:
        print(f"Startup email error: {e}")

    last_scanned_time = pd.Timestamp.now(tz='Asia/Kuala_Lumpur').tz_localize(None)
    
    while True:
        time.sleep(3600) 
        try:
            df = get_fresh_dataframe()
            if df.empty: 
                continue
            
            new_events = df[df['timestamp'] > last_scanned_time]
            if not new_events.empty:
                if 'input' in new_events.columns:
                    critical_mask = new_events['eventid'].str.startswith('cowrie.command.', na=False) | (new_events['input'] != '') | (new_events['eventid'] == 'cowrie.login.success')
                else:
                    critical_mask = new_events['eventid'].str.startswith('cowrie.command.', na=False) | (new_events['eventid'] == 'cowrie.login.success')
                    
                critical_events = new_events[critical_mask].sort_values(by='timestamp', ascending=False).head(100)
                
                if not critical_events.empty:
                    summary_html = format_email_html(critical_events)
                    users = load_users()
                    for u in users:
                        if u.get('status') == 'Active' and u.get('notification') == 'Enabled':
                            threading.Thread(target=send_email_alert, args=(u['email'], summary_html)).start()
                                
            last_scanned_time = pd.Timestamp.now(tz='Asia/Kuala_Lumpur').tz_localize(None)
        except Exception as e:
            print(f"Hourly email error: {e}")


def geo_ip_worker():
    """
    Background thread. Resolves attacker IPs to countries for the analytics
    map, in batches of 100 against ip-api.com. Results go into an LRU cache
    capped at MAX_CACHE_SIZE, so the same IP is never looked up twice.
    """
    print("Geo-IP Resolver Engine Started...")
    while True:
        try:
            df = get_fresh_dataframe()
            if not df.empty and 'src_ip' in df.columns:
                all_ips = df['src_ip'].unique()
                
                ips_to_query = [ip for ip in all_ips if ip not in ip_country_cache][:1000]
                
                if ips_to_query:
                    for i in range(0, len(ips_to_query), 100):
                        chunk = ips_to_query[i:i+100]
                        try:
                            res = requests.post("http://ip-api.com/batch?fields=query,country", json=chunk, timeout=5)
                            if res.status_code == 200:
                                for r in res.json():
                                    ip = r.get('query')
                                    country = r.get('country', 'Unknown')
                                    ip_country_cache[ip] = country
                                    ip_country_cache.move_to_end(ip)
                                    if len(ip_country_cache) > MAX_CACHE_SIZE:
                                        ip_country_cache.popitem(last=False)
                        except Exception:
                            pass
                        time.sleep(0.3)
        except Exception:
            pass
            
        time.sleep(60)



# ==========================================
# USER STORE
# users.json stands in for a database. Every read and write goes through
# these two helpers so the file is never touched by two threads at once.
# ==========================================
def load_users():
    """
    Read users.json, creating it with a default IT Manager account the
    first time the server runs. Returns a list of user dicts.
    """
    with users_lock:
        if not os.path.exists(USERS_FILE):
            default_users = [
                {
                    "id": 1, 
                    "name": "manager", 
                    "email": "manager@gmail.com", 
                    "password": "manager", 
                    "role": "IT Manager", 
                    "status": "Active", 
                    "notification": "Enabled", 
                    "lastLogin": "Never"
                }
            ]
            with open(USERS_FILE, 'w', encoding='utf-8') as f:
                json.dump(default_users, f, indent=4)
            return default_users
        else:
            with open(USERS_FILE, 'r', encoding='utf-8') as f:
                try:
                    return json.load(f)
                except Exception:
                    return []

def save_users(users_data):
    """
    Write the full user list back to users.json.
    """
    with users_lock:
        with open(USERS_FILE, 'w', encoding='utf-8') as f:
            json.dump(users_data, f, indent=4)

# ==========================================
# Hex Payload Decoder
# ==========================================
def decode_hex_payload(raw: str) -> str:
    """
    Detects \\xNN sequences in a string and decodes them to UTF-8 text.
    Returns the decoded string if it differs from raw, otherwise returns ''.
    e.g.  '\\x47\\x41\\x59'  ->  'GAY'
    """
    import re
    hex_pattern = re.compile(r'((?:\\x[0-9a-fA-F]{2})+)')
    if not hex_pattern.search(raw):
        return ''
    def replacer(m):
        try:
            hex_str = m.group(0).replace('\\x', '')
            return bytes.fromhex(hex_str).decode('utf-8', errors='replace')
        except Exception:
            return m.group(0)
    decoded = hex_pattern.sub(replacer, raw)
    return decoded if decoded != raw else ''

# ==========================================
# PANDAS DATA PARSING PIPELINE
# ==========================================
def get_fresh_dataframe():
    """
    Return the honeypot log as a cleaned pandas DataFrame.

    The parsed result is cached and only rebuilt when hacker_data.json has
    changed on disk. Cowrie appends JSON objects without separators, so the
    file is decoded object by object rather than with a single json.load.
    Timestamps are converted to Malaysia time, the destination port is
    filled in per session, and only the last 7 days are kept.
    """
    global cached_df, last_mtime
    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        json_path = os.path.join(current_dir, 'hacker_data.json')
        
        if not os.path.exists(json_path): 
            return pd.DataFrame()
            
        current_mtime = os.path.getmtime(json_path)
        with data_lock:
            if cached_df is None or current_mtime > last_mtime:
                parsed_data = []
                with open(json_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                decoder = json.JSONDecoder()
                pos, length = 0, len(content)
                while pos < length:
                    while pos < length and content[pos] in ' \n\r\t,[]': 
                        pos += 1
                    if pos >= length: 
                        break
                    try:
                        obj, idx = decoder.raw_decode(content, pos)
                        if isinstance(obj, dict): 
                            parsed_data.append(obj)
                        elif isinstance(obj, list): 
                            parsed_data.extend(obj)
                        pos = idx 
                    except Exception: 
                        pos += 1 
                        
                df = pd.DataFrame(parsed_data)
                if df.empty: 
                    return pd.DataFrame()
                    
                df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
                df['timestamp'] = df['timestamp'].dt.tz_convert('Asia/Kuala_Lumpur').dt.tz_localize(None)
                
                if 'dst_port' in df.columns and 'session' in df.columns:
                    df['dst_port'] = pd.to_numeric(df['dst_port'], errors='coerce')
                    df['dst_port'] = df.groupby('session')['dst_port'].transform(lambda x: x.ffill().bfill())
                    df['dst_port'] = df['dst_port'].fillna(23).astype(int)
                elif 'dst_port' in df.columns:
                    df['dst_port'] = pd.to_numeric(df['dst_port'], errors='coerce').fillna(23).astype(int)
                else: 
                    df['dst_port'] = 23
                
                # Keep only the ports the two emulated devices listen on
                # (22/2222 = Smart Door Lock over SSH, 23/2223 = Smart Plug over Telnet)
                df = df[df['dst_port'].isin([22, 2222, 23, 2223])]
                df = df.fillna('')
                
                # Normalise once at the source: strip stray whitespace here so no
                # endpoint or front-end page has to trim these fields again
                for col in ['username', 'password', 'input']:
                    if col in df.columns:
                        df[col] = df[col].astype(str).str.strip()
                
                if not df.empty:
                    latest_time = df['timestamp'].max()
                    df = df[df['timestamp'] >= latest_time - pd.Timedelta(days=7)]
                    df = df.reset_index(drop=True)
                
                cached_df = df
                last_mtime = current_mtime
        return cached_df
    except Exception as e:
        print(f"Error loading data: {e}")
        return pd.DataFrame()

# ==========================================
# USER MANAGEMENT AND AUTHENTICATION API
# ==========================================
@app.route('/api/login', methods=['POST'])
def login():
    """
    Authenticate by username or email and issue a session token.

    Inactive accounts are refused. An account still on the default password
    comes back with requirePasswordChange set, which sends the user to the
    forced password-change step on the login page.
    """
    data = request.json
    username_input = data.get('username')
    password_input = data.get('password')
    
    users = load_users()
    for u in users:
        if (u['name'] == username_input or u['email'] == username_input) and u.get('password') == password_input:
            if u['status'] != 'Active':
                return jsonify({"error": "Account is inactive. Please contact administrator."}), 403
            
            require_change = (u.get('password') == "123456")
            if not require_change:
                u['lastLogin'] = datetime.now().strftime('%Y-%m-%d %H:%M')
                save_users(users)
            
            # Issue a strong random session token for the authenticated user
            token = secrets.token_hex(32)
            ACTIVE_TOKENS[token] = u['id']
            
            safe_user = {
                "id": u['id'], 
                "name": u['name'], 
                "email": u['email'], 
                "role": u['role'], 
                "notification": u.get('notification', 'Enabled')
            }
            
            return jsonify({
                "message": "Login successful", 
                "user": safe_user, 
                "token": token, 
                "requirePasswordChange": require_change
            }), 200
            
    return jsonify({"error": "Invalid username or password"}), 401

@app.route('/api/logout', methods=['POST'])
@token_required
def logout():
    """
    Destroy the caller's token so it can no longer be used.
    """
    token = request.headers['Authorization'].split(" ")[1]
    if token in ACTIVE_TOKENS:
        del ACTIVE_TOKENS[token]
    return jsonify({"message": "Logged out and token destroyed"}), 200

@app.route('/api/change-password', methods=['POST'])
@token_required
def change_password():
    """
    Set a new password during the forced first-login change (no old
    password required, since the user just proved the default one).
    """
    data = request.json
    user_id = data.get('id')
    new_password = data.get('newPassword')
    
    if not user_id or not new_password: 
        return jsonify({"error": "Invalid parameters"}), 400
        
    users = load_users()
    for u in users:
        if u['id'] == user_id:
            u['password'] = new_password
            u['lastLogin'] = datetime.now().strftime('%Y-%m-%d %H:%M')
            save_users(users)
            return jsonify({"message": "Password updated"}), 200
            
    return jsonify({"error": "User not found"}), 404

@app.route('/api/profile/update', methods=['PUT'])
@token_required
def update_profile():
    """
    Update the signed-in user's name and email. The email must not already
    belong to another account.
    """
    data = request.json
    user_id = data.get('id')
    
    if not user_id: 
        return jsonify({"error": "Invalid parameters"}), 400
        
    users = load_users()
    for u in users:
        if u['id'] == user_id:
            new_email = data.get('email', '').strip()
            
            if any(other['email'].lower() == new_email.lower() and other['id'] != user_id for other in users):
                return jsonify({"error": "Email is already in use by another account."}), 400
                
            u['name'] = data.get('name', u['name']).strip()
            u['email'] = new_email
            save_users(users)
            
            safe_user = {
                "id": u['id'], 
                "name": u['name'], 
                "email": u['email'], 
                "role": u['role'], 
                "notification": u.get('notification', 'Enabled')
            }
            return jsonify({"message": "Profile updated", "user": safe_user}), 200
            
    return jsonify({"error": "User not found"}), 404

@app.route('/api/profile/password', methods=['PUT'])
@token_required
def update_profile_password():
    """
    Change the password from the Settings page. The current password must
    be supplied and match.
    """
    data = request.json
    user_id = data.get('id')
    old_password = data.get('oldPassword')
    new_password = data.get('newPassword')
    
    if not user_id or not old_password or not new_password: 
        return jsonify({"error": "Missing fields"}), 400
        
    users = load_users()
    for u in users:
        if u['id'] == user_id:
            if u.get('password') != old_password:
                return jsonify({"error": "Incorrect old password."}), 403
                
            u['password'] = new_password
            save_users(users)
            return jsonify({"message": "Password updated"}), 200
            
    return jsonify({"error": "User not found"}), 404

@app.route('/api/profile/notification', methods=['PUT'])
@token_required
def update_notification():
    """
    Turn the hourly email digest on or off for one user.
    """
    data = request.json
    user_id = data.get('id')
    notif = data.get('notification')
    
    users = load_users()
    for u in users:
        if u['id'] == user_id:
            u['notification'] = notif
            save_users(users)
            safe_user = {
                "id": u['id'], 
                "name": u['name'], 
                "email": u['email'], 
                "role": u['role'], 
                "notification": u['notification']
            }
            return jsonify({"message": "Notification updated", "user": safe_user}), 200
            
    return jsonify({"error": "User not found"}), 404

@app.route('/api/users', methods=['GET'])
@token_required
def get_users():
    """
    Return every user record, for the Manage Users table.
    """
    return jsonify(load_users())

@app.route('/api/users', methods=['POST'])
@token_required
def add_user():
    """
    Create a user with the default password 123456, then email them the
    current threat digest in the background so their first alert is not an
    hour away.
    """
    data = request.json
    users = load_users()
    
    if any(u['email'].lower() == data.get('email', '').lower() for u in users):
        return jsonify({"error": "Email already exists"}), 400
        
    new_id = max([u['id'] for u in users] + [0]) + 1
    new_user = {
        "id": new_id, 
        "name": data.get('name'), 
        "email": data.get('email'), 
        "password": "123456", 
        "role": data.get('role'), 
        "status": data.get('status'),
        "notification": "Enabled", 
        "lastLogin": "Never",
        "created_at": pd.Timestamp.now(tz='Asia/Kuala_Lumpur').tz_localize(None).strftime('%Y-%m-%d %H:%M:%S') 
    }
    users.append(new_user)
    save_users(users)
    
    def send_initial_digest(email):
        try:
            df = get_fresh_dataframe()
            if not df.empty:
                if 'input' in df.columns:
                    critical_mask = df['eventid'].str.startswith('cowrie.command.', na=False) | (df['input'] != '') | (df['eventid'] == 'cowrie.login.success')
                else:
                    critical_mask = df['eventid'].str.startswith('cowrie.command.', na=False) | (df['eventid'] == 'cowrie.login.success')
                
                critical_events = df[critical_mask].sort_values(by='timestamp', ascending=False).head(100)
                if not critical_events.empty:
                    summary_html = format_email_html(critical_events)
                    send_email_alert(email, summary_html)
        except Exception as e:
            print(f"Failed to send initial digest to {email}: {e}")
            
    threading.Thread(target=send_initial_digest, args=(data.get('email'),)).start()
    
    return jsonify({"message": "User added", "user": new_user}), 201

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@token_required
def update_user(user_id):
    """
    Edit an existing user's name, email, role or status.
    """
    data = request.json
    users = load_users()
    
    for u in users:
        if u['id'] == user_id:
            if any(other['email'].lower() == data.get('email', '').lower() and other['id'] != user_id for other in users):
                return jsonify({"error": "Email already exists"}), 400
                
            u['name'] = data.get('name', u['name'])
            u['email'] = data.get('email', u['email'])
            u['role'] = data.get('role', u['role'])
            u['status'] = data.get('status', u['status'])
            save_users(users)
            return jsonify({"message": "User updated"})
            
    return jsonify({"error": "User not found"}), 404

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@token_required
def delete_user(user_id):
    """
    Delete a user. The IT Manager account is protected and cannot be
    removed.
    """
    users = load_users()
    user_to_delete = next((u for u in users if u['id'] == user_id), None)
    
    if user_to_delete and user_to_delete.get('role') == 'IT Manager':
        return jsonify({"error": "Action denied: Cannot delete IT Manager."}), 403
        
    new_users = [u for u in users if u['id'] != user_id]
    
    if len(users) == len(new_users): 
        return jsonify({"error": "User not found"}), 404
        
    save_users(new_users)
    return jsonify({"message": "User deleted"})

@app.route('/api/dashboard-summary', methods=['GET'])
@token_required
def get_dashboard_summary():
    """
    Headline counters for the dashboard cards: total events, sessions,
    unique IPs, and the split across the four risk levels
    (critical / high / low / no risk) plus per-device totals.
    """
    logs_df = get_fresh_dataframe()
    if logs_df.empty:
        return jsonify({
            "total_threats": 0, "active_sessions": 0, "unique_ips": 0, "critical_alerts": 0, 
            "lock_count": 0, "plug_count": 0, "total_critical": 0, "total_high": 0, "total_probing": 0
        })
        
    total_threats = len(logs_df)
    
    if 'input' in logs_df.columns:
        critical_mask = logs_df['eventid'].str.startswith('cowrie.command.', na=False) | (logs_df['input'] != '')
    else:
        critical_mask = logs_df['eventid'].str.startswith('cowrie.command.', na=False)
        
    total_critical = int(logs_df[critical_mask].shape[0])
    total_high = int(logs_df[logs_df['eventid'] == 'cowrie.login.success'].shape[0])
    
    lock_count = len(logs_df[logs_df['dst_port'].isin([22, 2222])])
    plug_count = total_threats - lock_count

    total_low = int(logs_df[logs_df['eventid'] == 'cowrie.login.failed'].shape[0])
    total_no_risk = total_threats - total_critical - total_high - total_low

    return jsonify({
        "total_threats": total_threats,
        "active_sessions": int(logs_df['session'].nunique() if 'session' in logs_df.columns else 0),
        "unique_ips": int(logs_df['src_ip'].nunique() if 'src_ip' in logs_df.columns else 0),
        "critical_alerts": total_critical + total_high,
        "lock_count": lock_count,
        "plug_count": plug_count,
        "total_critical": total_critical, 
        "total_high": total_high, 
        "total_low": total_low,
        "total_no_risk": total_no_risk
    })

@app.route('/api/system-status', methods=['GET'])
@token_required
def get_system_status():
    """
    Health of the pipeline, shown in the System Summary panel: whether log
    data is present, when the last event arrived and how many records are
    loaded.
    """
    try:
        logs_df = get_fresh_dataframe()
        data_ok = not logs_df.empty
        last_event_time = None
        if data_ok and 'timestamp' in logs_df.columns:
            last_event_time = logs_df['timestamp'].max().strftime('%Y-%m-%d %H:%M:%S')
        return jsonify({
            "honeypot_status": "Cowrie Emulation Running" if data_ok else "No Data Detected",
            "parsing_engine": "Active" if data_ok else "Idle",
            "cowrie_stream": "Connected" if data_ok else "Disconnected",
            "pandas_engine": "Active" if data_ok else "Idle",
            "last_event_time": last_event_time,
            "total_records": int(len(logs_df)) if data_ok else 0
        })
    except Exception as e:
        return jsonify({
            "honeypot_status": "Error",
            "parsing_engine": "Error",
            "cowrie_stream": "Error",
            "pandas_engine": "Error",
            "last_event_time": None,
            "total_records": 0
        }), 500

@app.route('/api/logs', methods=['GET'])
@token_required
def get_attack_logs():
    """
    Full event list for the Attack Logs table, newest first. Any hex-encoded
    payload is decoded into decoded_input so the page can show a readable
    second line under the raw command.
    """
    logs_df = get_fresh_dataframe()
    if logs_df.empty: 
        return jsonify([])
        
    cols = ['timestamp', 'src_ip', 'dst_port', 'protocol', 'eventid']
    for c in ['username', 'password', 'input']:
        if c in logs_df.columns: 
            cols.append(c)
            
    recent_logs = logs_df[cols].copy()
    
    # Removed noisy_events filtering to match Dashboard Automated Probing counts
    
    recent_logs = recent_logs.sort_values(by='timestamp', ascending=False)
    recent_logs['timestamp'] = recent_logs['timestamp'].dt.strftime('%Y-%m-%dT%H:%M:%S+08:00')
    
    records = recent_logs.fillna('N/A').to_dict(orient='records')
    # Attach decoded_input for hex payloads so frontend can show a translated second line
    for rec in records:
        raw_input = str(rec.get('input', ''))
        rec['decoded_input'] = decode_hex_payload(raw_input) if raw_input not in ('N/A', '', 'nan') else ''
    return jsonify(records)

@app.route('/api/export-logs', methods=['GET'])
@token_required
def export_logs_csv():
    """
    Export events as CSV. The `type` parameter picks the column set to
    match whichever page requested it (dashboard, logs or alerts).
    """
    logs_df = get_fresh_dataframe()
    if logs_df.empty:
        return "No data available", 404

    export_type = request.args.get('type', 'dashboard')  # dashboard | logs | alerts

    df = logs_df.copy()

    # -- Shared computed columns (single source of truth) --------------------
    df['Timestamp'] = df['timestamp'].dt.strftime('%d/%m/%Y, %I:%M:%S %p')
    df['IP'] = df['src_ip']
    df['Target Device (Port)'] = df['dst_port'].apply(
        lambda p: f"Smart Door Lock ({int(p)})" if p in [22, 2222] else f"Smart Plug ({int(p)})"
    )
    df['Protocol'] = df['dst_port'].apply(lambda p: "SSH" if p in [22, 2222] else "Telnet")
    df['Event ID'] = df['eventid']

    def extract_cred(row):
        if row['eventid'] in ['cowrie.login.failed', 'cowrie.login.success']:
            u = str(row.get('username', ''))
            p = str(row.get('password', ''))
            if u == 'nan': u = ''
            if p == 'nan': p = ''
            return f"{u} / {p}"
        return "N/A"
    df['Credential'] = df.apply(extract_cred, axis=1)

    def extract_payload(row):
        inp = str(row.get('input', ''))
        if inp not in ['nan', '', 'N/A']:
            decoded = decode_hex_payload(inp)
            if decoded:
                return f'{inp} [Decoded: {decoded}]'
            return inp
        return "N/A"
    df['Payload'] = df.apply(extract_payload, axis=1)

    def get_risk(row):
        inp = str(row.get('input', ''))
        has_payload = inp not in ['nan', '', 'N/A']
        is_cmd = str(row['eventid']).startswith('cowrie.command.')
        is_ssh = row.get('dst_port') in [22, 2222]
        is_tel = row.get('dst_port') in [23, 2223]
        if has_payload or is_cmd:
            return "Critical Risk"
        elif row['eventid'] == 'cowrie.login.success':
            return "High Risk"
        elif row['eventid'] == 'cowrie.login.failed':
            return "Low Risk"
        return "No Risk"
    df['Risk'] = df.apply(get_risk, axis=1)

    def get_physical_intent(row):
        inp = str(row.get('input', ''))
        has_payload = inp not in ['nan', '', 'N/A']
        is_cmd = str(row['eventid']).startswith('cowrie.command.')
        is_ssh = row.get('dst_port') in [22, 2222]
        is_tel = row.get('dst_port') in [23, 2223]
        if has_payload or is_cmd:
            if is_ssh:
                return "SSH Command Execution"
            elif is_tel:
                return "Electrical State Manipulation"
            return "Remote Payload Injection"
        elif row['eventid'] == 'cowrie.login.success':
            if is_ssh:
                return "Mechanical Solenoid Trigger"
            elif is_tel:
                return "Electrical Auth Bypass"
            return "Unauthorized Override"
        elif row['eventid'] == 'cowrie.login.failed':
            return "Credential Stuffing"
        return "Automated Scanning & Probing"
    df['Physical Intent'] = df.apply(get_physical_intent, axis=1)

    filename = "TAR_Honeypot_Export.csv"

    # -- Attack Logs page export ---------------------------------------------
    if export_type == 'logs':
        search = request.args.get('search', '').lower().strip()
        device = request.args.get('device', 'All')
        risk   = request.args.get('risk', 'All')
        date   = request.args.get('date', '')  # YYYY-MM-DD (server local date)

        if search:
            mask = (
                df['IP'].str.lower().str.contains(search, na=False) |
                df['Payload'].str.lower().str.contains(search, na=False) |
                df['Credential'].str.lower().str.contains(search, na=False)
            )
            df = df[mask]

        if device != 'All':
            df = df[df['Target Device (Port)'].str.startswith(device)]

        if risk != 'All':
            df = df[df['Risk'].str.startswith(risk)]

        if date:
            df = df[df['timestamp'].dt.strftime('%Y-%m-%d') == date]

        filename = "TAR_Honeypot_AttackLogs.csv"

    # -- Alerts page export --------------------------------------------------
    elif export_type == 'alerts':
        risk = request.args.get('risk', 'All')  # All | CRITICAL | HIGH

        # Alerts page only shows Critical and High entries
        df = df[df['Risk'].isin(['Critical Risk', 'High Risk'])]

        if risk == 'CRITICAL':
            df = df[df['Risk'] == 'Critical Risk']
        elif risk == 'HIGH':
            df = df[df['Risk'] == 'High Risk']

        suffix = ('_' + risk) if risk != 'All' else ''
        filename = f"TAR_IoT_Alerts{suffix}.csv"

    # -- Dashboard page export (legacy, keeps ?query= behaviour) -------------
    else:
        query = request.args.get('query', '').lower()
        if query:
            mask = (
                df['IP'].str.lower().str.contains(query, na=False) |
                df['Target Device (Port)'].str.lower().str.contains(query, na=False) |
                df['Protocol'].str.lower().str.contains(query, na=False) |
                df['Risk'].str.lower().str.contains(query, na=False) |
                df['Payload'].str.lower().str.contains(query, na=False) |
                df['Credential'].str.lower().str.contains(query, na=False)
            )
            df = df[mask]
        filename = "TAR_Honeypot_Dashboard_Export.csv"

    export_df = df[['Timestamp', 'IP', 'Target Device (Port)', 'Protocol', 'Event ID', 'Credential', 'Payload', 'Risk', 'Physical Intent']]
    export_df = export_df.sort_values(by='Timestamp', ascending=False)

    csv_buffer = io.StringIO()
    # Write UTF-8 BOM for Excel compatibility
    csv_buffer.write('\ufeff')
    export_df.to_csv(csv_buffer, index=False)

    return Response(
        csv_buffer.getvalue(),
        mimetype='text/csv; charset=utf-8',
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.route('/api/analytics-data', methods=['GET'])
@token_required
def get_analytics_metrics():
    """
    Everything the Analytics page charts, computed in one pass:
    the summary cards, the 7-day trend, the 24-hour peak-hour histogram,
    the most-tried credentials, the physical-intent breakdown, the top
    payloads, and the per-country totals for the map.
    """
    logs_df = get_fresh_dataframe()
    if logs_df.empty:
        return jsonify({
            "summary": {"total": 0, "top_device": "N/A", "top_risk": "N/A", "disruptions": 0}, 
            "trend": {"labels": [], "data": []}, 
            "peak_hours": {"labels": [f"{i:02d}:00" for i in range(24)], "data": [0]*24}, 
            "top_credentials": [], 
            "intents": [], 
            "commands": [], 
            "geo": [["Country", "Attack Attempts"]]
        })

    total = len(logs_df)
    
    lock_count = len(logs_df[logs_df['dst_port'].isin([22, 2222])])
    plug_count = total - lock_count
    top_device = "Smart Door Lock" if lock_count >= plug_count else "Smart Plug"

    # ------------------------------------------------------------------
    # Physical-Impact Intent Classification
    # Aligned with Report Section 1.2.1, 1.4.2, 4.4.4 & Figure 4.4.4
    # ------------------------------------------------------------------
    is_ssh  = logs_df['dst_port'].isin([22, 2222])
    is_tel  = logs_df['dst_port'].isin([23, 2223])

    has_input_col = 'input' in logs_df.columns

    # Mechanical Solenoid Trigger:
    # SSH login successes ONLY — authentication bypass = physical door unlock
    # (SSH command injection is counted separately under Remote Payload Injection)
    mech_solenoid_count = int(
        logs_df[is_ssh & (logs_df['eventid'] == 'cowrie.login.success')].shape[0]
    )

    # Electrical State Manipulation:
    # Telnet payload/command injection (power relay / state manipulation of smart plug)
    tel_cmd_mask = is_tel & (
        logs_df['eventid'].str.startswith('cowrie.command.', na=False) |
        (has_input_col and (logs_df['input'] != ''))
    )
    elec_manip_count = int(logs_df[tel_cmd_mask].shape[0])

    # Remote Payload Injection:
    # Any platform — attacker injected malware/botnet scripts (hex, wget, curl payloads)
    if has_input_col:
        critical_mask = logs_df['eventid'].str.startswith('cowrie.command.', na=False) | (logs_df['input'] != '')
    else:
        critical_mask = logs_df['eventid'].str.startswith('cowrie.command.', na=False)
    
    # Breakdown for Remote Payload
    remote_payload_ssh = int(logs_df[critical_mask & is_ssh].shape[0])
    remote_payload_tel = int(logs_df[critical_mask & is_tel].shape[0])
    remote_payload_count = remote_payload_ssh + remote_payload_tel

    # Credential Stuffing:
    # All failed login attempts across both protocols
    cred_mask = logs_df['eventid'] == 'cowrie.login.failed'
    cred_ssh = int(logs_df[cred_mask & is_ssh].shape[0])
    cred_tel = int(logs_df[cred_mask & is_tel].shape[0])
    cred_stuff_count = cred_ssh + cred_tel

    # Unauthorized Auth Override:
    # All successful logins across both protocols
    high_mask = logs_df['eventid'] == 'cowrie.login.success'
    high_ssh = int(logs_df[high_mask & is_ssh].shape[0])
    high_tel = int(logs_df[high_mask & is_tel].shape[0])
    high_count = high_ssh + high_tel

    critical_count = remote_payload_count
    low_count = cred_stuff_count
    no_risk_count = total - critical_count - high_count - low_count

    disruptions = critical_count

    # SSH Command Execution (Lock Compromise):
    # SSH payload/command injection — attacker already inside door lock, now executing commands
    if has_input_col:
        ssh_cmd_mask = is_ssh & (
            logs_df['eventid'].str.startswith('cowrie.command.', na=False) |
            (logs_df['input'] != '')
        )
    else:
        ssh_cmd_mask = is_ssh & logs_df['eventid'].str.startswith('cowrie.command.', na=False)
    ssh_cmd_count = int(logs_df[ssh_cmd_mask].shape[0])

    # Electrical Auth Bypass (Plug Intrusion):
    # Telnet login success ONLY — attacker breached Smart Plug auth without executing commands yet
    elec_auth_count = int(
        logs_df[is_tel & (logs_df['eventid'] == 'cowrie.login.success')].shape[0]
    )

    # Build intent objects with breakdown info
    intents_list = [
        {
            "name": "Mechanical Solenoid Trigger", 
            "count": mech_solenoid_count,
            "breakdown": {"lock": mech_solenoid_count, "plug": 0}
        },
        {
            "name": "Electrical State Manipulation", 
            "count": elec_manip_count,
            "breakdown": {"lock": 0, "plug": elec_manip_count}
        },
        {
            "name": "SSH Command Execution", 
            "count": ssh_cmd_count,
            "breakdown": {"lock": ssh_cmd_count, "plug": 0}
        },
        {
            "name": "Electrical Auth Bypass", 
            "count": elec_auth_count,
            "breakdown": {"lock": 0, "plug": elec_auth_count}
        },
        {
            "name": "Remote Payload Injection", 
            "count": remote_payload_count,
            "breakdown": {"lock": remote_payload_ssh, "plug": remote_payload_tel}
        },
        {
            "name": "Credential Stuffing", 
            "count": cred_stuff_count,
            "breakdown": {"lock": cred_ssh, "plug": cred_tel}
        },
        {
            "name": "Unauthorized Override", 
            "count": high_count,
            "breakdown": {"lock": high_ssh, "plug": high_tel}
        }
    ]

    # top_risk is still derived from the broad risk tiers for the summary card
    risks = {
        "Malicious Payload (Critical)": critical_count,
        "Unauthorized Override (High)": high_count,
        "Credential Stuffing (Low)": low_count,
        "Automated Probing (No Risk)": no_risk_count,
    }
    top_risk = max(risks, key=risks.get)

    intents = [i for i in intents_list if i["count"] > 0]
    intents = sorted(intents, key=lambda x: x['count'], reverse=True)

    end_date = logs_df['timestamp'].max()
    date_labels = [d.strftime('%m-%d') for d in pd.date_range(start=(end_date - pd.Timedelta(days=6)).date(), end=end_date.date(), freq='D')]
    daily_counts = logs_df.groupby(logs_df['timestamp'].dt.strftime('%m-%d')).size()

    creds_df = logs_df[logs_df['eventid'].isin(['cowrie.login.success', 'cowrie.login.failed'])].copy()
    if not creds_df.empty:
        creds_df['cred_pair'] = creds_df['username'].astype(str) + " : " + creds_df['password'].astype(str)
        # Drop placeholder credential pairs (the literal below is captured data,
        # not a message - it must stay as-is for the filter to keep matching)
        top_creds = [{"pair": pair, "count": int(cnt)} for pair, cnt in creds_df[~creds_df['cred_pair'].str.contains('这里填', na=False)]['cred_pair'].value_counts().head(50).items()]
    else: 
        top_creds = []

    commands_df = logs_df[critical_mask]
    commands_list = []
    if not commands_df.empty and 'input' in commands_df.columns:
        valid_cmds = commands_df[commands_df['input'] != '']['input']
        top_commands = valid_cmds.value_counts().head(50)
        commands_list = [{"input": cmd, "count": int(cnt)} for cmd, cnt in top_commands.items()]

    all_ips_counts = logs_df['src_ip'].value_counts()

    geo_data_map = {}
    for ip, count in all_ips_counts.items():
        country = ip_country_cache.get(ip, 'Unknown')
        if country != 'Unknown': 
            geo_data_map[country] = geo_data_map.get(country, 0) + int(count)

    geo_list = [["Country", "Attack Attempts"]] + [[k, v] for k, v in geo_data_map.items()]
    if len(geo_list) == 1: 
        geo_list.append(["Unknown", 0])

    return jsonify({
        "summary": {"total": total, "top_device": top_device, "top_risk": top_risk.split(' (')[0], "disruptions": disruptions},
        "trend": {"labels": date_labels, "data": [int(daily_counts.get(label, 0)) for label in date_labels]},
        "peak_hours": {"labels": [f"{i:02d}:00" for i in range(24)], "data": [int(logs_df['timestamp'].dt.hour.value_counts().sort_index().get(i, 0)) for i in range(24)]},
        "top_credentials": top_creds, "intents": intents, "commands": commands_list, "geo": geo_list
    })

@app.route('/api/sessions', methods=['GET'])
@token_required
def get_available_sessions():
    """
    List the attacker IPs worth investigating - those that reached Critical
    or High risk - for the dropdown on the Attacker Details page.
    """
    logs_df = get_fresh_dataframe()
    if logs_df.empty:
        return jsonify([])
    
    agg_dict = {
        'last_seen': ('timestamp', 'max'),
        'events': ('eventid', lambda x: list(x))
    }
    if 'input' in logs_df.columns:
        agg_dict['inputs'] = ('input', lambda x: list(x))
        
    attackers = logs_df.groupby('src_ip').agg(**agg_dict).reset_index()
    attackers = attackers.sort_values('last_seen', ascending=False)
    
    attacker_list = []
    for _, row in attackers.iterrows():
        events = row['events']
        inputs = row.get('inputs', [])
        
        has_critical = any(str(e).startswith('cowrie.command.') for e in events) or any(str(i) not in ['nan', '', 'N/A'] for i in inputs)
        has_high = 'cowrie.login.success' in events
        
        if has_critical:
            risk = "Critical Risk"
        elif has_high:
            risk = "High Risk"
        else:
            risk = "Low Risk"
            
        if risk in ["Critical Risk", "High Risk"]:
            attacker_list.append({
                "ip": row['src_ip'], 
                "risk": risk
            })
            
    return jsonify(attacker_list)

@app.route('/api/attacker/details', methods=['GET'])
@token_required
def get_attacker_details():
    """
    Full forensic profile for one IP: which devices it hit, every distinct
    credential pair it tried, every unique payload it ran (hex decoded), and
    a chronological timeline of its sessions.
    """
    target_ip = request.args.get('ip')
    logs_df = get_fresh_dataframe()
    
    if not target_ip or logs_df.empty:
        return jsonify({})
    
    attacker_logs = logs_df[logs_df['src_ip'] == target_ip].sort_values('timestamp')
    if attacker_logs.empty:
        return jsonify({})
        
    connect_events = attacker_logs[attacker_logs['eventid'] == 'cowrie.session.connect']
    if not connect_events.empty:
        ports = connect_events['dst_port'].unique()
    else:
        ports = attacker_logs['dst_port'].unique()
        
    devices = []
    if any(p in [22, 2222] for p in ports): devices.append("Smart Door Lock (SSH)")
    if any(p in [23, 2223] for p in ports): devices.append("Smart Plug (Telnet)")
    device_str = " & ".join(devices) if devices else "Unknown"
    
    profile = {
        "ip": target_ip,
        "first_seen": attacker_logs['timestamp'].iloc[0].strftime('%Y-%m-%dT%H:%M:%S+08:00'),
        "total_sessions": int(attacker_logs['session'].nunique()), 
        "device": device_str
    }
    
    timeline, credentials, commands = [], [], []
    seen_creds, seen_cmds = set(), set()
    
    for _, row in attacker_logs.iterrows():
        event = row['eventid']
        inp = str(row.get('input', ''))
        has_payload = inp not in ['nan', '', 'N/A']
        is_cmd = str(event).startswith('cowrie.command.')
        
        time_str = row['timestamp'].strftime('%Y-%m-%dT%H:%M:%S+08:00')
        
        if event == 'cowrie.session.connect':
            timeline.append({"time": time_str, "event": event, "title": "Connection Established", "desc": "Attacker connected to honeypot."})
        elif event in ['cowrie.login.success', 'cowrie.login.failed']:
            status = "Success" if 'success' in event else "Failed"
            usr = row.get('username', 'N/A')
            pwd = row.get('password', 'N/A')
            cred_key = f"{usr}:{pwd}:{status}"
            
            if cred_key not in seen_creds:
                seen_creds.add(cred_key)
                credentials.append({"username": usr, "password": pwd, "result": status})
                
            device_name = 'Smart Door Lock' if row.get('dst_port') in [22, 2222] else 'Smart Plug'
            timeline.append({"time": time_str, "event": event, "title": f"Login {status} ({device_name})", "desc": f"Attempted login with credentials: {usr} / {pwd}"})
            
        elif has_payload or is_cmd:
            cmd = inp if has_payload else str(event)
            decoded_cmd = decode_hex_payload(cmd)
            if cmd not in seen_cmds and cmd:
                seen_cmds.add(cmd)
                commands.append({"raw": cmd, "decoded": decoded_cmd})
            desc_text = f"Payload: {cmd}"
            if decoded_cmd:
                desc_text += f" | Decoded: {decoded_cmd}"
            port = row.get('dst_port')
            device_name = 'Smart Door Lock' if port in [22, 2222] else 'Smart Plug'
            intent_title = f"Malicious Payload Injection ({device_name})"
            timeline.append({"time": time_str, "event": "cowrie.command.input", "title": intent_title, "desc": desc_text})

    return jsonify({"profile": profile, "credentials": credentials, "commands": commands, "timeline": timeline})


# Start background workers after all functions are defined
threading.Thread(target=email_alert_worker, daemon=True).start()
threading.Thread(target=geo_ip_worker, daemon=True).start()

if __name__ == '__main__':
    print("TAR Honeypot Backend Started...")
    app.run(host='0.0.0.0', port=5000, debug=True)