from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import mysql.connector
import os
import numpy as np
import math
import secrets
from PIL import Image
from fuzzywuzzy import fuzz
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
from difflib import SequenceMatcher
from flask_mail import Mail, Message
import qrcode
import uuid
import os

app = Flask(__name__)
app.secret_key = "lost2found_secret_key"

# --- CONFIGURATIONS ---
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- EMAIL CONFIGURATION (Simulation Mode if not set) ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'your-email@gmail.com' 
app.config['MAIL_PASSWORD'] = 'your-app-password'    
app.config['MAIL_DEFAULT_SENDER'] = 'noreply@lost2found.com'

mail = Mail(app)

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- DATABASE CONNECTION ---
def get_db():
    return mysql.connector.connect(
        host="localhost", 
        user="root", 
        password="root", 
        database="lost2found_db"
    )

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- LOGIN DECORATOR ---
def is_logged_in(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- EMAIL HELPER ---
def send_notification(subject, recipient, body):
    try:
        msg = Message(subject, recipients=[recipient])
        msg.body = body
        mail.send(msg)
        print(f"📧 EMAIL SENT to {recipient}: {subject}")
    except Exception as e:
        print(f"⚠️ EMAIL SIMULATION (To: {recipient}): {subject}")

# --- SMART GEO-FENCING ---
def calculate_distance(coords1, coords2):
    if not coords1 or not coords2: return float('inf')
    try:
        lat1, lon1 = map(float, coords1.split(','))
        lat2, lon2 = map(float, coords2.split(','))
        R = 6371000 
        phi1, phi2 = math.radians(lat1), math.radians(lat2)
        dphi = math.radians(lat2 - lat1)
        dlambda = math.radians(lon2 - lon1)
        a = math.sin(dphi / 2)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(dlambda / 2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c 
    except: return float('inf')

# --- HELPER FUNCTION ---
def get_user_by_email(email):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    conn.close()
    return user

# --- NEURAL IMAGE & TEXT MATCHING ---
def compare_images(img_path1, img_path2):
    try:
        i1 = Image.open(img_path1).resize((64, 64)).convert('RGB')
        i2 = Image.open(img_path2).resize((64, 64)).convert('RGB')
        h1 = i1.histogram()
        h2 = i2.histogram()
        h1_arr = np.array(h1)
        h2_arr = np.array(h2)
        diff = np.sqrt(np.sum((h1_arr - h2_arr) ** 2))
        max_diff = 40000 
        return int(max(0, 100 - (diff / max_diff * 100)))
    except Exception as e:
        return 0

def calculate_similarity(lost_entry, found_item):
    text_score = fuzz.token_set_ratio(lost_entry['item_name'], found_item['item_name'])
    cat_score = 100 if lost_entry['category'] == found_item['category'] else 0
    loc_score = fuzz.partial_ratio(lost_entry['location_lost'], found_item['location_found'])
    img_score = 0
    if lost_entry.get('image_path') and found_item['image_path']:
        p1 = os.path.join(app.config['UPLOAD_FOLDER'], lost_entry['image_path'])
        p2 = os.path.join(app.config['UPLOAD_FOLDER'], found_item['image_path'])
        if os.path.exists(p1) and os.path.exists(p2):
            img_score = compare_images(p1, p2)
    
    total_score = (text_score * 0.4) + (cat_score * 0.3) + (loc_score * 0.1) + (img_score * 0.2)
    if img_score == 0:
        total_score = (text_score * 0.5) + (cat_score * 0.35) + (loc_score * 0.15)
    return int(total_score)

def find_matches_smart(lost_entry):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM found_items WHERE status IN ('available', 'matched')")
    found_pool = cursor.fetchall()
    conn.close()
    
    matches = []
    for found in found_pool:
        score = calculate_similarity(lost_entry, found)
        distance = calculate_distance(lost_entry.get('location_coords'), found.get('location_coords'))
        if distance <= 100: score += 15 
        elif distance <= 500: score += 10
        elif distance <= 1000: score += 5
        if score > 45:
            found['match_score'] = round(min(score, 100), 1)
            found['distance_meters'] = round(distance, 0) if distance != float('inf') else None
            matches.append(found)
    matches.sort(key=lambda x: x['match_score'], reverse=True)
    return matches

# --- AI FRAUD DETECTION ---
def check_fraud_probability(user_email, item_name):
    fraud_points = 0
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # 1. Frequency
    cursor.execute("SELECT COUNT(*) as c FROM claims WHERE user_email=%s AND created_at > NOW() - INTERVAL 1 DAY", (user_email,))
    if cursor.fetchone()['c'] >= 2: fraud_points += 4

    # 2. History
    cursor.execute("SELECT COUNT(*) as c FROM claims WHERE user_email=%s AND status='rejected'", (user_email,))
    if cursor.fetchone()['c'] > 0: fraud_points += 3
    
    # 3. Keywords
    high_value_keywords = ['key', 'wallet', 'phone', 'iphone', 'macbook', 'laptop', 'cash', 'card']
    if any(word in item_name.lower() for word in high_value_keywords):
        fraud_points += 2

    conn.close()
    return fraud_points

# --- ROUTES ---

@app.route('/')
def index():
    return render_template('home.html')

@app.route('/browse')
def browse():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM found_items WHERE status = 'available' ORDER BY date_found DESC")
    items = cursor.fetchall()
    conn.close()
    return render_template('registry.html', items=items)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        action = request.form.get('action') 
        email = request.form.get('email')
        password = request.form.get('password')
        conn = get_db()
        cursor = conn.cursor(dictionary=True)

        if action == 'signup':
            name = request.form.get('fullname')
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                flash("Email exists.")
            else:
                pw_hash = generate_password_hash(password)
                cursor.execute("INSERT INTO users (name, email, password) VALUES (%s, %s, %s)", (name, email, pw_hash))
                conn.commit()
                flash("Account created! Log in.")

        elif action == 'login':
            if email == "adminl2f@gmail.com" and password == "l2f":
                session['user'] = "ADMIN"
                session['is_admin'] = True
                conn.close()
                return redirect(url_for('admin'))

            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()
            
            # --- BLOCKED CHECK ---
            if user and check_password_hash(user['password'], password):
                if user['is_blocked'] == 1:
                    flash("⛔ Account Blocked by Admin. Contact Support.")
                    conn.close()
                    return redirect(url_for('login'))
                
                session['user'] = user['email']
                session['is_admin'] = False
                conn.close()
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid Credentials")
        conn.close()
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for('index'))

# Inside app.py

@app.route('/dashboard')
@is_logged_in
def dashboard():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # 1. Get Current User
    cursor.execute("SELECT id, email, name, reward_points FROM users WHERE email = %s", (session['user'],))
    current_user = cursor.fetchone()

    # 2. Lost Items
    cursor.execute("""
        SELECT l.*, c.id as claim_id, c.admin_status as claim_admin_status
        FROM lost_items l
        LEFT JOIN claims c ON l.id = c.lost_item_id AND c.status != 'rejected'
        WHERE l.user_email = %s ORDER BY l.date_lost DESC
    """, (session['user'],))
    lost_items = cursor.fetchall()
    
    # 3. Found Items
    cursor.execute("""
        SELECT f.*, c.id as claim_id, c.admin_status as claim_admin_status
        FROM found_items f
        LEFT JOIN claims c ON f.id = c.found_item_id AND c.admin_status = 'approved'
        WHERE f.finder_email = %s ORDER BY f.date_found DESC
    """, (session['user'],))
    found_items = cursor.fetchall()

    # 4. NeuralTags
    cursor.execute("SELECT * FROM neural_tags WHERE user_id = %s ORDER BY created_at DESC", (current_user['id'],))
    my_tags = cursor.fetchall()

    # 5. Inbox Messages (With Read Status)
    try:
        cursor.execute("""
            SELECT m.*, t.item_name 
            FROM tag_messages m
            JOIN neural_tags t ON m.tag_id = t.id
            WHERE m.owner_id = %s
            ORDER BY m.created_at DESC
        """, (current_user['id'],))
        inbox_messages = cursor.fetchall()
        
        # Calculate Unread Count
        unread_count = sum(1 for m in inbox_messages if m.get('is_read', 0) == 0)
    except:
        inbox_messages = []
        unread_count = 0

    # 6. Leaderboard
    cursor.execute("SELECT name, reward_points FROM users ORDER BY reward_points DESC LIMIT 5")
    leaderboard = cursor.fetchall()

    conn.close()
    
    return render_template('dashboard.html', 
                           items=lost_items, 
                           found_items=found_items, 
                           my_tags=my_tags,
                           inbox_messages=inbox_messages,
                           unread_count=unread_count,  # <-- Passed to template
                           leaderboard=leaderboard,
                           user_points=current_user['reward_points'])

@app.route('/report_lost', methods=['GET', 'POST'])
@is_logged_in
def report_lost():
    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        location = request.form['location']
        coords = request.form.get('location_coords')
        date = request.form['date']
        description = request.form.get('description', 'Reported via Neural Sync')
        
        filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = f"lost_{secrets.token_hex(4)}_{secure_filename(file.filename)}"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        query = """INSERT INTO lost_items (item_name, category, location_lost, location_coords, date_lost, user_email, description, status, image_path) 
                   VALUES (%s, %s, %s, %s, %s, %s, %s, 'searching', %s)"""
        cursor.execute(query, (name, category, location, coords, date, session['user'], description, filename))
        lost_id = cursor.lastrowid
        conn.commit()

        lost_entry = {'item_name': name, 'category': category, 'location_lost': location, 'location_coords': coords, 'image_path': filename}
        matches = find_matches_smart(lost_entry)
        conn.close()
        return render_template('matches.html', matches=matches, lost_id=lost_id)
    return render_template('report_lost.html')

@app.route('/report_found', methods=['GET', 'POST'])
@is_logged_in
def report_found():
    if request.method == 'POST':
        # 1. Capture Form Data
        name = request.form['name']
        category = request.form['category']
        location = request.form['location']
        location_coords = request.form['location_coords'] # Captures the coordinates from the map
        date_found = request.form['date_found']
        image = request.files['image']

        # 2. Handle Image Upload
        filename = ""
        if image:
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        # 3. Save to Database
        # Note: We insert "Found via App" as description since the form doesn't have a description field
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO found_items 
            (item_name, category, description, location, location_coords, date_found, finder_email, image_path, status) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'searching')
        """, (name, category, "Found via App", location, location_coords, date_found, session['user'], filename))
        
        conn.commit()
        conn.close()

        flash("Item reported successfully! Thanks for helping.", "success")
        return redirect(url_for('dashboard'))
        
    return render_template('report_found.html')

@app.route('/claim/<int:fid>/<int:lid>', methods=['POST'])
@is_logged_in
def claim(fid, lid):
    user_email = session['user']
    proof = request.form['proof']
    
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT item_name, finder_email FROM found_items WHERE id=%s", (fid,))
    item_data = cursor.fetchone()
    
    risk_score = check_fraud_probability(user_email, item_data['item_name'])
    status = 'flagged' if risk_score >= 5 else 'pending'
    
    if risk_score >= 5: flash("Claim flagged for review.")
    else: flash("Claim submitted.")

    try:
        cursor.execute("""INSERT INTO claims (lost_item_id, found_item_id, user_email, proof_description, status, admin_status) 
                          VALUES (%s, %s, %s, %s, %s, 'pending')""", (lid, fid, user_email, proof, status))
        cursor.execute("UPDATE lost_items SET status = 'pending_approval' WHERE id = %s", (lid,))
        conn.commit()
        
        if status != 'flagged':
            send_notification("Claim Received", item_data['finder_email'], f"Claim for '{item_data['item_name']}' received.")
            
    except Exception as e:
        print(e)
    finally:
        conn.close()

    return redirect(url_for('dashboard'))

@app.route('/chat/<int:claim_id>', methods=['GET', 'POST'])
@is_logged_in
def chat(claim_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # 1. Fetch Claim Details (Keep your existing Join logic)
    query = """
        SELECT c.*, f.finder_email, f.item_name, f.id as found_id
        FROM claims c 
        JOIN found_items f ON c.found_item_id = f.id
        WHERE c.id = %s
    """
    cursor.execute(query, (claim_id,))
    claim = cursor.fetchone()

    if not claim:
        conn.close()
        return redirect(url_for('dashboard'))
        
    # Security Check
    if session['user'] not in [claim['user_email'], claim['finder_email']] and not session.get('is_admin'):
        conn.close()
        flash("Unauthorized access.")
        return redirect(url_for('dashboard'))

    # --- FIX: FETCH THE FULL ITEM DETAILS ---
    # We need this so the template can check 'item.status'
    cursor.execute("SELECT * FROM found_items WHERE id = %s", (claim['found_item_id'],))
    item = cursor.fetchone() 

    # 2. Handle Sending Messages
    if request.method == 'POST':
        msg = request.form.get('message')
        if msg:
            # Added 'timestamp' to ensure order is correct
            cursor.execute("""
                INSERT INTO messages (claim_id, sender_email, message_text, timestamp) 
                VALUES (%s, %s, %s, NOW())
            """, (claim_id, session['user'], msg))
            conn.commit()
            # Redirect to prevent form re-submission on refresh
            return redirect(url_for('chat', claim_id=claim_id))
    
    # 3. Fetch Chat History
    cursor.execute("SELECT * FROM messages WHERE claim_id = %s ORDER BY timestamp ASC", (claim_id,))
    messages = cursor.fetchall()
    
    is_finder = (session['user'] == claim['finder_email'])
    
    conn.close()
    
    # 4. Pass 'item' to the template
    return render_template('chat.html', 
                           messages=messages, 
                           claim=claim, 
                           claim_id=claim_id, 
                           is_finder=is_finder, 
                           item=item) # <--- This fixes the error

@app.route('/mark_returned/<int:claim_id>', methods=['GET', 'POST'])
@is_logged_in
def mark_returned(claim_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # 1. Get the claim details
    cursor.execute("SELECT * FROM claims WHERE id=%s", (claim_id,))
    claim = cursor.fetchone()

    if not claim:
        conn.close()
        flash("Claim not found", "danger")
        return redirect(url_for('dashboard'))

    # GUARD CHECK (From previous fix)
    if claim['status'] == 'solved' or claim['status'] == 'returned':
        conn.close()
        flash("This item is already marked as returned.", "info")
        return redirect(url_for('dashboard'))

    # --- FIX 1: UPDATE CLAIM STATUS TO 'solved' AND SET TIMESTAMP ---
    # This removes it from "Active Chats", adds it to "History", 
    # and provides the date for the Admin Graph.
    cursor.execute("UPDATE claims SET status='solved', solved_at=NOW() WHERE id=%s", (claim_id,))
    
    # 2. Update FOUND ITEM status (Keeps User Dashboard "RETURNED" badge)
    cursor.execute("UPDATE found_items SET status='returned' WHERE id=%s", (claim['found_item_id'],))

    # 3. Update LOST ITEM status
    cursor.execute("UPDATE lost_items SET status='returned' WHERE id=%s", (claim['lost_item_id'],))

    # 4. Reward the Finder
    cursor.execute("SELECT finder_email FROM found_items WHERE id=%s", (claim['found_item_id'],))
    item = cursor.fetchone()

    if item:
        finder_email = item['finder_email']
        cursor.execute("SELECT id FROM users WHERE email=%s", (finder_email,))
        user_record = cursor.fetchone()
        
        if user_record:
            cursor.execute("UPDATE users SET reward_points = reward_points + 50 WHERE id=%s", (user_record['id'],))
            flash("Item marked returned. Finder rewarded 50 points!", "success")
    
    conn.commit()
    conn.close()
    return redirect(url_for('dashboard'))

@app.route('/mark_message_read/<int:message_id>')
@is_logged_in
def mark_message_read(message_id):
    conn = get_db()
    cursor = conn.cursor()
    
    # Update status to Read (1)
    cursor.execute("UPDATE tag_messages SET is_read = 1 WHERE id = %s", (message_id,))
    
    conn.commit()
    conn.close()
    
    # Redirect back to dashboard with 'tab=alerts' parameter so it stays on the right tab
    return redirect(url_for('dashboard', tab='alerts'))

# --- ADMIN PANEL ROUTES ---

@app.route('/admin')
def admin():
    # 1. Security Check
    if 'user' not in session or session.get('user') != "ADMIN":
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor(dictionary=True)

    # ---------------------------------------------------------
    # 2. Fetch Pending Claims (With Images for the Cards)
    # ---------------------------------------------------------
    # We join lost_items and found_items to get images and descriptions
    cursor.execute("""
        SELECT 
            c.id as claim_id,
            c.user_email as claimant_email,
            c.proof_description,
            c.status as risk_status,
            f.item_name as found_item,
            f.image_path as found_image,
            l.image_path as lost_image
        FROM claims c
        JOIN found_items f ON c.found_item_id = f.id
        JOIN lost_items l ON c.lost_item_id = l.id
        WHERE c.admin_status = 'pending'
    """)
    pending_claims = cursor.fetchall()

    # ---------------------------------------------------------
    # 3. Fetch Active Chats
    # ---------------------------------------------------------
    # FIX: Join 'found_items' to get the finder_email. 
    # Removed 'c.finder_id' which caused the error.
    cursor.execute("""
        SELECT 
            c.id as claim_id, 
            f.item_name, 
            c.status,
            f.finder_email, 
            c.user_email as claimant
        FROM claims c
        JOIN found_items f ON c.found_item_id = f.id
        WHERE c.status != 'solved' AND c.status != 'rejected'
    """)
    active_chats = cursor.fetchall()

    # ---------------------------------------------------------
    # 4. Fetch Resolution Log (History)
    # ---------------------------------------------------------
    cursor.execute("""
        SELECT 
            c.id, 
            f.item_name, 
            c.solved_at,
            f.finder_email,
            c.user_email as claimant
        FROM claims c
        JOIN found_items f ON c.found_item_id = f.id
        WHERE c.status = 'solved'
        ORDER BY c.solved_at DESC
    """)
    history = cursor.fetchall()

    # ---------------------------------------------------------
    # 5. Fetch Users
    # ---------------------------------------------------------
    cursor.execute("SELECT id, name, email, is_blocked FROM users")
    users = cursor.fetchall()

    # ---------------------------------------------------------
    # 6. Graph Data (Last 7 Days)
    # ---------------------------------------------------------
    cursor.execute("""
        SELECT DATE(solved_at) as date, COUNT(*) as count 
        FROM claims 
        WHERE status = 'solved' AND solved_at >= DATE(NOW()) - INTERVAL 7 DAY
        GROUP BY DATE(solved_at) 
        ORDER BY DATE(solved_at)
    """)
    graph_data = cursor.fetchall()
    
    dates = [row['date'].strftime('%Y-%m-%d') for row in graph_data]
    counts = [row['count'] for row in graph_data]

    cursor.close()
    conn.close()

    return render_template('admin.html', 
                         claims=pending_claims, 
                         active_chats=active_chats,
                         history=history,
                         users=users,
                         graph_dates=dates, 
                         graph_counts=counts)

@app.route('/approve/<int:cid>', methods=['POST'])
def approve(cid):
    if session.get('user') != "ADMIN": return redirect(url_for('login'))
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT lost_item_id, found_item_id, user_email FROM claims WHERE id = %s", (cid,))
    res = cursor.fetchone()
    if res:
        cursor.execute("UPDATE claims SET admin_status = 'approved' WHERE id = %s", (cid,))
        cursor.execute("UPDATE found_items SET status = 'matched' WHERE id = %s", (res['found_item_id'],))
        cursor.execute("UPDATE lost_items SET status = 'potential_match' WHERE id = %s", (res['lost_item_id'],))
        conn.commit()
        send_notification("Claim Approved", res['user_email'], "Claim approved. Chat unlocked.")
        flash("Claim Approved!")
    conn.close()
    return redirect(url_for('admin'))

@app.route('/reject/<int:claim_id>', methods=['POST'])
@is_logged_in
def reject(claim_id):
    if session.get('user') != "ADMIN": return redirect(url_for('login'))
    reason = request.form.get('reason', 'No reason provided.')
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT lost_item_id, found_item_id, user_email FROM claims WHERE id = %s", (claim_id,))
    res = cursor.fetchone()
    if res:
        cursor.execute("UPDATE lost_items SET status = 'searching', rejection_reason = %s WHERE id = %s", (reason, res['lost_item_id']))
        cursor.execute("UPDATE found_items SET status = 'available' WHERE id = %s", (res['found_item_id'],))
        cursor.execute("UPDATE claims SET admin_status = 'rejected', status = 'rejected' WHERE id = %s", (claim_id,))
        conn.commit()
        send_notification("Claim Rejected", res['user_email'], f"Rejected: {reason}")
        flash("Claim rejected.")
    conn.close()
    return redirect(url_for('admin'))

@app.route('/check_matches/<int:lost_id>')
@is_logged_in
def check_matches(lost_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM lost_items WHERE id = %s AND user_email = %s", (lost_id, session['user']))
    lost_item = cursor.fetchone()
    conn.close()
    if not lost_item: return redirect(url_for('dashboard'))
    matches = find_matches_smart(lost_item)
    return render_template('matches.html', matches=matches, lost_id=lost_id)

# --- NEW ROUTE: TOGGLE BLOCK ---
@app.route('/toggle_block/<int:user_id>')
def toggle_block(user_id):
    if session.get('user') != "ADMIN": return redirect(url_for('login'))
    
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # Get current status
    cursor.execute("SELECT is_blocked FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    
    if user:
        new_status = 0 if user['is_blocked'] else 1
        cursor.execute("UPDATE users SET is_blocked = %s WHERE id = %s", (new_status, user_id))
        conn.commit()
        action = "Blocked" if new_status else "Unblocked"
        flash(f"User successfully {action}.")
    
    conn.close()
    return redirect(url_for('admin'))

# ==========================================
# FEATURE 1: NEURAL TAGS (QR CODES)
# ==========================================

@app.route('/create_tag', methods=['POST'])
@is_logged_in
def create_tag():
    user = get_user_by_email(session['user'])
    item_name = request.form['item_name']
    item_desc = request.form['item_desc']
    
    # 1. Generate unique secure code
    unique_code = str(uuid.uuid4())[:8] # Short unique ID
    
    # 2. Create QR Code pointing to your app's scan route
    # In production, replace 'http://127.0.0.1:5000' with your real domain (e.g. ngrok or pythonanywhere)
    scan_url = f"http://127.0.0.1:5000/scan/{unique_code}"
    
    qr = qrcode.make(scan_url)
    qr_filename = f"tag_{unique_code}.png"
    qr_path = os.path.join('static', 'qrcodes', qr_filename)
    
    # Ensure directory exists
    os.makedirs(os.path.join('static', 'qrcodes'), exist_ok=True)
    qr.save(qr_path)
    
    # 3. Save to DB
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO neural_tags (user_id, item_name, item_desc, unique_code, qr_image_path)
        VALUES (%s, %s, %s, %s, %s)
    """, (user['id'], item_name, item_desc, unique_code, f"qrcodes/{qr_filename}"))
    conn.commit()
    conn.close()
    
    flash('NeuralTag generated successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/scan/<unique_code>')
def scan_tag(unique_code):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # Fetch tag details and owner email
    cursor.execute("""
        SELECT t.*, u.email as owner_email, u.name as owner_name 
        FROM neural_tags t 
        JOIN users u ON t.user_id = u.id 
        WHERE t.unique_code = %s
    """, (unique_code,))
    tag = cursor.fetchone()
    conn.close()
    
    if not tag:
        return "Invalid or Deleted Tag", 404
        
    return render_template('tag_found.html', tag=tag)

@app.route('/alert_owner/<unique_code>', methods=['POST'])
def alert_owner(unique_code):
    finder_contact = request.form.get('finder_contact')
    message = request.form.get('message')
    
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # 1. Find the tag and the owner
    cursor.execute("""
        SELECT t.id as tag_id, t.user_id as owner_id, u.name as owner_name 
        FROM neural_tags t 
        JOIN users u ON t.user_id = u.id 
        WHERE unique_code=%s
    """, (unique_code,))
    tag = cursor.fetchone()
    
    if tag:
        # 2. Save message to the Inbox (Database)
        cursor.execute("""
            INSERT INTO tag_messages (tag_id, owner_id, finder_contact, message)
            VALUES (%s, %s, %s, %s)
        """, (tag['tag_id'], tag['owner_id'], finder_contact, message))
        conn.commit()
        
        # 3. Notify the finder
        flash(f"Message sent to {tag['owner_name']}! They will contact you shortly.", 'success')
    else:
        flash("Tag not found.", "danger")
        
    conn.close()
    return redirect(url_for('index'))
      
# ==========================================
# FEATURE 2: KARMA LEADERBOARD
# ==========================================

@app.route('/leaderboard')
def leaderboard():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    # Get top 10 users with karma > 0
    cursor.execute("SELECT name, karma FROM users WHERE karma > 0 ORDER BY karma DESC LIMIT 10")
    leaders = cursor.fetchall()
    conn.close()
    return render_template('leaderboard.html', leaders=leaders)

# ==========================================
# FEATURE 3: PUBLIC SOS LINK
# ==========================================
@app.route('/view_lost/<int:item_id>')
def view_lost(item_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # Fetch safe public details (No private emails/phone numbers exposed directly)
    cursor.execute("""
        SELECT id, item_name, description, location, date_lost, image_path, status 
        FROM lost_items WHERE id = %s
    """, (item_id,))
    item = cursor.fetchone()
    conn.close()

    if not item:
        return "Item not found or removed.", 404

    return render_template('public_item.html', item=item)

if __name__ == '__main__':
    app.run(debug=True)