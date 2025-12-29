from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import mysql.connector
import os
import numpy as np
from PIL import Image
from fuzzywuzzy import fuzz
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps  # <--- FIXED: Added missing import

app = Flask(__name__)
app.secret_key = "lost2found_secret_key"

# --- CONFIGURATIONS ---
UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def get_db():
    return mysql.connector.connect(
        host="localhost", 
        user="root", 
        password="root", 
        database="lost2found_db"
    )

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- LOGIN DECORATOR (FIXED) ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- AI & IMAGE LOGIC ---

def compare_images(img_path1, img_path2):
    """
    Compares two images using Color Histograms.
    Returns a similarity score (0-100).
    """
    try:
        # Load images
        i1 = Image.open(img_path1).resize((64, 64)).convert('RGB')
        i2 = Image.open(img_path2).resize((64, 64)).convert('RGB')
        
        # Calculate histograms
        h1 = i1.histogram()
        h2 = i2.histogram()
        
        # Calculate Euclidean distance between histograms
        h1_arr = np.array(h1)
        h2_arr = np.array(h2)
        diff = np.sqrt(np.sum((h1_arr - h2_arr) ** 2))
        
        # Normalize to a 0-100 score (Approximate heuristic)
        max_diff = 40000 
        score = max(0, 100 - (diff / max_diff * 100))
        return int(score)
    except Exception as e:
        print(f"Image comparison error: {e}")
        return 0

def calculate_similarity(lost_entry, found_item):
    """
    Returns a weighted score based on Text, Category, and Image.
    """
    # 1. Text Match (Fuzzy) - 40% Weight
    text_score = fuzz.token_set_ratio(lost_entry['item_name'], found_item['item_name'])
    
    # 2. Category Match - 30% Weight
    cat_score = 100 if lost_entry['category'] == found_item['category'] else 0
    
    # 3. Location Match - 10% Weight
    loc_score = fuzz.partial_ratio(lost_entry['location_lost'], found_item['location_found'])
    
    # 4. Image Match - 20% Weight (Only if both have images)
    img_score = 0
    if lost_entry.get('image_path') and found_item['image_path']:
        p1 = os.path.join(app.config['UPLOAD_FOLDER'], lost_entry['image_path'])
        p2 = os.path.join(app.config['UPLOAD_FOLDER'], found_item['image_path'])
        if os.path.exists(p1) and os.path.exists(p2):
            img_score = compare_images(p1, p2)
    
    # Calculate Total Weighted Score
    total_score = (text_score * 0.4) + (cat_score * 0.3) + (loc_score * 0.1) + (img_score * 0.2)
    
    # If no images, redistribute the 20% weight to text
    if img_score == 0:
        total_score = (text_score * 0.5) + (cat_score * 0.35) + (loc_score * 0.15)

    return int(total_score)

def find_matches_smart(lost_entry):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # Fetch ALL available found items to compare
    cursor.execute("SELECT * FROM found_items WHERE status = 'available'")
    found_pool = cursor.fetchall()
    conn.close()
    
    matches = []
    for found in found_pool:
        score = calculate_similarity(lost_entry, found)
        
        # Filter: Only show if match is decent (> 45%)
        if score > 45:
            matches.append({'item': found, 'confidence': score})
            
    # Sort by highest confidence
    matches.sort(key=lambda x: x['confidence'], reverse=True)
    return matches

# --- CORE ROUTES ---

@app.route('/')
def index():
    return render_template('home.html')

# Public Registry (No login required)
@app.route('/browse')
def browse():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM found_items WHERE status = 'available' ORDER BY date_found DESC")
    items = cursor.fetchall()
    conn.close()
    # Ensure you are using the updated registry.html template provided earlier
    return render_template('registry.html', items=items)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# --- DASHBOARD ROUTE (Updated) ---
@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # 1. Fetch items I LOST
    cursor.execute("SELECT * FROM lost_items WHERE user_email = %s ORDER BY date_lost DESC", 
                   (session['user'],))
    lost_items = cursor.fetchall()
    
    # 2. Fetch items I FOUND (New)
    cursor.execute("SELECT * FROM found_items WHERE finder_email = %s ORDER BY date_found DESC", 
                   (session['user'],))
    found_items = cursor.fetchall()

    conn.close()
    return render_template('dashboard.html', items=lost_items, found_items=found_items)

# --- AUTHENTICATION ---
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
            if user and check_password_hash(user['password'], password):
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

# --- REPORTING ---

@app.route('/report_lost', methods=['GET', 'POST'])
@login_required
def report_lost():
    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        location = request.form['location']
        date = request.form['date']
        description = request.form.get('description', '')
        
        filename = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"lost_{datetime.now().timestamp()}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        conn = get_db()
        cursor = conn.cursor()
        
        query = """
            INSERT INTO lost_items 
            (item_name, category, location_lost, date_lost, user_email, description, status, image_path) 
            VALUES (%s, %s, %s, %s, %s, %s, 'searching', %s)
        """
        cursor.execute(query, (name, category, location, date, session['user'], description, filename))
        
        lost_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        lost_entry = {
            'item_name': name,
            'category': category,
            'location_lost': location,
            'image_path': filename
        }
        
        matches = find_matches_smart(lost_entry)
        
        return render_template('matches.html', matches=matches, lost_id=lost_id)
    
    return render_template('report_lost.html')

@app.route('/report_found', methods=['GET', 'POST'])
@login_required
def report_found():
    if request.method == 'POST':
        name = request.form['name']
        category = request.form['category']
        date = request.form['date']
        location = request.form['location']
        
        file = request.files['image']
        filename = ""
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            import secrets
            filename = f"{secrets.token_hex(3)}_{filename}"
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        
        conn = get_db()
        cursor = conn.cursor(dictionary=True)
        
        # 1. Save Found Item
        cursor.execute("INSERT INTO found_items (item_name, category, date_found, location_found, image_path, status, finder_email) VALUES (%s, %s, %s, %s, %s, 'available', %s)",
                       (name, category, date, location, filename, session['user']))
        found_item_id = cursor.lastrowid
        
        # 2. Reverse Match Logic (Notify potential losers)
        cursor.execute("SELECT * FROM lost_items WHERE status = 'searching'")
        active_lost_items = cursor.fetchall()
        
        from difflib import SequenceMatcher
        
        for lost in active_lost_items:
            score = 0
            name_sim = SequenceMatcher(None, lost['item_name'].lower(), name.lower()).ratio()
            score += name_sim * 40
            
            if lost['category'] == category:
                score += 30
                
            loc_sim = SequenceMatcher(None, lost['location_lost'].lower(), location.lower()).ratio()
            score += 20
            
            if score > 60:
                print(f"MATCH FOUND! Lost Item {lost['id']} matches Found Item {found_item_id}")
                cursor.execute("UPDATE lost_items SET status = 'potential_match' WHERE id = %s", (lost['id'],))

        conn.commit()
        conn.close()
        
        flash("Report submitted! We have also cross-checked it with lost items.")
        return redirect(url_for('dashboard'))

    return render_template('report_found.html')

# --- CLAIM & ADMIN ---

@app.route('/claim/<int:fid>/<int:lid>', methods=['POST'])
@login_required
def claim(fid, lid):
    proof = request.form['proof']
    conn = get_db()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""INSERT INTO claims (lost_item_id, found_item_id, proof_description) 
                          VALUES (%s, %s, %s)""", (lid, fid, proof))
        
        cursor.execute("UPDATE lost_items SET status = 'pending_approval' WHERE id = %s", (lid,))
        
        conn.commit()
        flash("Claim submitted! Status: Pending Admin Review.")
    except Exception as e:
        flash("Error submitting claim.")
        print(e)
    finally:
        conn.close()

    return redirect(url_for('dashboard'))

# --- REJECT CLAIM ROUTE (FIXED) ---
@app.route('/reject/<int:claim_id>', methods=['POST'])
@login_required
def reject(claim_id):
    # Get the explanation from the form
    reason = request.form.get('reason', 'No reason provided.')
    
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    # We query the claim first
    cursor.execute("SELECT * FROM claims WHERE id = %s", (claim_id,))
    claim = cursor.fetchone()
    
    if claim:
        # Robustly get IDs regardless of column naming
        lid = claim.get('lost_item_id') or claim.get('lost_id')
        fid = claim.get('found_item_id') or claim.get('found_id')

        if lid and fid:
            # 1. Reset Lost Item to 'searching' AND save the reason
            cursor.execute("UPDATE lost_items SET status = 'searching', rejection_reason = %s WHERE id = %s", 
                           (reason, lid))
            
            # 2. Reset Found Item to 'available'
            cursor.execute("UPDATE found_items SET status = 'available' WHERE id = %s", (fid,))
            
            # 3. Delete the Claim
            cursor.execute("DELETE FROM claims WHERE id = %s", (claim_id,))
            
            conn.commit()
            flash("Claim rejected and reason sent to user.")
        else:
            flash("Error: Could not find item IDs in claim record.")
    
    conn.close()
    return redirect(url_for('admin'))

@app.route('/admin')
def admin():
    if 'user' not in session or session.get('user') != "ADMIN": return redirect(url_for('login'))
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    query = """
        SELECT c.id as claim_id, c.proof_description, l.id as lost_id, l.item_name as lost_item, 
        l.user_email as claimant_email, f.item_name as found_item, f.image_path 
        FROM claims c 
        JOIN found_items f ON c.found_item_id = f.id 
        JOIN lost_items l ON c.lost_item_id = l.id
        WHERE c.admin_status = 'pending'
    """
    cursor.execute(query)
    data = cursor.fetchall()
    conn.close()
    return render_template('admin.html', claims=data)

@app.route('/approve/<int:cid>/<int:lid>', methods=['POST'])
def approve(cid, lid):
    if 'user' not in session or session.get('user') != "ADMIN": return redirect(url_for('login'))
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("SELECT found_item_id FROM claims WHERE id = %s", (cid,))
    result = cursor.fetchone()
    
    if result:
        fid = result[0]
        # 1. Approve Claim
        cursor.execute("UPDATE claims SET admin_status = 'approved' WHERE id = %s", (cid,))
        # 2. Mark Found Item as Returned
        cursor.execute("UPDATE found_items SET status = 'returned' WHERE id = %s", (fid,))
        # 3. Mark Lost Item as Returned
        cursor.execute("UPDATE lost_items SET status = 'returned' WHERE id = %s", (lid,))
        
        conn.commit()
        flash("Claim approved. User notified on dashboard.")
        
    conn.close()
    return redirect(url_for('admin'))

@app.route('/check_matches/<int:lost_id>')
@login_required
def check_matches(lost_id):
    conn = get_db()
    cursor = conn.cursor(dictionary=True)
    
    cursor.execute("SELECT * FROM lost_items WHERE id = %s AND user_email = %s", (lost_id, session['user']))
    lost_item = cursor.fetchone()
    conn.close()
    
    if not lost_item:
        flash("Item not found.")
        return redirect(url_for('dashboard'))
        
    matches = find_matches_smart(lost_item)
    return render_template('matches.html', matches=matches, lost_id=lost_id)

if __name__ == '__main__':
    app.run(debug=True)