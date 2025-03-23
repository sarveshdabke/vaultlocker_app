from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, make_response, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet, InvalidToken
import os, random, smtplib, uuid
from email.mime.text import MIMEText
from flask_mail import Mail, Message
from dotenv import load_dotenv
from datetime import datetime, timedelta
from flask_wtf.csrf import CSRFProtect

# Load environment variables
load_dotenv()
EMAIL_USER = os.getenv("EMAIL_USER")  # vaultlocker.official@gmail.com
EMAIL_PASS = os.getenv("EMAIL_PASS")  # SMTP Password
# Initialize Flask app and database
app = Flask(__name__)
# Flask-Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Use Gmail SMTP
app.config['MAIL_PORT'] = 465  # Use 465 for SSL
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = os.getenv("EMAIL_USER")  # Get from .env
app.config['MAIL_PASSWORD'] = os.getenv("EMAIL_PASS")  # Get from .env
app.config['MAIL_DEFAULT_SENDER'] = os.getenv("EMAIL_USER")  # Default sender
app.config['MAIL_DEBUG'] = True
mail = Mail(app)

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")  # Get SECRET_KEY from .env
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///xcrypt.db'  # SQLite database file
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking to save resources
app.config['UPLOAD_FOLDER'] = 'static/uploads'
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}
db = SQLAlchemy(app)
# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    phone = db.Column(db.String(20), nullable=False)
    password = db.Column(db.String(150), nullable=False)
    profile_picture = db.Column(db.String(255), default="default.png")  # Profile picture column

# Define Password model
class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    app_name = db.Column(db.String(150), nullable=False)
    password = db.Column(db.String(150), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('passwords', lazy=True))

# New model for token-based reset requests
class PasswordResetRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), nullable=False)
    token = db.Column(db.String(255), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)

# Load encryption key properly
key_path = 'encryption_key.key'
if not os.path.exists(key_path):
    key = Fernet.generate_key()
    with open(key_path, 'wb') as key_file:
        key_file.write(key)
else:
    with open(key_path, 'rb') as key_file:
        key = key_file.read()

print(f"Loaded Encryption Key: {key}")  # Debugging statement
cipher_suite = Fernet(key)
# Function to check file type
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

MAX_ATTEMPTS = 3  # Maximum login attempts before lockout
LOCKOUT_TIME = 30  # Lockout duration in seconds

# Function to send OTP via email
def send_email_otp(email, otp):
    try:
        msg = Message(
            subject="Your OTP for Verification",
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[email],
            body=f"Your OTP is {otp}. Please enter this code to verify your account."
        )
        mail.send(msg)
        print(f"✅ OTP sent successfully to {email}")
    except Exception as e:
        print(f"❌ Failed to send OTP: {e}")

# Send OTP route
@app.route('/send-otp', methods=['POST'])
def send_otp():
    email = request.json.get('email')  # Get email from request
    user = User.query.filter_by(email=email).first()  # Fetch user by email

    if user:
        otp = str(random.randint(100000, 999999))  # Generate OTP
        hashed_otp = generate_password_hash(otp)  # Hash OTP before storing

        session['otp'] = hashed_otp  # Store hashed OTP
        session['otp_email'] = email  # Store email for verification
        session['otp_expiry'] = (datetime.utcnow() + timedelta(minutes=5)).isoformat()  # OTP expires in 5 min

        # Debugging Logs
        print(f"Generated OTP: {otp}")
        print(f"Stored Hashed OTP in Session: {session['otp']}")
        print(f"OTP Expiry Time: {session['otp_expiry']}")

        send_email_otp(email, otp)  # Send OTP via email
        return jsonify({"message": "OTP sent successfully to registered email"}), 200

    return jsonify({"message": "User not found"}), 404

# Verify OTP route
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    user_otp = request.json.get('otp')  # Get OTP from request JSON
    stored_hashed_otp = session.get('otp')  # Get stored OTP (hashed)
    otp_expiry = session.get('otp_expiry')  # Get OTP expiry time

    # Debugging Logs
    print(f"Received OTP from user: {user_otp}")
    print(f"Stored Hashed OTP: {stored_hashed_otp}")
    print(f"Stored OTP Expiry: {otp_expiry}")

    # Check if OTP exists in session
    if not stored_hashed_otp or not otp_expiry:
        return jsonify({"success": False, "message": "OTP expired or not found"}), 400

    # Check if OTP has expired
    if datetime.utcnow() > datetime.fromisoformat(otp_expiry):
        session.pop('otp', None)
        session.pop('otp_email', None)
        session.pop('otp_expiry', None)
        return jsonify({"success": False, "message": "OTP expired"}), 400

    # Verify OTP using hashing
    if check_password_hash(stored_hashed_otp, user_otp):
        email = session.pop('otp_email', None)
        session.pop('otp', None)
        session.pop('otp_expiry', None)

        user = User.query.filter_by(email=email).first()
        if user:
            session['user_id'] = user.id  # Store user session
            return jsonify({"success": True, "redirect": url_for('home')}), 200

    return jsonify({"success": False, "message": "Invalid OTP"}), 400

# OTP Verification Page
@app.route('/otp-verification')
def otp_verification():
    return render_template('otp_verification.html')
# Profile picture upload route
@app.route('/upload_profile_pic', methods=['POST'])
def upload_profile_pic():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 403

    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    user = User.query.get(session['user_id'])

    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    if file and allowed_file(file.filename):
        filename = f"user_{user.id}.jpg"  # Save file as user_ID.jpg
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Update database
        user.profile_picture = filename
        db.session.commit()

        return jsonify({"success": "Profile picture updated", "filename": filename})

    return jsonify({"error": "File type not allowed"}), 400

# Serve profile pictures
@app.route('/profile_pictures/<filename>')
def get_profile_picture(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# Home route (index page)
@app.route('/')
def index():
    return render_template('index.html')

# ✅ AJAX Route to Check User Existence (Before Registration)
@app.route('/check-user', methods=['POST'])
def check_user():
    data = request.get_json()
    email = data.get('email')
    phone = data.get('phone')

    email_exists = User.query.filter_by(email=email).first() is not None
    phone_exists = User.query.filter_by(phone=phone).first() is not None

    return jsonify({'email_exists': email_exists, 'phone_exists': phone_exists})

# ✅ Register Route with Uniqueness Check and Session Handling
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match!", 'danger')
            return redirect(url_for('register'))

        # ✅ Check if email or phone already exists
        if User.query.filter_by(email=email).first():
            flash("Email is already registered!", 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(phone=phone).first():
            flash("Phone number is already registered!", 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, email=email, phone=phone, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()

            # ✅ Store user session and redirect to home page
            session['user_id'] = new_user.id
            session['username'] = new_user.username
            session['last_login_time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            flash("Registration successful! Welcome!", 'success')
            return redirect(url_for('home'))  # ✅ Redirects to home instead of login

        except Exception as e:
            flash(f"Error: {e}", 'danger')
            db.session.rollback()
            return redirect(url_for('register'))

    return render_template('register.html')

# ✅ Login Route with Attempt Tracking and Debugging
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'failed_attempts' not in session:
        session['failed_attempts'] = 0  # ✅ Initialize attempts
        session['lockout_time'] = None  # ✅ Initialize lockout time

    # ✅ Check if user is locked out
    if session['failed_attempts'] >= MAX_ATTEMPTS:
        if session['lockout_time']:
            lockout_time = datetime.strptime(session['lockout_time'], "%Y-%m-%d %H:%M:%S")
            if datetime.utcnow() < lockout_time:
                time_left = (lockout_time - datetime.utcnow()).seconds
                return render_template('login.html', lockout_time=time_left, error_message="Too many failed attempts. Try again later.", attempts_left=0)
            else:
                session['failed_attempts'] = 0  # ✅ Reset attempts after lockout ends
                session['lockout_time'] = None

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if not username or not password:
            flash("Username and password are required!", 'danger')
            return redirect(url_for('login'))

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):  # ✅ Correct password
            session['user_id'] = user.id
            session['username'] = user.username
            session['last_login_time'] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

            # ✅ Reset failed attempts on successful login
            session.pop('failed_attempts', None)
            session.pop('lockout_time', None)

            flash("Login successful!", 'success')
            return redirect(url_for('home'))

        # ✅ Track failed attempts
        session['failed_attempts'] += 1
        attempts_left = MAX_ATTEMPTS - session['failed_attempts']

        if session['failed_attempts'] >= MAX_ATTEMPTS:
            session['lockout_time'] = (datetime.utcnow() + timedelta(seconds=LOCKOUT_TIME)).strftime("%Y-%m-%d %H:%M:%S")
            return render_template('login.html', lockout_time=LOCKOUT_TIME, error_message="Too many failed attempts. Try again later.", attempts_left=0)

        flash(f"Invalid username or password! Attempts left: {attempts_left}", 'danger')

        return render_template('login.html', attempts_left=attempts_left, error_message=f"❌ Invalid credentials. {attempts_left} attempts left.")

    # ✅ When refreshing, attempts_left should not be shown
    return render_template('login.html', attempts_left=None)
@app.route('/check_email', methods=['POST'])
def check_email():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({'exists': True}), 200
    return jsonify({'exists': False}), 404

# Forgot password route
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        if not session.get('reset_verified'):
            flash("Please approve password reset from your email!", 'danger')
            return redirect(url_for('forgot_password'))

        email = session.get('reset_email')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        user = User.query.filter_by(email=email).first()
        if not user:
            flash("Email not found!", 'danger')
            return redirect(url_for('forgot_password'))

        if new_password != confirm_new_password:
            flash("Passwords do not match!", 'danger')
            return redirect(url_for('forgot_password'))

        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
        user.password = hashed_password
        db.session.commit()

        session.pop('reset_email', None)
        session.pop('reset_verified', None)

        flash("Password updated successfully! Please log in.", 'success')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')

# Token-based password reset: Send verification email with token
@app.route('/send-verification-email', methods=['POST'])
def send_verification_email():
    data = request.get_json()
    email = data.get('email')
    username = data.get('username')
    
    user = User.query.filter_by(email=email, username=username).first()
    if not user:
        return jsonify({'success': False, 'message': 'Invalid email or username'}), 404

    token = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(hours=1)
    reset_request = PasswordResetRequest(email=email, token=token, expires_at=expires_at)
    db.session.add(reset_request)
    db.session.commit()

    email_body = f"""
    <html>
    <body>
        <p><strong>Do you want to reset your password?</strong></p>
        <a href="http://127.0.0.1:5000/approve-reset?token={token}" style="padding: 10px 20px; background-color: green; color: white; text-decoration: none; border-radius: 5px;">Yes</a>
        <a href="http://127.0.0.1:5000/deny-reset?token={token}" style="padding: 10px 20px; background-color: red; color: white; text-decoration: none; border-radius: 5px;">No</a>
    </body>
    </html>
    """
    
    msg = Message("Password Reset Request", sender=app.config['MAIL_DEFAULT_SENDER'], recipients=[email], html=email_body)
    mail.send(msg)

    return jsonify({'success': True, 'message': 'Verification email sent'}), 200

@app.route('/approve-reset', methods=['GET'])
def approve_reset():
    token = request.args.get('token')
    reset_request = PasswordResetRequest.query.filter_by(token=token).first()
    if not reset_request or reset_request.expires_at < datetime.utcnow():
        return "<p>Invalid or expired token. Try again.</p>"

    reset_request.approved = True
    db.session.commit()
    
    session['reset_verified'] = True
    session['reset_email'] = reset_request.email
    
    return redirect(url_for('forgot_password'))

@app.route('/check-reset-status', methods=['GET'])
def check_reset_status():
    if session.get('reset_verified'):
        return jsonify({'approved': True, 'email': session.get('reset_email')})
    return jsonify({'approved': False})

# Deny reset route using token verification
@app.route('/deny-reset', methods=['GET'])
def deny_reset():
    token = request.args.get('token')
    reset_request = PasswordResetRequest.query.filter_by(token=token).first()
    if reset_request:
        db.session.delete(reset_request)
        db.session.commit()
    flash("Password reset request denied.", "danger")
    return redirect(url_for('forgot_password'))

# Home route (after login)
@app.route('/home')
def home():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    profile_picture = user.profile_picture if user.profile_picture else "default.png"
    
    return render_template('home.html', profile_picture=profile_picture)

# Profile route
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    return render_template('profile.html', user=user)

# Settings route
@app.route('/settings', methods=['GET', 'POST'])
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])  # ✅ Fetch the logged-in user

    theme = request.cookies.get('theme', 'light')
    last_logged_in_user = session.get('username', 'Unknown User')
    last_login_time = session.get('last_login_time', 'No recent login')

    return render_template('settings.html', 
                           theme=theme, 
                           last_user=last_logged_in_user, 
                           last_time=last_login_time,
                           user=user)  # ✅ Pass the `user` variable to the template

@app.route('/delete-account', methods=['POST'])
def delete_account():
    if 'user_id' not in session:
        return jsonify({'error': 'User not authenticated'}), 403

    user = User.query.get(session['user_id'])

    if user:
        try:
            # Delete user's passwords first (to maintain database integrity)
            Password.query.filter_by(user_id=user.id).delete()

            # Delete the user account
            db.session.delete(user)
            db.session.commit()

            session.clear()  # Log out user after deletion
            return jsonify({'success': True})
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': str(e)}), 500
    return jsonify({'error': 'User not found'}), 404

# About route
@app.route('/about')
def about():
    return render_template('about.html')

# Privacy Policy route
@app.route('/privacy-policy')
def privacy_policy():
    return render_template('privacy_policy.html')
@app.route("/feedback")
def feedback():
    return render_template("feedback.html")

@app.route("/send-feedback", methods=["POST"])
def send_feedback():
    if "user_id" not in session:
        return jsonify({"error": "User not logged in"}), 401

    data = request.json
    user_message = data.get("message")

    if not user_message:
        return jsonify({"error": "Message cannot be empty"}), 400

    # Get user's email from the database
    user = User.query.get(session["user_id"])
    if not user:
        return jsonify({"error": "User not found"}), 404

    user_email = user.email  # Fetch registered email from database

    try:
        # Configure Email Message
        subject = "New User Feedback - VaultLocker"
        receiver_email = EMAIL_USER  # The app's official email

        msg = MIMEText(f"Feedback from {user_email}:\n\n{user_message}")
        msg["Subject"] = subject
        msg["From"] = user_email  # Set user email as the sender
        msg["To"] = receiver_email

        # Send Email via SMTP
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(user_email, receiver_email, msg.as_string())

        return jsonify({"success": True})

    except Exception as e:
        return jsonify({"error": str(e)}), 500
# Add password route
@app.route('/add-password', methods=['GET', 'POST'])
def add_password():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        app_name = request.form.get('app_name')
        password = request.form.get('password')

        # Check if the app name already exists for the user
        existing_entry = Password.query.filter_by(app_name=app_name, user_id=session['user_id']).first()
        if existing_entry:
            return jsonify({"status": "error", "message": "This app already has a saved password!"})

        # Encrypt the password before storing
        encrypted_password = cipher_suite.encrypt(password.encode()).decode()

        # Add new password entry with encrypted password
        new_password = Password(user_id=session['user_id'], app_name=app_name, password=encrypted_password)
        db.session.add(new_password)
        db.session.commit()
        
        return jsonify({"status": "success", "message": "Password added successfully!"})

    return render_template('add_password.html')
# Edit password route
@app.route('/edit-password', methods=['GET', 'POST'])
def edit_password():
    if 'user_id' not in session:
        return jsonify({"error": "User not logged in"}), 401  # Return JSON instead of redirecting

    if request.method == 'POST':
        app_name = request.form.get('app_name')
        new_password = request.form.get('password')  # ✅ Fix: Use "password" instead of "new_password"

        # Encrypt the new password before storing
        encrypted_password = cipher_suite.encrypt(new_password.encode()).decode()

        # Find the password entry for the given app
        password_entry = Password.query.filter_by(app_name=app_name, user_id=session['user_id']).first()

        if password_entry:
            password_entry.password = encrypted_password
            db.session.commit()
            return jsonify({"success": "Password updated successfully!"})  # ✅ JSON response for AJAX

        else:
            return jsonify({"error": "No record found"}), 404  # ✅ Return JSON error response

    return render_template('edit_password.html')
# View passwords route
@app.route('/view-passwords')
def view_passwords():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    passwords = Password.query.filter_by(user_id=user.id).all()
    return render_template('view_passwords.html', passwords=passwords)

# Authenticate route
@app.route('/authenticate', methods=['POST'])
def authenticate():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if user and check_password_hash(user.password, password):
        return jsonify({'authenticated': True})
    else:
        return jsonify({'authenticated': False}), 401

# Decrypt a password route
@app.route('/decrypt', methods=['POST'])
def decrypt_password():
    if 'user_id' not in session:
        return jsonify({'error': 'User not authenticated'}), 403
    data = request.get_json()
    encrypted_password = data.get('encrypted_password')
    try:
        decrypted_password = cipher_suite.decrypt(encrypted_password.encode()).decode()
        return jsonify({'decrypted_password': decrypted_password})
    except InvalidToken:
        return jsonify({'error': 'Invalid encryption data'}), 400

# Decrypt all stored passwords route
@app.route('/decrypt-stored-passwords', methods=['GET'])
def decrypt_all_passwords():
    if 'user_id' not in session:
        return jsonify({'error': 'User not authenticated'}), 403
    passwords = Password.query.filter_by(user_id=session['user_id']).all()
    decrypted_data = []
    for password in passwords:
        try:
            decrypted_password = cipher_suite.decrypt(password.password.encode()).decode()
            decrypted_data.append({'app_name': password.app_name, 'decrypted_password': decrypted_password})
        except Exception:
            decrypted_data.append({'app_name': password.app_name, 'error': 'Decryption failed'})
    return jsonify(decrypted_data)

# Delete password route
@app.route('/delete-password/<int:password_id>', methods=['POST'])
def delete_password(password_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    password_to_delete = Password.query.get(password_id)
    if password_to_delete and password_to_delete.user_id == session['user_id']:
        try:
            db.session.delete(password_to_delete)
            db.session.commit()
            flash("Password deleted successfully.", 'success')
        except Exception as e:
            db.session.rollback()
            flash(f"Error: {e}", 'danger')
    else:
        flash("Password not found or unauthorized.", 'danger')
    return redirect(url_for('home'))

# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Logged out successfully!", 'success')
    return redirect(url_for('login'))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Ensure database tables are created

    from waitress import serve  # Use a production WSGI server
    serve(app, host="0.0.0.0", port=5000)
