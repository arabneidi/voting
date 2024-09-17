from flask import Flask, render_template, request, jsonify, session, redirect, url_for, \
    flash  # Import Flask's flash function
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import os
from cryptography.fernet import Fernet
import requests
from twilio.rest import Client
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random
from datetime import datetime, timezone, timedelta
import re  # Import regex module
from blockchain import Blockchain, Block, BlockchainModel
import json
from time import time
import base64
from flask_migrate import Migrate


# reCAPTCHA v3 secret key
RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')  # Replace with your secret key

app = Flask(__name__, template_folder='C:/Users/shexe/PycharmProjects/voting/templates')

app.secret_key = os.urandom(24)

# Initialize the blockchain
voting_blockchain = Blockchain()

# Twilio account credentials
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')

# Initialize Twilio client
twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# Store OTPs for 2FA verification
otp_storage = {}


def send_email(to_email, subject, body):
    sender_email = os.getenv('sender_email')
    sender_password = os.getenv('sender_password')  # Use an app-specific password for security if using Gmail

    # Create the email
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        # Set up the SMTP server
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        text = msg.as_string()

        # Send the email
        server.sendmail(sender_email, to_email, text)
        server.quit()
        print(f"Email sent successfully to {to_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")


# Function to send SMS via Twilio
def send_sms(phone_number, message):
    try:
        twilio_client.messages.create(
            body=message,
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        print(f"SMS sent to {phone_number}")
    except Exception as e:
        print(f"Failed to send SMS: {e}")


# Generate a random 6-digit OTP
def generate_otp():
    return str(random.randint(100000, 999999))


# Configure MySQL database
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Sunny%40shex00@localhost/voting_system'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Session timeout configuration (15 minutes)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Load the encryption key from the secret.key file
def load_encryption_key():
    key_path = os.path.join(os.path.dirname(__file__), 'secret.key')
    return open(key_path, 'rb').read()


encryption_key = load_encryption_key()
cipher_suite = Fernet(encryption_key)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    sex = db.Column(db.String(10), nullable=False)
    national_id = db.Column(db.String(20), unique=True, nullable=False)
    country_code = db.Column(db.String(10), nullable=False)
    phone_number = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    otp = db.Column(db.String(6), nullable=True)  # For SMS verification
    otp_generation_time = db.Column(db.DateTime, nullable=True)  # Add OTP generation time
    phone_verified = db.Column(db.Boolean, default=False)  # Track if phone is verified


class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    candidate_id = db.Column(db.Integer, nullable=False)
    encrypted_vote = db.Column(db.String(500), nullable=False)

    user = db.relationship('User', backref=db.backref('votes', lazy=True))


class Bank(db.Model):
    __tablename__ = 'bank'  # Ensure this matches the table name in your database

    national_id = db.Column(db.String(20), primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    sex = db.Column(db.String(10), nullable=False)
    country_code = db.Column(db.String(10), nullable=False)
    phone_number = db.Column(db.String(15), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    birthdate = db.Column(db.Date, nullable=False)
    is_dead = db.Column(db.Boolean, default=False)  # Boolean to track if the user is deceased


# Create the table in your database
with app.app_context():
    db.create_all()

# reCAPTCHA v3 verification function
def verify_recaptcha_v3(recaptcha_token):
    """Verify the reCAPTCHA v3 token with Google."""
    recaptcha_verify_url = 'https://www.google.com/recaptcha/api/siteverify'
    payload = {
        'secret': RECAPTCHA_SECRET_KEY,
        'response': recaptcha_token
    }

    try:
        response = requests.post(recaptcha_verify_url, data=payload)
        result = response.json()

        # Debugging: Print Google's response for verification
        print(f"reCAPTCHA verification result: {result}")

        return result.get('success', False) and result.get('score', 0) >= 0.5
    except Exception as e:
        print(f"Error during reCAPTCHA verification: {e}")
        return False


@app.route('/send_otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    phone_number = data['phone_number']
    country_code = data['country_code']

    full_phone_number = f"{country_code}{phone_number}"

    if not phone_number:
        return jsonify({'success': False, 'message': 'Phone Number is required.'}), 400

    # Generate OTP
    otp = generate_otp()

    # Send OTP via SMS
    send_sms(full_phone_number, f"Your OTP code is {otp}")

    # Store OTP and generation time in session
    session['otp'] = otp
    # Store OTP generation time with timezone-aware datetime
    session['otp_generation_time'] = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S%z')

    return jsonify({"success": True, 'message': 'OTP sent successfully to Phone.'})


@app.route('/send_otp_email', methods=['POST'])
def send_otp_email():
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({'success': False, 'message': 'Email is required.'}), 400

    # Generate OTP and send it via email
    otp = generate_otp()

    try:
        send_email(email, "Your OTP Code", f"Your OTP is: {otp}")
        session['otp'] = otp  # Store OTP in the session

        # Store OTP generation time with timezone-aware datetime
        session['otp_generation_time'] = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S%z')

        return jsonify({'success': True, 'message': 'OTP sent successfully to email.'})
    except Exception as e:
        print(f"Error sending OTP email: {e}")
        return jsonify({'success': False, 'message': 'Failed to send OTP.'}), 500


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get the form details

        first_name = request.form['first_name']
        last_name = request.form['last_name']
        sex = request.form['sex']
        national_id = request.form['national_id']
        country_code = request.form['country_code']
        phone_number = request.form['phone_number']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        entered_otp = request.form['otp']
        recaptcha_token = request.form.get('recaptchaToken')

        # Validate reCAPTCHA
        if not verify_recaptcha_v3(recaptcha_token):
            flash("reCAPTCHA verification failed. Please try again.", "danger")
            return render_template('register.html', request=request)

        # Validate email format
        if not validate_email_format(email):
            flash("Invalid email format.", "danger")
            return render_template('register.html', request=request)

        # Validate National ID length
        if len(national_id) != 10:
            flash("National ID must be exactly 10 digits.", "danger")
            return render_template('register.html', request=request)

        # Check if email already exists
        if User.query.filter_by(email=email).first():
            flash("Email is already registered.", "danger")
            return render_template('register.html', request=request)

        # Check if phone number is already registered
        if User.query.filter_by(phone_number=phone_number).first():
            flash("Phone number is already registered.", "danger")
            return render_template('register.html', request=request)

        # Check if national ID is already registered
        if User.query.filter_by(national_id=national_id).first():
            flash("National ID is already registered.", "danger")
            return render_template('register.html', request=request)

        # Check if passwords match
        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return render_template('register.html', request=request)

        # Check password strength
        if len(password) < 8 or not any(char.isdigit() for char in password) or not any(
                char.isupper() for char in password):
            flash("Password must be at least 8 characters long, contain an uppercase letter, and a number.", "danger")
            return render_template('register.html', request=request)

            # Check if national_id exists in the bank table
        bank_record = db.session.query(Bank).filter_by(national_id=national_id).first()

        if not bank_record:
            flash("Your information is not correct.", "danger")
            return render_template('register.html', request=request)

        # Verify that other details match the national_id in the bank
        if (bank_record.first_name != first_name or bank_record.last_name != last_name or
                bank_record.sex != sex or bank_record.email != email):
            flash("Your information is not correct.", "danger")
            return render_template('register.html', request=request)

        # Check if the user is dead
        if bank_record.is_dead:
            flash("You are not allowed to vote. [More Information](#)", "danger")
            return render_template('register.html', request=request)

        # Verify the user is older than 21
        today = datetime.today()
        age = today.year - bank_record.birthdate.year - (
                (today.month, today.day) < (bank_record.birthdate.month, bank_record.birthdate.day))

        if age < 21:
            flash("You must be at least 21 years old to register and vote.", "danger")
            return render_template('register.html', request=request)

        # Hash the password
        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Validate OTP
        if 'otp' not in session or 'otp_generation_time' not in session:
            return "OTP not found. Please request a new one.", 400

        if entered_otp != session['otp']:
            flash("code is not correct.", "danger")
            return render_template('register.html', request=request)

        # Check OTP expiry (2 minutes)
        otp_generation_time = datetime.strptime(session['otp_generation_time'], '%Y-%m-%d %H:%M:%S%z')

        # Use datetime.now(timezone.utc) to get current time in UTC
        if datetime.now(timezone.utc) - otp_generation_time > timedelta(minutes=2):
            return "OTP has expired. Please request a new one.", 400

        # Create a new user instance
        new_user = User(first_name=first_name, last_name=last_name, sex=sex,
                        national_id=national_id, country_code=country_code, phone_number=phone_number,
                        email=email, password=hashed_pw, phone_verified=True)

        # Save the new user in the database
        db.session.add(new_user)
        db.session.commit()

        # Clear OTP from session after successful registration
        session.pop('otp', None)
        session.pop('otp_generation_time', None)

        # Redirect to login after successful registration
        return redirect(url_for('login_page'))

    return render_template('register.html')


def validate_email_format(email):
    """Validate email format using regex."""
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None


def verify_otp(phone_number, otp):
    otp_data = otp_storage.get(phone_number)

    if otp_data and otp_data['otp'] == otp:
        # Check if the OTP is within the valid 2-minute window

        # Check OTP expiry (2 minutes)
        otp_generation_time = datetime.strptime(session['otp_generation_time'], '%Y-%m-%d %H:%M:%S%z')

        # Use datetime.now(timezone.utc) to get current time in UTC
        if datetime.now(timezone.utc) - otp_generation_time > timedelta(minutes=2):
            return True
    return False


def is_otp_valid(user):
    # Check if OTP was generated within the last 2 minutes
    # Check OTP expiry (2 minutes)
    otp_generation_time = datetime.strptime(session['otp_generation_time'], '%Y-%m-%d %H:%M:%S%z')

    # Use datetime.now(timezone.utc) to get current time in UTC
    if user.opt_generation_time and datetime.now(timezone.utc) - otp_generation_time > timedelta(minutes=2):
        return True
    return False


@app.route('/verify_phone_number/<int:user_id>', methods=['GET', 'POST'])
def verify_phone_number(user_id):
    user = User.query.get(user_id)
    if not user:
        return "User not found."

    if request.method == 'POST':
        otp = request.form['otp']
        if user.otp == otp and is_otp_valid(user):
            user.phone_verified = True
            db.session.commit()
            return redirect(url_for('login_page'))
        else:
            return "Invalid OTP. Please try again."

    return render_template('verify_phone.html', user_id=user_id)


# Route to serve the voting page
@app.route('/voting')
def voting_page():
    if 'logged_in' not in session:
        return redirect(url_for('login_page'))
    return render_template('voting.html')


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        password = request.form['password'].encode('utf-8')
        recaptcha_token = request.form.get('recaptchaToken')

        print(f"reCAPTCHA token received: {recaptcha_token}")

        # Verify the reCAPTCHA token
        if not verify_recaptcha_v3(recaptcha_token):
            return "reCAPTCHA verification failed. Please try again."

        # Look for a user with matching first name, last name, and password
        user = User.query.filter_by(first_name=first_name, last_name=last_name).first()

        if user and bcrypt.checkpw(password, user.password.encode('utf-8')):
            # Set the session and redirect to home page
            session['logged_in'] = True
            session['user_id'] = user.id
            return redirect(url_for('home_page'))
        else:
            return "Invalid login credentials."

    return render_template('login.html')


# Home page after login
@app.route('/home')
def home_page():
    if 'logged_in' not in session:
        return redirect(url_for('login_page'))

    user_id = session['user_id']
    has_voted = Vote.query.filter_by(user_id=user_id).first() is not None
    return render_template('home.html', has_voted=has_voted)


@app.route('/cast_vote', methods=['POST'])
def cast_vote():
    if 'logged_in' not in session:
        return jsonify({"message": "User not logged in"}), 401  # Return proper error if not logged in

    user_id = session['user_id']
    user = db.session.get(User, user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404  # Handle case if user is not found

    # Check if the user has already voted
    existing_vote = Vote.query.filter_by(user_id=user_id).first()
    if existing_vote:
        return jsonify({"message": "You have already voted!"}), 400

    # Get candidate_id from the request data
    data = request.get_json()
    candidate_id = data.get('candidate_id')

    if not candidate_id:
        return jsonify({"message": "No candidate selected"}), 400  # Handle missing candidate selection

    # Encrypt the vote before storing it
    encrypted_vote = encrypt_vote(candidate_id)

    # Create a new block for the vote and add it to the blockchain
    new_block = Block(len(voting_blockchain.chain), time(), {
        'user_id': user_id,
        'candidate_id': candidate_id,
        'encrypted_vote': encrypted_vote
    }, voting_blockchain.get_latest_block().hash)

    voting_blockchain.add_block(new_block)

    # Save the block data to the blockchain table
    block_data = {
        'block_index': new_block.index,
        'timestamp': datetime.fromtimestamp(new_block.timestamp),  # Convert UNIX time to MySQL datetime format
        'user_id': new_block.data['user_id'],
        'candidate_id': new_block.data['candidate_id'],
        'encrypted_vote': new_block.data['encrypted_vote'],
        'previous_hash': new_block.previous_hash,
        'block_hash': new_block.hash
    }

    # Insert the block into the blockchain table
    blockchain_entry = BlockchainModel(
        block_index=block_data['block_index'],
        timestamp=block_data['timestamp'],
        user_id=block_data['user_id'],
        candidate_id=block_data['candidate_id'],
        encrypted_vote=block_data['encrypted_vote'],
        previous_hash=block_data['previous_hash'],
        block_hash=block_data['block_hash']
    )

    db.session.add(blockchain_entry)
    db.session.commit()  # Commit the blockchain record to the blockchain table

    # Store the vote in the database
    vote = Vote(user_id=user_id, candidate_id=candidate_id, encrypted_vote=encrypted_vote)
    db.session.add(vote)
    db.session.commit()

    # Send vote confirmation email
    send_email(user.email, "Vote Confirmation",
               f"Thank you for voting! You voted for candidate {candidate_id}.")  # Use email
    return jsonify({"message": "Vote cast successfully!"})


# Route to serve the audit page
@app.route('/audit')
def audit_page():
    if 'logged_in' not in session:
        return redirect(url_for('login_page'))
    return render_template('audit.html')


@app.route('/audit_results', methods=['GET'])
def audit_results():
    if 'logged_in' not in session:
        return redirect(url_for('login_page'))

    user_id = session['user_id']  # Get the current logged-in user's ID

    # Retrieve only the votes for the logged-in user
    user_votes = Vote.query.filter_by(user_id=user_id).all()

    # Decrypt the user's votes
    decrypted_votes = [{'user_id': vote.user_id, 'candidate_id': decrypt_vote(vote.encrypted_vote)} for vote in
                       user_votes]

    return jsonify({"votes": decrypted_votes})


@app.route('/verify_blockchain', methods=['GET'])
def verify_blockchain():
    if voting_blockchain.is_chain_valid():
        return jsonify({"message": "Blockchain is valid."})
    else:
        return jsonify({"message": "Blockchain integrity compromised."}), 400

@app.route('/save_blockchain', methods=['POST'])
def save_blockchain():
    blockchain_state = json.dumps([block.__dict__ for block in voting_blockchain.chain])
    # Store the blockchain in the database
    query = "INSERT INTO blockchain (chain) VALUES (%s)"
    db.session.execute(query, (blockchain_state,))
    db.session.commit()
    return jsonify({"message": "Blockchain saved successfully!"})

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        national_id = request.form['national_id']
        phone_number = request.form.get('phone_number', '')
        email = request.form.get('email', '')
        otp = request.form['otp']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        recaptcha_token = request.form.get('recaptchaToken')

        # Verify the reCAPTCHA token
        if not verify_recaptcha_v3(recaptcha_token):
            return render_template('reset_password.html', error="reCAPTCHA verification failed. Please try again.",
                                   first_name=first_name, last_name=last_name, national_id=national_id,
                                   phone_number=phone_number, email=email)

        # Verify that at least one of phone or email is provided
        if not phone_number and not email:
            return render_template('reset_password.html', error="Please enter either phone number or email.",
                                   first_name=first_name, last_name=last_name, national_id=national_id)

        # Fetch user based on personal details
        user = User.query.filter_by(first_name=first_name, last_name=last_name, national_id=national_id).first()
        if not user:
            return render_template('reset_password.html', error="User not found. Please check your details.",
                                   first_name=first_name, last_name=last_name, national_id=national_id,
                                   phone_number=phone_number, email=email)

        # Validate OTP
        otp_verified = verify_otp1(otp) if phone_number else verify_email_otp(otp)
        if not otp_verified:
            return render_template('reset_password.html', error="Invalid or expired OTP. Please try again.",
                                   first_name=first_name, last_name=last_name, national_id=national_id)

        # Verify that passwords match
        if new_password != confirm_password:
            return render_template('reset_password.html', error="Passwords do not match.",
                                   first_name=first_name, last_name=last_name, national_id=national_id)

        # Basic password strength validation
        if len(new_password) < 8 or not any(c.isdigit() for c in new_password) or not any(c.isalpha() for c in new_password):
            return render_template('reset_password.html', error="Password must be at least 8 characters and contain both letters and numbers.",
                                   first_name=first_name, last_name=last_name, national_id=national_id)

        # Update password
        hashed_pw = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
        user.password = hashed_pw
        db.session.commit()

        return redirect(url_for('login_page'))

    return render_template('reset_password.html')



@app.route('/send_reset_otp', methods=['POST'])
def send_reset_otp():
    data = request.get_json()
    phone_number = data.get('phone_number', '')
    email = data.get('email', '')
    national_id = data['national_id']
    country_code = data['country_code']

    full_phone_number = f"{country_code}{phone_number}"

    # Verify user's existence in the database
    user = User.query.filter_by(national_id=national_id).first()
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 400

    # Send OTP via phone or email based on user input
    otp = generate_otp()
    session['otp'] = otp
    session['otp_generation_time'] = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S%z')

    if full_phone_number:
        send_sms(full_phone_number, f"Your OTP code is {otp}")
    elif email:
        send_email(email, "Your OTP Code", f"Your OTP code is {otp}")

    return jsonify({"success": True, "message": "OTP sent successfully"}), 200


def verify_otp1(otp):
    # Verify OTP sent to phone
    if session.get('otp') == otp:
        otp_generation_time = datetime.strptime(session.get('otp_generation_time'), '%Y-%m-%d %H:%M:%S%z')

        # Check OTP expiry (2 minutes)
        # otp_generation_time = datetime.strptime(session['otp_generation_time'], '%Y-%m-%d %H:%M:%S%z').replace(
        #     tzinfo=timezone.utc)

        # Use datetime.now(timezone.utc) to get current time in UTC
        if datetime.now(timezone.utc) - otp_generation_time > timedelta(minutes=2):
            return False  # OTP expired
        return True
    return False

def verify_email_otp(otp):
    # Similar to verify_otp, but this handles OTP verification for emails
    print("OTP entered:", otp)
    stored_otp = session.get('otp')
    stored_otp_generation_time = session.get('otp_generation_time')

    # Ensure OTP and generation time exist
    if stored_otp and stored_otp == otp and stored_otp_generation_time:
        # Parse the stored OTP generation time with timezone awareness
        otp_generation_time = datetime.strptime(stored_otp_generation_time, '%Y-%m-%d %H:%M:%S%z')

        print("OTP Generation Time:", otp_generation_time)
        # Check if the OTP is still valid (within 2 minutes)
        if datetime.now(timezone.utc) - otp_generation_time > timedelta(minutes=2):
            return False  # OTP expired
        return True
    return False


# Logout route to clear the session and redirect to log in
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))


def encrypt_vote(vote):
    vote_bytes = str(vote).encode('utf-8')
    encrypted_vote = cipher_suite.encrypt(vote_bytes)
    # Convert encrypted bytes to base64-encoded string for JSON serialization
    return base64.b64encode(encrypted_vote).decode('utf-8')

def decrypt_vote(encrypted_vote):
    # Decode base64 to bytes before decryption
    encrypted_vote_bytes = base64.b64decode(encrypted_vote)
    decrypted_vote = cipher_suite.decrypt(encrypted_vote_bytes).decode('utf-8')
    return decrypted_vote


if __name__ == "__main__":
    app.run(debug=True)
