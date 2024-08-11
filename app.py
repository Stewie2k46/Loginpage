from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# Updated to use the environment variable for the database URI
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'mysql+pymysql://admin:qwertyuiop@my-flask-db.ct8686g6i2km.us-west-2.rds.amazonaws.com/my-flask-db')

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

class UserDetails(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    first_name = db.Column(db.String(150))
    last_name = db.Column(db.String(150))
    dob = db.Column(db.String(150))
    gender = db.Column(db.String(150))
    age = db.Column(db.Integer)
    address = db.Column(db.String(300))
    contact_number = db.Column(db.String(150))
    email = db.Column(db.String(150))
    emergency_contact_name = db.Column(db.String(150))
    emergency_contact_number = db.Column(db.String(150))
    primary_care_physician = db.Column(db.String(150))
    insurance_provider = db.Column(db.String(150))
    insurance_policy_number = db.Column(db.String(150))
    known_allergies = db.Column(db.String(150))
    current_medications = db.Column(db.String(150))
    medical_history = db.Column(db.String(150))
    reason_for_visit = db.Column(db.String(150))
    date_of_visit = db.Column(db.String(150))
    signature = db.Column(db.String(150))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return redirect(url_for('register'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        # Check if the username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'danger')
            return redirect(url_for('register'))

        # If the username is unique, proceed with registration
        hashed_password = generate_password_hash(password)
        user = User(username=username, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        return redirect(url_for('home'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')

@app.route('/home')
@login_required
def home():
    try:
        response = requests.get('https://example.com/api/who/notices')
        response.raise_for_status()  # Raises an HTTPError for bad responses
        who_notices = response.json()  # Try to parse JSON
    except requests.exceptions.HTTPError as http_err:
        flash(f'HTTP error occurred: {http_err}', 'danger')
        who_notices = []
    except requests.exceptions.RequestException as req_err:
        flash(f'Request error occurred: {req_err}', 'danger')
        who_notices = []
    except requests.exceptions.JSONDecodeError:
        flash('Failed to decode JSON response', 'danger')
        who_notices = []
    
    return render_template('home.html', notices=who_notices)

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        details = UserDetails(
            user_id=current_user.id,
            first_name=request.form.get('first_name'),
            last_name=request.form.get('last_name'),
            dob=request.form.get('dob'),
            gender=request.form.get('gender'),
            age=request.form.get('age'),
            address=request.form.get('address'),
            contact_number=request.form.get('contact_number'),
            email=request.form.get('email'),
            emergency_contact_name=request.form.get('emergency_contact_name'),
            emergency_contact_number=request.form.get('emergency_contact_number'),
            primary_care_physician=request.form.get('primary_care_physician'),
            insurance_provider=request.form.get('insurance_provider'),
            insurance_policy_number=request.form.get('insurance_policy_number'),
            known_allergies=request.form.get('known_allergies'),
            current_medications=request.form.get('current_medications'),
            medical_history=request.form.get('medical_history'),
            reason_for_visit=request.form.get('reason_for_visit'),
            date_of_visit=request.form.get('date_of_visit'),
            signature=request.form.get('signature')
        )
        db.session.add(details)
        db.session.commit()
        flash('Saved details successfully', 'success')
        return redirect(url_for('profile'))
    return render_template('dashboard.html')

@app.route('/profile')
@login_required
def profile():
    user_details = UserDetails.query.filter_by(user_id=current_user.id).first()
    return render_template('profile.html', details=user_details)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
