from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MySQL connection
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:xumToVVeixNAlLaKmPPXVmpgffaoMGlD@centerbeam.proxy.rlwy.net:48103/railway'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # super_admin, admin, user

# Routes
@app.route('/')
def index():
    if 'user' in session:
        user = User.query.filter_by(username=session['user']).first()
        return render_template('dashboard.html', user=user)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            session['user'] = user.username
            return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return '❌ Username already exists'
        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/db-check')
def db_check():
    try:
        db.session.execute(text('SELECT 1'))
        return '✅ Connected to MySQL successfully!'
    except Exception as e:
        return f'❌ Database connection failed: {e}'

@app.route('/create-test-users')
def create_test_users():
    db.session.query(User).delete()
    users = [
        User(username='superadmin', password='123', role='super_admin'),
        User(username='admin', password='123', role='admin'),
        User(username='user', password='123', role='user'),
    ]
    db.session.add_all(users)
    db.session.commit()
    return "✅ Test users created: superadmin, admin, user (password: 123)"

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = User.query.filter_by(username=session['user']).first()
    if user.role == 'super_admin':
        return f"🔐 Super Admin Dashboard for {user.username}"
    elif user.role == 'admin':
        return f"🔧 Admin Dashboard for {user.username}"
    elif user.role == 'user':
        return f"👤 User Dashboard for {user.username}"
    return "❌ Unknown role"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("✅ Tables created or already exist")

    app.run(debug=True)
