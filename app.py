from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text

app = Flask(__name__)
app.secret_key = 'your_secret_key'

username = 'SYSTEM'
password = '2002'
host = 'localhost'
port = '1521'
service = 'XEPDB1'

app.config['SQLALCHEMY_DATABASE_URI'] = f'oracle+oracledb://{username}:{password}@{host}:{port}/?service_name={service}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(50), nullable=False)  # super_admin, admin, user

def redirect_based_on_role(user):
    print(f"[DEBUG] Redirecting {user.username} with role {user.role}")
    role = user.role.lower()
    if role == 'super_admin':
        return redirect(url_for('super_admin_home'))
    elif role == 'admin':
        return redirect(url_for('admin_home'))
    elif role == 'user':
        return redirect(url_for('trainee_home'))
    else:
        return "❌ Unknown role", 403

@app.route('/create-test-users')
def create_test_users():
    db.session.query(User).delete()
    users = [
        User(username='superadmin', password='123', role='super_admin'),
        User(username='admin', password='123', role='admin'),
        User(username='user', password='123', role='user'),
        User(username='swalif', password='888', role='user'),
        User(username='sw', password='888', role='user'),
    ]
    db.session.add_all(users)
    db.session.commit()
    return "✅ Test users created: superadmin, admin, user, swalif (passwords: 123 or 888)"

@app.route('/')
def index():
    if 'user' in session:
        user = User.query.filter(User.username.ilike(session['user'])).first()
        if user:
            print(f"[DEBUG] User in session: {user.username}, Role: {user.role}")
            return redirect_based_on_role(user)
        else:
            session.pop('user', None)
            return redirect(url_for('login'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        print(f"[DEBUG] Trying login with username: '{username}', password: '{password}'")
        user = User.query.filter(
            User.username.ilike(username),
            User.password == password
        ).first()
        if user:
            print(f"[DEBUG] User found: {user.username} with role {user.role}")
            session['user'] = user.username
            return redirect_based_on_role(user)
        else:
            print("[DEBUG] Login failed: user not found or wrong password")
            error = "Invalid username or password"
    return render_template('login.html', error=error)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        role = request.form['role']
        existing_user = User.query.filter(User.username.ilike(username)).first()
        if existing_user:
            error = '❌ Username already exists'
            return render_template('signup.html', error=error)
        new_user = User(username=username, password=password, role=role)
        db.session.add(new_user)
        db.session.commit()
        session['user'] = new_user.username
        return redirect_based_on_role(new_user)
    return render_template('signup.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('login'))

@app.route('/super-admin-home')
def super_admin_home():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = User.query.filter(User.username.ilike(session['user'])).first()
    if user and user.role.lower() == 'super_admin':
        # Fetch admins and users for deletion listing (example)
        admins = User.query.filter(User.role.ilike('admin')).all()
        users = User.query.filter(User.role.ilike('user')).all()
        return render_template('super_admin_home.html', user=user, admins=admins, users=users)
    return redirect(url_for('login'))

@app.route('/admin-home')
def admin_home():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = User.query.filter(User.username.ilike(session['user'])).first()
    if user and user.role.lower() == 'admin':
        trainees = User.query.filter(User.role.ilike('user')).all()
        # For demonstration, add a placeholder for reports if needed
        return render_template('admin_home.html', user=user, trainees=trainees)
    return redirect(url_for('login'))

@app.route('/trainee-home')
def trainee_home():
    if 'user' not in session:
        return redirect(url_for('login'))
    user = User.query.filter(User.username.ilike(session['user'])).first()
    if user and user.role.lower() == 'user':
        return render_template('trainee_home.html', user=user)
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("✅ Tables created or already exist")

    app.run(debug=True)
