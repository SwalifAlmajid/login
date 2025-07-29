from sqlalchemy import Sequence
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

# Role-specific tables

class SuperAdmin(db.Model):
    __tablename__ = 'superadmin'
    id = db.Column(db.Integer, Sequence('superadmin_id_seq'), primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Admin(db.Model):
    __tablename__ = 'admin'
    id = db.Column(db.Integer, Sequence('admin_id_seq'), primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Trainee(db.Model):
    __tablename__ = 'trainee'
    id = db.Column(db.Integer, Sequence('trainee_id_seq'), primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)


@app.route('/')
def index():
    if 'user' in session and 'role' in session:
        role = session['role']
        return redirect(url_for(f'{role}_home'))
    return redirect(url_for('login'))
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        role = request.form['role']

        # Check if username already exists in any table
        exists = (
            SuperAdmin.query.filter_by(username=username).first() or
            Admin.query.filter_by(username=username).first() or
            Trainee.query.filter_by(username=username).first()
        )
        if exists:
            error = "❌ Username already exists"
            return render_template('signup.html', error=error)

        # Add to the correct role table
        if role == 'superadmin':
            user = SuperAdmin(username=username, password=password)
        elif role == 'admin':
            user = Admin(username=username, password=password)
        elif role == 'trainee':
            user = Trainee(username=username, password=password)
        else:
            error = "❌ Invalid role selected"
            return render_template('signup.html', error=error)

        db.session.add(user)
        db.session.commit()

        # Auto-login after signup
        session['user'] = user.username
        session['role'] = role
        return redirect(url_for(f'{role}_home'))

    return render_template('signup.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        # Check SuperAdmin
        user = SuperAdmin.query.filter_by(username=username, password=password).first()
        if user:
            session['user'] = user.username
            session['role'] = 'superadmin'
            return redirect(url_for('superadmin_home'))

        # Check Admin
        user = Admin.query.filter_by(username=username, password=password).first()
        if user:
            session['user'] = user.username
            session['role'] = 'admin'
            return redirect(url_for('admin_home'))

        # Check Trainee
        user = Trainee.query.filter_by(username=username, password=password).first()
        if user:
            session['user'] = user.username
            session['role'] = 'trainee'
            return redirect(url_for('trainee_home'))

        error = "Invalid username or password"

    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('role', None)
    return redirect(url_for('login'))

@app.route('/superadmin-home')
def superadmin_home():
    if session.get('role') == 'superadmin':
        user = SuperAdmin.query.filter_by(username=session['user']).first()
        return render_template('super_admin_home.html', user=user)
    return redirect(url_for('login'))

@app.route('/admin-home')
def admin_home():
    if session.get('role') == 'admin':
        user = Admin.query.filter_by(username=session['user']).first()
        trainees = Trainee.query.all()
        return render_template('admin_home.html', user=user, trainees=trainees)
    return redirect(url_for('login'))

@app.route('/trainee-home')
def trainee_home():
    if session.get('role') == 'trainee':
        user = Trainee.query.filter_by(username=session['user']).first()
        return render_template('trainee_home.html', user=user)
    return redirect(url_for('login'))

@app.route('/create-test-users')
def create_test_users():
    db.session.query(SuperAdmin).delete()
    db.session.query(Admin).delete()
    db.session.query(Trainee).delete()
    db.session.add(SuperAdmin(username='superadmin', password='123'))
    db.session.add(Admin(username='admin', password='123'))
    db.session.add(Trainee(username='user', password='123'))
    db.session.commit()
    return "✅ Test users created"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("✅ Tables created or already exist")

    app.run(debug=True)
