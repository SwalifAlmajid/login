from flask import Flask, render_template, request, redirect, url_for, session, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text, Sequence
from werkzeug.utils import secure_filename
import os
import io

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# DB Config
username = 'SYSTEM'
password = '2002'
host = 'localhost'
port = '1521'
service = 'XEPDB1'

app.config['SQLALCHEMY_DATABASE_URI'] = f'oracle+oracledb://{username}:{password}@{host}:{port}/?service_name={service}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User tables
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
    email = db.Column(db.String(120))        # ✅ must exist
    phone = db.Column(db.String(20))         # ✅ must exist
    university = db.Column(db.String(100))   # ✅ must exist


# Modified Report model with FILE_DATA BLOB column
class Report(db.Model):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, Sequence('report_id_seq'), primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_data = db.Column(db.LargeBinary, nullable=False)  # store file binary data
    trainee_id = db.Column(db.Integer, db.ForeignKey('trainee.id'), nullable=False)

# Home redirect logic (unchanged)
@app.route('/')
def index():
    if 'user' in session and 'role' in session:
        return redirect(url_for(f"{session['role']}_home"))
    return redirect(url_for('login'))

# Signup logic (unchanged)
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        role = request.form['role']

        exists = (
            SuperAdmin.query.filter_by(username=username).first() or
            Admin.query.filter_by(username=username).first() or
            Trainee.query.filter_by(username=username).first()
        )

        if exists:
            error = "❌ Username already exists"
            return render_template('signup.html', error=error)

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

        session['user'] = user.username
        session['role'] = role
        return redirect(url_for(f'{role}_home'))

    return render_template('signup.html', error=error)

# Login logic (unchanged)
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        user = SuperAdmin.query.filter_by(username=username, password=password).first()
        if user:
            session['user'] = user.username
            session['role'] = 'superadmin'
            return redirect(url_for('superadmin_home'))

        user = Admin.query.filter_by(username=username, password=password).first()
        if user:
            session['user'] = user.username
            session['role'] = 'admin'
            return redirect(url_for('admin_home'))

        user = Trainee.query.filter_by(username=username, password=password).first()
        if user:
            session['user'] = user.username
            session['role'] = 'trainee'
            return redirect(url_for('trainee_home'))

        error = "Invalid username or password"
    return render_template('login.html', error=error)

# Logout (unchanged)
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# SuperAdmin home (unchanged)
@app.route('/superadmin-home')
def superadmin_home():
    if session.get('role') == 'superadmin':
        user = SuperAdmin.query.filter_by(username=session['user']).first()
        return render_template('super_admin_home.html', user=user)
    return redirect(url_for('login'))

# Admin home (unchanged)
@app.route('/admin-home')
def admin_home():
    if session.get('role') == 'admin':
        user = Admin.query.filter_by(username=session['user']).first()
        trainees = Trainee.query.all()
        return render_template('admin_home.html', user=user, trainees=trainees)
    return redirect(url_for('login'))

# Trainee home with report list (pass reports to template)
@app.route('/trainee-home')
def trainee_home():
    if session.get('role') == 'trainee':
        user = Trainee.query.filter_by(username=session['user']).first()
        reports = Report.query.filter_by(trainee_id=user.id).all()
        return render_template('trainee_home.html', user=user, reports=reports)
    return redirect(url_for('login'))

# Submit report route - saves file into database as BLOB
@app.route('/submit-report', methods=['POST'])
def submit_report():
    if session.get('role') != 'trainee':
        return redirect(url_for('login'))

    trainee = Trainee.query.filter_by(username=session['user']).first()
    title = request.form['reportTitle']
    file = request.files['reportFile']

    if file and title:
        filename = secure_filename(file.filename)
        file_data = file.read()  # read file bytes

        report = Report(title=title, filename=filename, file_data=file_data, trainee_id=trainee.id)
        db.session.add(report)
        db.session.commit()
        return redirect(url_for('trainee_home'))

    return "Missing title or file", 400

# Download report file route
@app.route('/download_report/<int:report_id>')
def download_report(report_id):
    report = Report.query.get(report_id)
    if not report or not report.file_data:
        abort(404)

    return send_file(
        io.BytesIO(report.file_data),
        mimetype='application/octet-stream',
        as_attachment=True,
        download_name=report.filename
    )

# Create test users (unchanged)
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

@app.route('/update-profile', methods=['POST'])
def update_profile():
    if 'user' not in session or session['role'] != 'trainee':
        return redirect(url_for('login'))

    trainee = Trainee.query.filter_by(username=session['user']).first()
    trainee.email = request.form.get('email')
    trainee.phone = request.form.get('phone')
    trainee.university = request.form.get('university')

    db.session.commit()
    return redirect(url_for('trainee_home'))


@app.route('/admin/trainee-info/<int:trainee_id>')
def get_trainee_info(trainee_id):
    trainee = Trainee.query.get_or_404(trainee_id)
    reports = Report.query.filter_by(trainee_id=trainee.id).all()

    return {
        "username": trainee.username,
        "email": trainee.email,
        "phone": trainee.phone,
        "university": trainee.university,
        "reports": [
            {"id": r.id, "title": r.title, "filename": r.filename}
            for r in reports
        ]
    }

# Run app
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("✅ Tables created or already exist")
    app.run(debug=True)
