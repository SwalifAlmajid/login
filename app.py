from flask import Flask, render_template, request, redirect, url_for, session, send_file, abort, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Sequence
from datetime import datetime, date
from werkzeug.utils import secure_filename
import io

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.context_processor
def inject_now():
    from datetime import datetime
    return {'now': datetime.utcnow}

# Database Config
username = 'SYSTEM'
password = '2002'
host = 'localhost'
port = '1521'
service = 'XEPDB1'
app.config['SQLALCHEMY_DATABASE_URI'] = f'oracle+oracledb://{username}:{password}@{host}:{port}/?service_name={service}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Models
class SuperAdmin(db.Model):
    __tablename__ = 'superadmin'
    id = db.Column(db.Integer, Sequence('superadmin_id_seq'), primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Department(db.Model):
    __tablename__ = 'departments'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

    admin = db.relationship('Admin', back_populates='department', uselist=False)
    trainees = db.relationship('Trainee', back_populates='department')
    course_guides = db.relationship('CourseGuide', back_populates='department')

class Admin(db.Model):
    __tablename__ = 'admin'
    id = db.Column(db.Integer, Sequence('admin_id_seq'), primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'))
    department = db.relationship('Department', back_populates='admin')

class Trainee(db.Model):
    __tablename__ = 'trainee'
    id = db.Column(db.Integer, Sequence('trainee_id_seq'), primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    university = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'))
    department = db.relationship('Department', back_populates='trainees')

class Report(db.Model):
    __tablename__ = 'reports'
    id = db.Column(db.Integer, Sequence('report_id_seq'), primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_data = db.Column(db.LargeBinary, nullable=False)
    trainee_id = db.Column(db.Integer, db.ForeignKey('trainee.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    trainee = db.relationship('Trainee', backref='reports')

class CourseGuide(db.Model):
    __tablename__ = 'course_guides'
    id = db.Column(db.Integer, Sequence('course_guide_id_seq'), primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_data = db.Column(db.LargeBinary, nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    department_id = db.Column(db.Integer, db.ForeignKey('departments.id'), nullable=False)
    department = db.relationship('Department', back_populates='course_guides')

# Routes
@app.route('/')
def index():
    if 'user' in session and 'role' in session:
        return redirect(url_for(f"{session['role']}_home"))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    departments = Department.query.all()
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        role = request.form['role']
        dept_id = request.form.get('department')

        if not dept_id:
            error = "Department is required"
            return render_template('signup.html', error=error, departments=departments)

        exists = (
            SuperAdmin.query.filter_by(username=username).first() or
            Admin.query.filter_by(username=username).first() or
            Trainee.query.filter_by(username=username).first()
        )

        if exists:
            error = "❌ Username already exists"
        else:
            if role == 'admin':
                user = Admin(username=username, password=password, department_id=dept_id)
            elif role == 'trainee':
                user = Trainee(username=username, password=password, department_id=dept_id)
            else:
                error = "❌ Invalid role selected"
                return render_template('signup.html', error=error, departments=departments)

            db.session.add(user)
            db.session.commit()
            session['user'] = user.username
            session['role'] = role
            return redirect(url_for(f'{role}_home'))

    return render_template('signup.html', error=error, departments=departments)

@app.route('/create-admin', methods=['GET', 'POST'])
def create_admin():
    if session.get('role') != 'superadmin':
        return redirect(url_for('login'))

    departments = Department.query.all()
    error = None

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        department_id = request.form.get('department')

        if Admin.query.filter_by(username=username).first():
            error = "Admin username already exists"
        else:
            new_admin = Admin(username=username, password=password, department_id=department_id)
            db.session.add(new_admin)
            db.session.commit()
            flash("Admin created successfully.", "success")
            return redirect(url_for('superadmin_home'))

    return render_template('create_admin.html', departments=departments, error=error)

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

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/superadmin-home')
def superadmin_home():
    if session.get('role') != 'superadmin' or 'user' not in session:
        return redirect(url_for('login'))

    user = SuperAdmin.query.filter_by(username=session['user']).first()
    search_query = request.args.get('search', '')

    admins = Admin.query.filter(Admin.username.ilike(f"%{search_query}%")).all()
    trainees = Trainee.query.filter(Trainee.username.ilike(f"%{search_query}%")).all()

    # Load departments with their course guides eagerly to avoid lazy loading issues
    departments = Department.query.options(db.joinedload(Department.course_guides)).all()

    # Load all reports to show in reports tab
    reports = Report.query.order_by(Report.created_at.desc()).all()

    return render_template(
        'super_admin_home.html',
        user=user,
        admins=admins,
        trainees=trainees,
        departments=departments,
        reports=reports
    )


@app.route('/admin-home')
def admin_home():
    if session.get('role') != 'admin' or 'user' not in session:
        return redirect(url_for('login'))

    admin = Admin.query.filter_by(username=session['user']).first()
    if not admin:
        return redirect(url_for('login'))

    # Get trainees in this admin's department
    trainees = Trainee.query.filter_by(department_id=admin.department_id).all()
    total_trainees = len(trainees)
    trainees_with_no_reports = sum(1 for t in trainees if Report.query.filter_by(trainee_id=t.id).count() == 0)

    # Get all reports submitted by these trainees
    trainee_ids = [t.id for t in trainees]
    reports_today = Report.query.filter(
        Report.trainee_id.in_(trainee_ids),
        Report.created_at >= datetime.combine(date.today(), datetime.min.time())
    ).count()

    # Also get all reports for these trainees to display in admin page
    reports = Report.query.filter(Report.trainee_id.in_(trainee_ids)).order_by(Report.created_at.desc()).all()

    return render_template('admin_home.html', user=admin, trainees=trainees,
                           total_trainees=total_trainees,
                           trainees_with_no_reports=trainees_with_no_reports,
                           reports_today=reports_today,
                           reports=reports)

@app.route('/trainee-home')
def trainee_home():
    if session.get('role') != 'trainee' or 'user' not in session:
        return redirect(url_for('login'))

    user = Trainee.query.filter_by(username=session['user']).first()
    if not user:
        return redirect(url_for('login'))

    reports = Report.query.filter_by(trainee_id=user.id).all()
    course_guides = CourseGuide.query.filter_by(department_id=user.department_id).order_by(CourseGuide.uploaded_at.desc()).all()

    return render_template('trainee_home.html', user=user, reports=reports, course_guides=course_guides)

@app.route('/submit-report', methods=['POST'])
def submit_report():
    if session.get('role') != 'trainee' or 'user' not in session:
        return redirect(url_for('login'))

    trainee = Trainee.query.filter_by(username=session['user']).first()
    if not trainee:
        return redirect(url_for('login'))

    title = request.form.get('reportTitle')
    file = request.files.get('reportFile')

    if file and title:
        filename = secure_filename(file.filename)
        file_data = file.read()
        report = Report(title=title, filename=filename, file_data=file_data, trainee_id=trainee.id)
        db.session.add(report)
        db.session.commit()
        return redirect(url_for('trainee_home'))

    return "Missing title or file", 400

@app.route('/admin/course-guide-upload', methods=['GET', 'POST'])
def course_guide_upload():
    if session.get('role') != 'admin':
        return redirect(url_for('login'))

    admin = Admin.query.filter_by(username=session['user']).first()
    if not admin or not admin.department_id:
        flash("You must be assigned to a department to upload guides.", "error")
        return redirect(url_for('admin_home'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        file = request.files.get('file')

        if not title or not file:
            flash("Title and file are required.", "error")
            return redirect(url_for('course_guide_upload'))

        filename = secure_filename(file.filename)
        file_data = file.read()

        new_guide = CourseGuide(title=title, filename=filename, file_data=file_data, department_id=admin.department_id)
        db.session.add(new_guide)
        db.session.commit()

        flash("Course guide uploaded successfully.", "success")
        return redirect(url_for('course_guide_upload'))

    # GET request: send current guides for this admin's department
    guides = CourseGuide.query.filter_by(department_id=admin.department_id).order_by(CourseGuide.uploaded_at.desc()).all()

    return render_template('course_guide_upload.html', guides=guides, user=admin)


@app.route('/delete_course_guide/<int:guide_id>', methods=['POST'])
def delete_course_guide(guide_id):
    if session.get('role') != 'admin' or 'user' not in session:
        return redirect(url_for('login'))

    admin = Admin.query.filter_by(username=session['user']).first()
    if not admin:
        return redirect(url_for('login'))

    guide = CourseGuide.query.get(guide_id)
    if not guide or guide.department_id != admin.department_id:
        flash("You are not authorized to delete this guide.", "error")
        return redirect(url_for('course_guide_upload'))

    db.session.delete(guide)
    db.session.commit()
    flash("Course guide deleted successfully.", "success")
    return redirect(url_for('course_guide_upload'))

@app.route('/download_report/<int:report_id>')
def download_report(report_id):
    report = Report.query.get(report_id)
    if not report or not report.file_data:
        abort(404)

    return send_file(io.BytesIO(report.file_data), mimetype='application/octet-stream',
                     as_attachment=True, download_name=report.filename)

@app.route('/download_course_guide/<int:guide_id>')
def download_course_guide(guide_id):
    guide = CourseGuide.query.get(guide_id)
    if not guide or not guide.file_data:
        abort(404)

    return send_file(io.BytesIO(guide.file_data), mimetype='application/octet-stream',
                     as_attachment=True, download_name=guide.filename)

@app.route('/update-profile', methods=['POST'])
def update_profile():
    if 'user' not in session or session.get('role') != 'trainee':
        return redirect(url_for('login'))

    trainee = Trainee.query.filter_by(username=session['user']).first()
    if not trainee:
        return redirect(url_for('login'))

    trainee.email = request.form.get('email')
    trainee.phone = request.form.get('phone')
    trainee.university = request.form.get('university')
    db.session.commit()
    return redirect(url_for('trainee_home'))

@app.route('/delete-admin/<int:admin_id>', methods=['POST'])
def delete_admin(admin_id):
    if session.get('role') != 'superadmin':
        return redirect(url_for('login'))

    admin = Admin.query.get(admin_id)
    if admin:
        db.session.delete(admin)
        db.session.commit()
        flash("Admin deleted successfully.", "success")
    else:
        flash("Admin not found.", "error")

    return redirect(url_for('superadmin_home'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
