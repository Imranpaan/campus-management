from flask import Flask, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from flask_bcrypt import Bcrypt
import sqlite3
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret123'

bcrypt = Bcrypt(app)

STUDENT_DB = "static/student.db"
ADMIN_DB = "static/admin.db"
LECTURER_DB = "static/lecturer.db"

os.makedirs("static", exist_ok=True)

def init_db(db_path, table_sql):
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(table_sql)
    conn.commit()
    conn.close()

init_db(STUDENT_DB, """
CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
""")

init_db(ADMIN_DB, """
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
""")

init_db(LECTURER_DB, """
CREATE TABLE IF NOT EXISTS lecturers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lecturer_id TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
""")

# ---------------- FORMS ----------------
class StudentSignupForm(FlaskForm):
    student_id = StringField('Student ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class StudentLoginForm(FlaskForm):
    student_id = StringField('Student ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AdminSignupForm(FlaskForm):
    admin_id = StringField('Admin ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class AdminLoginForm(FlaskForm):
    admin_id = StringField('Admin ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class LecturerSignupForm(FlaskForm):
    lecturer_id = StringField('Lecturer ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class LecturerLoginForm(FlaskForm):
    user_id = StringField('Lecturer ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

def query_db(db, query, args=(), one=False):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute(query, args)
    conn.commit()
    result = cur.fetchall()
    conn.close()
    return result[0] if one and result else result

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/student/signup', methods=['GET', 'POST'])
def student_signup():
    form = StudentSignupForm()
    if form.validate_on_submit():
        if len(form.password.data) < 8:
            flash("Password must be at least 8 characters", "danger")
            return render_template('studentsignup.html', form=form)

        try:
            query_db(
                STUDENT_DB,
                "INSERT INTO students (student_id, password) VALUES (?, ?)",
                (form.student_id.data,
                 bcrypt.generate_password_hash(form.password.data).decode())
            )
            flash("Student account created successfully!", "success")
            return redirect(url_for('student_login'))
        except sqlite3.IntegrityError:
            flash("Student ID already exists", "danger")

    return render_template('studentsignup.html', form=form)

@app.route('/student/login', methods=['GET', 'POST'])
def student_login():
    form = StudentLoginForm()
    if form.validate_on_submit():
        user = query_db(
            STUDENT_DB,
            "SELECT * FROM students WHERE student_id = ?",
            (form.student_id.data,),
            one=True
        )
        if user and bcrypt.check_password_hash(user[2], form.password.data):
            return redirect(url_for('dashboard'))
        flash("Invalid Student ID or Password", "danger")

    return render_template('student_login.html', form=form)

@app.route('/admin/signup', methods=['GET', 'POST'])
def admin_signup():
    form = AdminSignupForm()
    if form.validate_on_submit():
        if len(form.password.data) < 8:
            flash("Password must be at least 8 characters", "danger")
            return render_template('admin_signup.html', form=form)

        try:
            query_db(
                ADMIN_DB,
                "INSERT INTO admins (admin_id, password) VALUES (?, ?)",
                (form.admin_id.data,
                 bcrypt.generate_password_hash(form.password.data).decode())
            )
            flash("Admin account created successfully!", "success")
            return redirect(url_for('admin_login'))
        except sqlite3.IntegrityError:
            flash("Admin ID already exists", "danger")

    return render_template('admin_signup.html', form=form)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        admin = query_db(
            ADMIN_DB,
            "SELECT * FROM admins WHERE admin_id = ?",
            (form.admin_id.data,),
            one=True
        )
        if admin and bcrypt.check_password_hash(admin[2], form.password.data):
            return redirect(url_for('dashboard'))
        flash("Invalid Admin ID or Password", "danger")

    return render_template('admin_login.html', form=form)

@app.route('/lecturer/signup', methods=['GET', 'POST'])
def lecturer_signup():
    form = LecturerSignupForm()
    if form.validate_on_submit():
        if len(form.password.data) < 8:
            flash("Password must be at least 8 characters", "danger")
            return render_template('lecturer_signup.html', form=form)

        try:
            query_db(
                LECTURER_DB,
                "INSERT INTO lecturers (lecturer_id, password) VALUES (?, ?)",
                (form.lecturer_id.data,
                 bcrypt.generate_password_hash(form.password.data).decode())
            )
            flash("Lecturer account created successfully!", "success")
            return redirect(url_for('lecturer_login'))
        except sqlite3.IntegrityError:
            flash("Lecturer ID already exists", "danger")

    return render_template('lecturer_signup.html', form=form)

@app.route('/lecturer/login', methods=['GET', 'POST'])
def lecturer_login():
    form = LecturerLoginForm()
    if form.validate_on_submit():
        lecturer = query_db(
            LECTURER_DB,
            "SELECT * FROM lecturers WHERE lecturer_id = ?",
            (form.user_id.data,),
            one=True
        )
        if lecturer and bcrypt.check_password_hash(lecturer[2], form.password.data):
            return redirect(url_for('dashboard'))
        flash("Invalid Lecturer ID or Password", "danger")

    return render_template('lecturer_login.html', form=form)

if __name__== '__main__':
    app.run(debug=True)