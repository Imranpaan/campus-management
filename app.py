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

# =========================
# DATABASE PATHS
# =========================
STUDENT_DB = "static/student.db"
ADMIN_DB = "static/admin.db"

os.makedirs("static", exist_ok=True)

# =========================
# CREATE ADMIN DB & TABLE
# =========================
def init_admin_db():
    conn = sqlite3.connect(ADMIN_DB)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL
    )
    """)
    conn.commit()
    conn.close()

init_admin_db()   # 🔥 THIS CREATES admin.db

# =========================
# FORMS
# =========================
class LecturerLoginForm(FlaskForm):
    user_id = StringField('Lecturer User ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class StudentSignupForm(FlaskForm):
    student_id = StringField('Student User ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class StudentLoginForm(FlaskForm):
    student_id = StringField('Student User ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AdminLoginForm(FlaskForm):
    admin_id = StringField('Admin User ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# =========================
# STUDENT DB QUERY
# =========================
def query_student_db(query, args=(), one=False):
    conn = sqlite3.connect(STUDENT_DB)
    cur = conn.cursor()
    cur.execute(query, args)
    conn.commit()
    rv = cur.fetchall()
    conn.close()
    return (rv[0] if rv else None) if one else rv

# =========================
# ROUTES
# =========================
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# Lecturer login (unchanged)
@app.route('/lecturer/login', methods=['GET', 'POST'])
def lecturer_login():
    form = LecturerLoginForm()
    if form.validate_on_submit():
        if form.user_id.data == 'lecturer1' and form.password.data == '1234':
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid User ID or Password', 'danger')
    return render_template('lecturer_login.html', form=form)

# =========================
# STUDENT SIGNUP
# =========================
@app.route('/student/signup', methods=['GET', 'POST'])
def student_signup():
    form = StudentSignupForm()
    if form.validate_on_submit():
        student_id = form.student_id.data
        password = form.password.data

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template('studentsignup.html', form=form)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            query_student_db(
                "INSERT INTO students (student_id, password) VALUES (?, ?)",
                (student_id, hashed_password)
            )
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for('student_login'))
        except sqlite3.IntegrityError:
            flash("Student ID already exists!", "danger")

    return render_template('studentsignup.html', form=form)

# =========================
# STUDENT LOGIN
# =========================
@app.route('/student/login', methods=['GET', 'POST'])
def student_login():
    form = StudentLoginForm()
    if form.validate_on_submit():
        student_id = form.student_id.data
        password = form.password.data

        user = query_student_db(
            "SELECT * FROM students WHERE student_id = ?",
            (student_id,),
            one=True
        )

        if user and bcrypt.check_password_hash(user[2], password):
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid Student ID or Password', 'danger')

    return render_template('student_login.html', form=form)

# =========================
# ADMIN LOGIN (USING admin.db)
# =========================
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        conn = sqlite3.connect(ADMIN_DB)
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM admins WHERE admin_id = ?",
            (form.admin_id.data,)
        )
        admin = cur.fetchone()
        conn.close()

        if admin and bcrypt.check_password_hash(admin[2], form.password.data):
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid Admin ID or Password', 'danger')

    return render_template('admin_login.html', form=form)

# =========================
if __name__ == '__main__':
    app.run(debug=True)
