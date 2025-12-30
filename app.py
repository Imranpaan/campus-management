from flask import Flask, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_bcrypt import Bcrypt
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret123'


bcrypt = Bcrypt(app)
DB_NAME = "static/student.db"


# Lecturer class
class LecturerLoginForm(FlaskForm):
    user_id = StringField('Lecturer User ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class StudentSignupForm(FlaskForm):
    student_id = StringField('Student User ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')


# Student class
class StudentLoginForm(FlaskForm):
    student_id = StringField('Student User ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

# Admin class
class AdminLoginForm(FlaskForm):
    admin_id = StringField('Admin User ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

def query_db(query, args=(), one=False):
    conn = sqlite3.connect(DB_NAME)
    cur = conn.cursor()
    cur.execute(query, args)
    conn.commit()
    rv = cur.fetchall()
    conn.close()
    return (rv[0] if rv else None) if one else rv



@app.route('/')
def index():
    return render_template('index.html')

# main page
@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

# Lecturer login
@app.route('/lecturer/login', methods=['GET', 'POST'])
def lecturer_login():
    form = LecturerLoginForm()
    if form.validate_on_submit():
        if form.user_id.data == 'lecturer1' and form.password.data == '1234':
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid User ID or Password', 'danger')
    return render_template('lecturer_login.html', form=form)

# student signup
@app.route('/student/signup', methods=['GET', 'POST'])
def student_signup():
    form = StudentSignupForm()
    if form.validate_on_submit():
        student_id = form.student_id.data
        password = form.password.data

        # Password validation: at least 8 chars, numbers/special allowed
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template('studentsignup.html', form=form)


        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            query_db("INSERT INTO students (student_id, password) VALUES (?, ?)", 
                     (student_id, hashed_password))
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for('student_login'))
        except sqlite3.IntegrityError:
            flash("Student ID already exists!", "danger")

    return render_template('studentsignup.html', form=form)

# Student login
@app.route('/student/login', methods=['GET', 'POST'])
def student_login():
    form = StudentLoginForm()
    if form.validate_on_submit():
        student_id = form.student_id.data
        password = form.password.data

        user = query_db("SELECT * FROM students WHERE student_id = ?", (student_id,), one=True)

        if user and bcrypt.check_password_hash(user[2], password):
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid Student ID or Password', 'danger')

    return render_template('student_login.html', form=form)


# Admin login
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        if form.admin_id.data == 'admin1' and form.password.data == 'admin123':
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid Admin ID or Password', 'danger')
    return render_template('admin_login.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)
