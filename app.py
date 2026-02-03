from flask import Flask, render_template, redirect, url_for, flash, session, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
import sqlite3
import os
from wtforms import SelectField 
from datetime import datetime, timedelta
from flask_mail import Mail, Message
import smtplib
from email.mime.text import MIMEText
import secrets
from itsdangerous import URLSafeTimedSerializer


app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret123'

serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'yourgmail@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_app_password'
app.config['MAIL_DEFAULT_SENDER'] = 'yourgmail@gmail.com'

mail = Mail(app)

bcrypt = Bcrypt(app)

# ===== File upload config =====

UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = {"pdf", "docx", "pptx", "jpg", "png"}

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

STUDENT_DB = "static/student.db"
ADMIN_DB = "static/admin.db"
LECTURER_DB = "static/lecturer.db"

os.makedirs("static", exist_ok=True)

def init_db(db_path, table_sql):
    conn = sqlite3.connect(db_path, timeout=10)
    cur = conn.cursor()
    cur.execute(table_sql)
    conn.commit()
    conn.close()

init_db(STUDENT_DB, """
CREATE TABLE IF NOT EXISTS students (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    status TEXT DEFAULT 'active'
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
    password TEXT NOT NULL,
    status TEXT DEFAULT 'active'
)
""")

init_db(LECTURER_DB, """
CREATE TABLE IF NOT EXISTS uploaded_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lecturer_id TEXT NOT NULL,
    filename TEXT NOT NULL,
    upload_time TEXT NOT NULL,
    status TEXT DEFAULT 'active'
)
""")


init_db(ADMIN_DB, """
CREATE TABLE IF NOT EXISTS equipment_bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    equipment_name TEXT NOT NULL,
    booked_by TEXT NOT NULL,
    booking_date TEXT NOT NULL,
    start_time TEXT NOT NULL,  -- When they start
    end_time TEXT NOT NULL,    -- When they return it
    user_role TEXT NOT NULL,
    status TEXT DEFAULT 'Reserved'
)
""")
init_db(ADMIN_DB, """
CREATE TABLE IF NOT EXISTS venue_bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    location TEXT NOT NULL,
    booked_by TEXT NOT NULL,
    user_role TEXT NOT NULL,
    status TEXT DEFAULT 'pending'
)
""")

init_db(ADMIN_DB, """
CREATE TABLE IF NOT EXISTS equipment_bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    equipment_name TEXT NOT NULL,
    booked_by TEXT NOT NULL,
    booking_date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    user_role TEXT NOT NULL,
    status TEXT DEFAULT 'Reserved'
)
""")

init_db(ADMIN_DB, """
CREATE TABLE IF NOT EXISTS venue_unavailability (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    location TEXT NOT NULL,
    date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    reason TEXT NOT NULL
)
""")

init_db(ADMIN_DB, """
CREATE TABLE IF NOT EXISTS announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
)
""")

# Add reset_token column (only runs once)
try:
    init_db(STUDENT_DB, "ALTER TABLE students ADD COLUMN reset_token TEXT")
except:
    pass

try:
    init_db(LECTURER_DB, "ALTER TABLE lecturers ADD COLUMN reset_token TEXT")
except:
    pass

try:
    init_db(ADMIN_DB, "ALTER TABLE admins ADD COLUMN reset_token TEXT")
except:
    pass


class StudentSignupForm(FlaskForm):
    student_id = StringField('Student ID', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class StudentLoginForm(FlaskForm):
    login = StringField('Student ID or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class AdminSignupForm(FlaskForm):
    admin_id = StringField('Admin ID', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class AdminLoginForm(FlaskForm):
    login = StringField('Admin ID or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class LecturerSignupForm(FlaskForm):
    lecturer_id = StringField('Lecturer ID', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class LecturerLoginForm(FlaskForm):
    login = StringField('Lecturer ID or Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class EventForm(FlaskForm):
    title = StringField('Event Title', validators=[DataRequired()])
    date = StringField('Event Date', validators=[DataRequired()])
    start_time = StringField('Start Time', validators=[DataRequired()])
    end_time = StringField('End Time', validators=[DataRequired()])
    location = SelectField('Venue', choices=[
        ('Lecture Hall A', 'Lecture Hall A'),
        ('Lecture Hall B', 'Lecture Hall B'),
        ('Computer Lab 1', 'Computer Lab 1'),
        ('Auditorium', 'Auditorium')
    ])
    description = StringField('Description')
    submit = SubmitField('Submit Event')


def query_db(db, query, args=(), one=False):
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row   # 🔥 THIS LINE CHANGES EVERYTHING
    cur = conn.cursor()
    cur.execute(query, args)
    conn.commit()
    result = cur.fetchall()
    conn.close()
    return result[0] if one and result else result

def send_email(to_email, subject, body):
    EMAIL_ADDRESS = "yourgmail@gmail.com"
    EMAIL_PASSWORD = "YOUR_GMAIL_APP_PASSWORD"

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_ADDRESS
    msg["To"] = to_email

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.sendmail(EMAIL_ADDRESS, to_email, msg.as_string())

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    announcements = query_db(
        ADMIN_DB,
        "SELECT * FROM announcements ORDER BY created_at DESC"
    )
    return render_template(
        'dashboard.html',
        announcements=announcements
    )
@app.route('/admin/users')
def manage_users():
    # Optional: restrict only admin
    if session.get('role') != 'admin':
        flash("Access denied", "danger")
        return redirect(url_for('dashboard'))

    students = query_db(
        STUDENT_DB,
        "SELECT student_id, status FROM students"
    )
    lecturers = query_db(
        LECTURER_DB,
        "SELECT lecturer_id, status FROM lecturers"
    )

    return render_template(
        'user_management.html',
        students=students,
        lecturers=lecturers
    )

@app.route('/admin/deactivate/<user_type>/<user_id>')
def deactivate_user(user_type, user_id):
    if session.get('role') != 'admin':
        flash("Access denied", "danger")
        return redirect(url_for('dashboard'))

    if user_type == 'student':
        query_db(
            STUDENT_DB,
            "UPDATE students SET status = 'inactive' WHERE student_id = ?",
            (user_id,)
        )
    elif user_type == 'lecturer':
        query_db(
            LECTURER_DB,
            "UPDATE lecturers SET status = 'inactive' WHERE lecturer_id = ?",
            (user_id,)
        )

    flash("User deactivated successfully", "success")
    return redirect(url_for('manage_users'))

import secrets

@app.route('/admin/reactivate/<user_type>/<user_id>')
def reactivate_user(user_type, user_id):
    if session.get('role') != 'admin':
        flash("Access denied", "danger")
        return redirect(url_for('dashboard'))

    if user_type == 'student':
        query_db(
            STUDENT_DB,
            "UPDATE students SET status = 'active' WHERE student_id = ?",
            (user_id,)
        )
    elif user_type == 'lecturer':
        query_db(
            LECTURER_DB,
            "UPDATE lecturers SET status = 'active' WHERE lecturer_id = ?",
            (user_id,)
        )

    flash("User reactivated successfully", "success")
    return redirect(url_for('manage_users'))


@app.route('/admin/reset-password/<user_type>/<user_id>')
def reset_password(user_type, user_id):
    if session.get('role') != 'admin':
        flash("Access denied", "danger")
        return redirect(url_for('dashboard'))

    temp_password = secrets.token_urlsafe(8)
    hashed_password = bcrypt.generate_password_hash(temp_password).decode()

    if user_type == 'student':
        query_db(
            STUDENT_DB,
            "UPDATE students SET password = ? WHERE student_id = ?",
            (hashed_password, user_id)
        )
    elif user_type == 'lecturer':
        query_db(
            LECTURER_DB,
            "UPDATE lecturers SET password = ? WHERE lecturer_id = ?",
            (hashed_password, user_id)
        )

    # TEMP: show password (later replace with email)
    flash(f"Temporary password for {user_id}: {temp_password}", "warning")
    return redirect(url_for('manage_users'))

from itsdangerous import URLSafeTimedSerializer

app.config['SECRET_KEY'] = 'secret123'

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        # Check STUDENT
        user = query_db(STUDENT_DB, "SELECT id FROM students WHERE email = ?", (email,), one=True)
        role = 'student'

        # Check LECTURER
        if not user:
            user = query_db(LECTURER_DB, "SELECT id FROM lecturers WHERE email = ?", (email,), one=True)
            role = 'lecturer'

        # Check ADMIN
        if not user:
            user = query_db(ADMIN_DB, "SELECT id FROM admins WHERE email = ?", (email,), one=True)
            role = 'admin'

        if user:
            token = serializer.dumps({'id': user[0], 'role': role}, salt='reset-password')
            reset_link = url_for('reset_password_token', token=token, _external=True)

            # For now we SHOW link instead of sending email
            flash(f"Reset link (copy this): {reset_link}", "info")
        else:
            flash("Email not found!", "danger")

    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    try:
        data = serializer.loads(token, salt='reset-password', max_age=3600)
    except:
        flash("Invalid or expired link", "danger")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        email = request.form.get("email")
        password = request.form.get('password')
        confirm = request.form.get('confirm')

        # 🔴 DEBUG (optional — you can remove later)
        print("Password:", password)
        print("Confirm :", confirm)

        if not password or not confirm:
            flash("Please fill in both fields", "danger")
            return render_template('reset_password.html')

        if password != confirm:
            flash("Passwords do not match", "danger")
            return render_template('reset_password.html')

        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')

        if data['role'] == 'student':
            query_db(STUDENT_DB,
                    "UPDATE students SET password = ? WHERE email = ?",
                    (hashed_pw, email))
        elif data['role'] == 'lecturer':
            query_db(LECTURER_DB,
                    "UPDATE lecturer SET password = ? WHERE email = ?",
                    (hashed_pw, email))
        else:
            query_db(ADMIN_DB,
                    "UPDATE admins SET password = ? WHERE email = ?",
                    (hashed_pw, email))

        flash("Password reset successful. Please login.", "success")
        return redirect(url_for('index'))

    return render_template('reset_password.html')

@app.route('/schedule-event', methods=['GET', 'POST'])
def schedule_event():
    if 'user_id' not in session:
        flash("Please login first", "danger")
        return redirect(url_for('index'))

    form = EventForm()

    if form.validate_on_submit():
        user_id = session.get('user_id')
        role = session.get('role')

        date = form.date.data
        start_time = form.start_time.data
        end_time = form.end_time.data
        location = form.location.data

        # 🔴 VENUE CLASH CHECK
        clash = query_db(
            ADMIN_DB,
            """
            SELECT * FROM venue_bookings
            WHERE date = ?
              AND location = ?
              AND (? < end_time AND ? > start_time)
            """,
            (date, location, start_time, end_time),
            one=True
        )

        if clash:
            flash(
                f"Venue clash! {location} is already booked during that time.",
                "danger"
            )
            return render_template('schedule_event.html', form=form)
        
         # 🔴 UNAVAILABILITY CHECK (maintenance / special events)
        unavailable = query_db(
            ADMIN_DB,
            """
            SELECT * FROM venue_unavailability
            WHERE date = ?
            AND location = ?
            AND (? < end_time AND ? > start_time)
            """,
            (date, location, start_time, end_time),
            one=True
        )

        if unavailable:
            flash(
                f"{location} is unavailable during that time (maintenance or special event).",
                "danger"
            )
            return render_template('schedule_event.html', form=form)


       # ✅ NO CLASH → INSERT EVENT
        query_db(
            ADMIN_DB,
            """
            INSERT INTO venue_bookings
            (title, date, start_time, end_time, location, booked_by, user_role, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
            form.title.data,
            date,
            start_time,
            end_time,
            location,
            user_id,
            role,
            'pending'
            )

        )

        flash("Event scheduled successfully!", "success")
        return redirect(url_for('timetable'))

    return render_template('schedule_event.html', form=form)

@app.route('/admin/unavailable', methods=['GET', 'POST'])
def set_unavailable():
    if session.get('role') != 'admin':
        flash("Access denied", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        location = request.form.get('location')
        date = request.form.get('date')
        start_time = request.form.get('start_time')
        end_time = request.form.get('end_time')
        reason = request.form.get('reason')

        query_db(
            ADMIN_DB,
            """
            INSERT INTO venue_unavailability
            (location, date, start_time, end_time, reason)
            VALUES (?, ?, ?, ?, ?)
            """,
            (location, date, start_time, end_time, reason)
        )

        flash("Venue marked as unavailable.", "success")
        return redirect(url_for('timetable'))

    return render_template('set_unavailable.html')

@app.route('/admin/unavailable/delete')
def delete_unavailability():
    if session.get('role') != 'admin':
        flash("Access denied", "danger")
        return redirect(url_for('timetable'))

    location = request.args.get('uid')
    date = request.args.get('date')
    start = request.args.get('start')

    query_db(
        ADMIN_DB,
        """
        DELETE FROM venue_unavailability
        WHERE location = ? AND date = ? AND start_time = ?
        """,
        (location, date, start)
    )

    flash("Unavailability removed.", "success")
    return redirect(url_for('timetable'))

# ================================
# ADMIN APPROVE / REJECT BOOKINGS
# ================================
@app.route('/admin/booking/<int:booking_id>/<action>')
def approve_reject_booking(booking_id, action):
    if session.get('role') != 'admin':
        flash("Access denied", "danger")
        return redirect(url_for('dashboard'))

    if action not in ['approve', 'reject']:
        flash("Invalid action", "danger")
        return redirect(url_for('timetable'))

    status = 'approved' if action == 'approve' else 'rejected'

    query_db(
        ADMIN_DB,
        "UPDATE venue_bookings SET status = ? WHERE id = ?",
        (status, booking_id)
    )

    flash(f"Booking {status}.", "success")
    return redirect(url_for('timetable'))

@app.route('/timetable')
def timetable():
    # Existing bookings (KEEP AS IS)
    events = query_db(
        ADMIN_DB,
        """
        SELECT
            id,
            title,
            date,
            start_time,
            end_time,
            location,
            booked_by,
            user_role,
            status
        FROM venue_bookings
        ORDER BY date, start_time
        """
    )

    # 🔴 ADDITION: venue unavailability (maintenance / special events)
    unavailable = query_db(
        ADMIN_DB,
        """
        SELECT
            location,
            date,
            start_time,
            end_time,
            reason
        FROM venue_unavailability
        ORDER BY date, start_time
        """
    )

    # Pass BOTH to the template
    return render_template(
        'timetable.html',
        events=events,
        unavailable=unavailable
    )

@app.route('/admin/reports')
def admin_reports():
    if session.get('role') != 'admin':
        flash("Access denied", "danger")
        return redirect(url_for('dashboard'))

    # Total bookings
    total_bookings = query_db(
        ADMIN_DB,
        "SELECT COUNT(*) FROM venue_bookings",
        one=True
    )[0]

    # Bookings per venue
    bookings_by_venue = query_db(
        ADMIN_DB,
        """
        SELECT location, COUNT(*)
        FROM venue_bookings
        GROUP BY location
        """
    )

    # Bookings by role
    bookings_by_role = query_db(
        ADMIN_DB,
        """
        SELECT user_role, COUNT(*)
        FROM venue_bookings
        GROUP BY user_role
        """
    )

    # Booking status distribution
    bookings_by_status = query_db(
        ADMIN_DB,
        """
        SELECT status, COUNT(*)
        FROM venue_bookings
        GROUP BY status
        """
    )

    # Venue unavailability count
    total_unavailable = query_db(
        ADMIN_DB,
        "SELECT COUNT(*) FROM venue_unavailability",
        one=True
    )[0]

    return render_template(
        'reports.html',
        total_bookings=total_bookings,
        bookings_by_venue=bookings_by_venue,
        bookings_by_role=bookings_by_role,
        bookings_by_status=bookings_by_status,
        total_unavailable=total_unavailable
    )


@app.route('/equipment')
def equipment():
    # 1. Check if user is logged in
    if 'user_id' not in session:
        flash("Please login first", "danger")
        return redirect(url_for('student_login'))
    
    # 2. BLOCK LECTURERS: If the role is 'lecturer', send them away
    if session.get('role') == 'lecturer':
        flash("Access Denied: Lecturers are not permitted to view or book equipment.", "danger")
        return redirect(url_for('dashboard'))
    
    # 3. If they are a student or admin, show the page
    bookings = query_db(ADMIN_DB, "SELECT * FROM equipment_bookings")
    return render_template('equipment.html', bookings=bookings)

@app.route('/book-equipment', methods=['POST'])
def book_equipment():
    if 'user_id' not in session:
        flash("Please login first", "danger")
        return redirect(url_for('student_login'))
    
    name = request.form.get('equipment_name')
    date = request.form.get('date')
    start = request.form.get('start_time')
    end = request.form.get('end_time')
    user_id = session.get('user_id')
    role = session.get('role')

    # IMPROVED CLASH CHECK
    # This checks if (NewStart < ExistingEnd) AND (NewEnd > ExistingStart)
    clash = query_db(ADMIN_DB, """
        SELECT * FROM equipment_bookings 
        WHERE equipment_name = ? 
        AND booking_date = ? 
        AND (? < end_time AND ? > start_time)
    """, (name, date, start, end), one=True)

    if clash:
        flash(f"Sorry, {name} is already booked on {date} during that time!", "danger")
        return redirect(url_for('equipment'))

    query_db(ADMIN_DB, 
             "INSERT INTO equipment_bookings (equipment_name, booked_by, booking_date, start_time, end_time, user_role) VALUES (?, ?, ?, ?, ?, ?)",
             (name, user_id, date, start, end, role))
    
    flash(f"{name} reserved from {start} to {end}!", "success")
    return redirect(url_for('equipment'))

@app.route('/return-equipment/<int:booking_id>')
def return_equipment(booking_id):
    # Ensure the user is logged in
    if 'user_id' not in session:
        return redirect(url_for('student_login'))
    
    # Delete the specific booking using its primary key (ID)
    query_db(ADMIN_DB, "DELETE FROM equipment_bookings WHERE id = ?", (booking_id,))
    
    flash("Equipment returned/booking cancelled.", "info")
    return redirect(url_for('equipment'))


@app.route('/student/signup', methods=['GET', 'POST'])
def student_signup():
    form = StudentSignupForm()
    if form.validate_on_submit():
        if len(form.password.data) < 8:
            flash("Password must be at least 8 characters", "danger")
            return render_template('studentsignup.html', form=form)

        try:
            # Save to database first
            query_db(
                STUDENT_DB,
                "INSERT INTO students (student_id, email, password) VALUES (?, ?, ?)",
                (
                    form.student_id.data,
                    form.email.data,
                    bcrypt.generate_password_hash(form.password.data).decode()
                )
            )

            # 📧 SEND WELCOME EMAIL
            msg = Message(
                subject="Welcome to Campus Management System 🎓",
                recipients=[form.email.data]
            )
            msg.body = f"""
Hi {form.student_id.data},

Your student account has been successfully created.

You can now log in and start booking venues and equipment.

– Campus Management System
"""
            mail.send(msg)

            flash("Student account created successfully! A confirmation email has been sent.", "success")
            return redirect(url_for('student_login'))

        except sqlite3.IntegrityError:
            flash("Student ID or Email already exists", "danger")

    return render_template('studentsignup.html', form=form)


@app.route('/student/login', methods=['GET', 'POST'])
def student_login():
    form = StudentLoginForm()

    if form.validate_on_submit():
        login_input = form.login.data  # ID or Email

        # Check if user typed email
        if "@" in login_input:
            user = query_db(
                STUDENT_DB,
                "SELECT * FROM students WHERE email = ? AND status = 'active'",
                (login_input,),
                one=True
            )
        else:
            user = query_db(
                STUDENT_DB,
                "SELECT * FROM students WHERE student_id = ? AND status = 'active'",
                (login_input,),
                one=True
            )

        if user and bcrypt.check_password_hash(user["password"], form.password.data):
            session['role'] = 'student'
            session['user_id'] = user["student_id"]
            return redirect(url_for('dashboard'))

        flash("Invalid credentials or account inactive", "danger")

    return render_template('student_login.html', form=form)

@app.route('/student/forgot-password', methods=['GET', 'POST'])
def student_forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        user = query_db(
            STUDENT_DB,
            "SELECT * FROM students WHERE email = ?",
            (email,),
            one=True
        )

        if user:
            token = secrets.token_urlsafe(16)

            query_db(
                STUDENT_DB,
                "UPDATE students SET reset_token = ? WHERE email = ?",
                (token, email)
            )

            flash(f"Password reset link: http://127.0.0.1:5000/student/reset/{token}", "info")
        else:
            flash("Email not found", "danger")

    return render_template('forgot_password.html', role="student")

@app.route('/student/reset/<token>', methods=['GET', 'POST'])
def student_reset_password(token):
    if request.method == 'POST':
        new_password = request.form.get('password')

        if len(new_password) < 8:
            flash("Password must be at least 8 characters", "danger")
            return render_template('reset_password.html')

        hashed = bcrypt.generate_password_hash(new_password).decode()

        query_db(
            STUDENT_DB,
            "UPDATE students SET password = ?, reset_token = NULL WHERE reset_token = ?",
            (hashed, token)
        )

        flash("Password reset successful. Please login.", "success")
        return redirect(url_for('student_login'))

    return render_template('reset_password.html')

@app.route('/admin/signup', methods=['GET', 'POST'])
def admin_signup():
    form = AdminSignupForm()
    if form.validate_on_submit():
        if len(form.password.data) < 8:
            flash("Password must be at least 8 characters", "danger")
            return render_template('admin_signup.html', form=form)

        try:
            # Save admin to database
            query_db(
                ADMIN_DB,
                "INSERT INTO admins (admin_id, email, password) VALUES (?, ?, ?)",
                (
                    form.admin_id.data,
                    form.email.data,
                    bcrypt.generate_password_hash(form.password.data).decode()
                )
            )

            # 📧 SEND WELCOME EMAIL
            msg = Message(
                subject="Welcome Admin – Campus Management System 🛠️",
                recipients=[form.email.data]
            )
            msg.body = f"""
Hello {form.admin_id.data},

Your administrator account has been successfully created.

You now have access to:
• User management
• Venue controls
• Reports and announcements

Login and start managing the campus system.

– Campus Management System
"""
            mail.send(msg)

            flash("Admin account created successfully! A confirmation email has been sent.", "success")
            return redirect(url_for('admin_login'))

        except sqlite3.IntegrityError:
            flash("Admin ID or Email already exists", "danger")

    return render_template('admin_signup.html', form=form)

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()

    if form.validate_on_submit():
        login_input = form.login.data  # ID or Email

        if "@" in login_input:
            admin = query_db(
                ADMIN_DB,
                "SELECT * FROM admins WHERE email = ?",
                (login_input,),
                one=True
            )
        else:
            admin = query_db(
                ADMIN_DB,
                "SELECT * FROM admins WHERE admin_id = ?",
                (login_input,),
                one=True
            )

        if admin and bcrypt.check_password_hash(admin["password"], form.password.data):
            session['role'] = 'admin'
            session['user_id'] = admin["admin_id"]
            return redirect(url_for('dashboard'))

        flash("Invalid Admin ID/Email or Password", "danger")

    return render_template('admin_login.html', form=form)

@app.route('/admin/announcements', methods=['GET', 'POST'])
def admin_announcements():
    if session.get('role') != 'admin' and 'user_id' not in session:
        flash("Access denied", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        title = request.form.get('title')
        message = request.form.get('message')

        query_db(
            ADMIN_DB,
            "INSERT INTO announcements (title, message) VALUES (?, ?)",
            (title, message)
        )

        flash("Announcement posted successfully.", "success")
        return redirect(url_for('admin_announcements'))

    announcements = query_db(
        ADMIN_DB,
        "SELECT * FROM announcements ORDER BY created_at DESC"
    )

    return render_template(
        'admin_announcements.html',
        announcements=announcements
    )

@app.route('/admin/announcements/delete/<int:aid>')
def delete_announcement(aid):
    if session.get('role') != 'admin':
        flash("Access denied", "danger")
        return redirect(url_for('dashboard'))

    query_db(
        ADMIN_DB,
        "DELETE FROM announcements WHERE id = ?",
        (aid,)
    )

    flash("Announcement removed.", "info")
    return redirect(url_for('admin_announcements'))


@app.route('/lecturer/signup', methods=['GET', 'POST'])
def lecturer_signup():
    form = LecturerSignupForm()
    if form.validate_on_submit():
        if len(form.password.data) < 8:
            flash("Password must be at least 8 characters", "danger")
            return render_template('lecturer_signup.html', form=form)

        try:
            # Save lecturer to database
            query_db(
                LECTURER_DB,
                "INSERT INTO lecturers (lecturer_id, email, password) VALUES (?, ?, ?)",
                (
                    form.lecturer_id.data,
                    form.email.data,
                    bcrypt.generate_password_hash(form.password.data).decode()
                )
            )

            # 📧 SEND WELCOME EMAIL
            msg = Message(
                subject="Welcome Lecturer – Campus Management System 🎓",
                recipients=[form.email.data]
            )
            msg.body = f"""
Hi {form.lecturer_id.data},

Your lecturer account has been successfully created.

You can now log in to manage your events and campus activities.

– Campus Management System
"""
            mail.send(msg)

            flash("Lecturer account created successfully! A confirmation email has been sent.", "success")
            return redirect(url_for('lecturer_login'))

        except sqlite3.IntegrityError:
            flash("Lecturer ID or Email already exists", "danger")

    return render_template('lecturer_signup.html', form=form)

@app.route('/lecturer/login', methods=['GET', 'POST'])
def lecturer_login():
    form = LecturerLoginForm()

    if form.validate_on_submit():
        login_input = form.login.data  # ID or Email

        if "@" in login_input:
            lecturer = query_db(
                LECTURER_DB,
                "SELECT * FROM lecturers WHERE email = ?",
                (login_input,),
                one=True
            )
        else:
            lecturer = query_db(
                LECTURER_DB,
                "SELECT * FROM lecturers WHERE lecturer_id = ?",
                (login_input,),
                one=True
            )

        if lecturer and bcrypt.check_password_hash(lecturer["password"], form.password.data):
            session['role'] = 'lecturer'
            session['user_id'] = lecturer["lecturer_id"]
            return redirect(url_for('dashboard'))

        flash("Invalid credentials or account deactivated", "danger")

    return render_template('lecturer_login.html', form=form)

@app.route("/lecturer/upload", methods=["GET", "POST"])
def upload_file():
    if session.get("role") != "lecturer":
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))

    # GET → show page
    if request.method == "GET":
        return render_template("lecturer_upload.html")

    # POST → handle upload
    file = request.files.get("file")

    if not file or file.filename == "":
        flash("No file selected", "danger")
        return redirect(request.url)

    if not allowed_file(file.filename):
        flash("File type not allowed", "danger")
        return redirect(request.url)

    filename = secure_filename(file.filename)
    file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

    query_db(
        LECTURER_DB,
        """
        INSERT INTO uploaded_files (lecturer_id, filename, upload_time)
        VALUES (?, ?, ?)
        """,
        (
            session.get("user_id"),
            filename,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )
    )

    flash("File uploaded successfully!", "success")
    return redirect(url_for("lecturer_files"))

@app.route("/lecturer/files")
def lecturer_files():
    if session.get("role") != "lecturer":
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))

    rows = query_db(
        LECTURER_DB,
        """
        SELECT id, filename, upload_time
        FROM uploaded_files
        WHERE lecturer_id = ?
        ORDER BY upload_time DESC
        """,
        (session.get("user_id"),)
    )

    files = []
    for file_id, filename, upload_time in rows:
        date, time = upload_time.split(" ")
        files.append((file_id, filename, date, time))

    return render_template("lecturer_files.html", files=files)

@app.route("/lecturer/delete/<int:file_id>")
def delete_file(file_id):
    if session.get("role") != "lecturer":
        flash("Access denied", "danger")
        return redirect(url_for("dashboard"))

    file = query_db(
        LECTURER_DB,
        "SELECT filename FROM uploaded_files WHERE id = ?",
        (file_id,),
        one=True
    )

    if not file:
        flash("File not found", "danger")
        return redirect(url_for("lecturer_files"))

    filename = file[0]

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if os.path.exists(filepath):
        os.remove(filepath)

    query_db(
        LECTURER_DB,
        "DELETE FROM uploaded_files WHERE id = ?",
        (file_id,)
    )

    flash("File deleted successfully", "success")
    return redirect(url_for("lecturer_files"))



@app.route('/logout')
def logout():
    session.clear() 
    flash("You have been logged out.", "info")
    return redirect(url_for('index'))



if __name__== '__main__':
    app.run(debug=True)