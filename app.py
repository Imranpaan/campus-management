from flask import Flask, render_template, redirect, url_for, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret123'

# Lecturer class
class LecturerLoginForm(FlaskForm):
    user_id = StringField('Lecturer User ID', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

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

# Student login
@app.route('/student/login', methods=['GET', 'POST'])
def student_login():
    form = StudentLoginForm()
    if form.validate_on_submit():
        if form.student_id.data == 'student1' and form.password.data == '1234':
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
