from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, SelectField
from wtforms.validators import DataRequired, Email, EqualTo, NumberRange

class SignupForm(FlaskForm):
    name = StringField('Employee Name', validators=[DataRequired()])
    emp_id = StringField('Employee ID', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    role = SelectField('Role', choices=[], validators=[DataRequired()])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class TimesheetForm(FlaskForm):
    week_number = IntegerField('Week Number (1–52)', validators=[DataRequired(), NumberRange(min=1, max=52)])
    project = SelectField('Project', coerce=int)
    jira_task = SelectField('JIRA Task', coerce=int)

    mon = IntegerField('Monday', validators=[NumberRange(min=0, max=24)])
    tue = IntegerField('Tuesday', validators=[NumberRange(min=0, max=24)])
    wed = IntegerField('Wednesday', validators=[NumberRange(min=0, max=24)])
    thu = IntegerField('Thursday', validators=[NumberRange(min=0, max=24)])
    fri = IntegerField('Friday', validators=[NumberRange(min=0, max=24)])
    sat = IntegerField('Saturday', validators=[NumberRange(min=0, max=24)])
    sun = IntegerField('Sunday', validators=[NumberRange(min=0, max=24)])
    submit = SubmitField('Submit Task')