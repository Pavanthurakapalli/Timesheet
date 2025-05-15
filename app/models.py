from app import db, login_manager
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    emp_id = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='employee')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Timesheet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    week_number = db.Column(db.Integer)
    
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'))
    project = db.relationship('Project', backref='timesheets')

    jira_task_id = db.Column(db.Integer, db.ForeignKey('jira_task.id'))
    jira_task = db.relationship('JiraTask', backref='timesheets')

    mon = db.Column(db.Float)
    tue = db.Column(db.Float)
    wed = db.Column(db.Float)
    thu = db.Column(db.Float)
    fri = db.Column(db.Float)
    sat = db.Column(db.Float)
    sun = db.Column(db.Float)

    status = db.Column(db.String(20), default='Pending')


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)

class JiraTask(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task_code = db.Column(db.String(100), unique=True, nullable=False)