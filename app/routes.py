from flask import Blueprint, render_template, redirect, url_for, flash, request
from app.forms import SignupForm, LoginForm, TimesheetForm
from app.models import User, Timesheet, Project, JiraTask
from app import db, bcrypt
from flask_login import login_user, logout_user, login_required, current_user

bp = Blueprint('routes', __name__)

@bp.route('/')
def home():
    return redirect(url_for('routes.login'))

@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()

    admin_exists = User.query.filter_by(role='admin').first() is not None
    if admin_exists:
        form.role.choices = [('employee', 'Employee')]
    else:
        form.role.choices = [('admin', 'Admin'), ('employee', 'Employee')]


    if form.validate_on_submit():
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(name=form.name.data, emp_id=form.emp_id.data,
                    email=form.email.data, role=form.role.data, password=hashed_pw)
        db.session.add(user)
        db.session.commit()
        flash('Signup successful. Please login.', 'success')
        return redirect(url_for('routes.login'))
    return render_template('signup.html', form=form)

@bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('routes.dashboard'))
        else:
            flash('Invalid login credentials.', 'danger')
    return render_template('login.html', form=form)

@bp.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        users = User.query.all()
        return render_template('dashboard.html', users=users, role='admin')
    elif current_user.role == 'manager':
        users = User.query.filter(User.role == 'employee').all()
        return render_template('dashboard.html', users=users, role='manager')
    else:
        return redirect(url_for('routes.my_timesheet'))

@bp.route('/profile', methods=['GET', 'POST'])
@bp.route('/profile/<int:user_id>', methods=['GET', 'POST'])
@login_required
def profile(user_id=None):
    if user_id is None:
        user_id = current_user.id

    user = User.query.get_or_404(user_id)

    # Role update (admin only)
    if request.method == 'POST' and current_user.role == 'admin':
        new_role = request.form.get('new_role')
        user.role = new_role
        db.session.commit()
        flash(f'Role updated to {new_role}.', 'success')
        return redirect(url_for('routes.profile', user_id=user.id))

    # ✅ Fetch timesheets for this user
    timesheets = Timesheet.query.filter_by(user_id=user.id).all()

    return render_template('profile.html', user=user, timesheets=timesheets)



@bp.route('/timesheet', methods=['GET', 'POST'])
@login_required
def my_timesheet():
    form = TimesheetForm()
    form.project.choices = [(p.id, p.name) for p in Project.query.all()]
    form.jira_task.choices = [(t.id, t.task_code) for t in JiraTask.query.all()]

    if request.method == 'POST':
        if form.validate_on_submit():
            timesheet = Timesheet(
                user_id=current_user.id,
                week_number=form.week_number.data,
                project_id=form.project.data,
                jira_task_id=form.jira_task.data,
                mon=form.mon.data, tue=form.tue.data,
                wed=form.wed.data, thu=form.thu.data,
                fri=form.fri.data, sat=form.sat.data,
                sun=form.sun.data
            )
            db.session.add(timesheet)
            db.session.commit()
            flash('Timesheet submitted.', 'success')
            return redirect(url_for('routes.my_timesheet'))

    timesheets = Timesheet.query.filter_by(user_id=current_user.id).all()
    return render_template('timesheet.html', form=form, timesheets=timesheets, user=current_user)



@bp.route('/review/<int:user_id>')
@login_required
def review_timesheet(user_id):
    if current_user.role not in ['manager', 'admin']:
        flash('Access denied.', 'danger')
        return redirect(url_for('routes.dashboard'))
    user = User.query.get_or_404(user_id)
    timesheets = Timesheet.query.filter_by(user_id=user.id).all()
    return render_template('review_timesheet.html', user=user, timesheets=timesheets)

@bp.route('/approve/<int:timesheet_id>')
@login_required
def approve(timesheet_id):
    if current_user.role not in ['manager', 'admin']:
        flash('Access denied.', 'danger')
        return redirect(url_for('routes.dashboard'))
    ts = Timesheet.query.get_or_404(timesheet_id)
    ts.status = 'Approved'
    db.session.commit()
    flash('Timesheet approved.', 'success')
    return redirect(url_for('routes.review_timesheet', user_id=ts.user_id))

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('routes.login'))

@bp.route('/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('index'))

    users = User.query.filter(User.role != 'admin').all()

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        new_role = request.form.get('new_role')
        user = User.query.get(user_id)

        if user and new_role in ['employee', 'manager']:
            user.role = new_role
            db.session.commit()
            flash(f'{user.name} is now a {user.role}.', 'success')
        else:
            flash('Invalid role or user.', 'danger')

        return redirect(url_for('manage_users'))

    return render_template('manage_users.html', users=users)

@bp.route('/edit_timesheet/<int:timesheet_id>', methods=['GET', 'POST'])
@login_required
def edit_timesheet(timesheet_id):
    timesheet = Timesheet.query.get_or_404(timesheet_id)

    # Ensure user can only edit their own pending timesheets
    if timesheet.user_id != current_user.id or timesheet.status != 'Pending':
        flash('You are not authorized to edit this timesheet.', 'danger')
        return redirect(url_for('routes.timesheet'))

    form = TimesheetForm(obj=timesheet)

    if form.validate_on_submit():
        form.populate_obj(timesheet)
        db.session.commit()
        flash('Timesheet updated successfully.', 'success')
        return redirect(url_for('routes.timesheet'))

    return render_template('edit_timesheet.html', form=form)

@bp.route('/update-timesheet/<int:timesheet_id>', methods=['POST'])
@login_required
def update_timesheet(timesheet_id):
    timesheet = Timesheet.query.get_or_404(timesheet_id)

    # Ensure the current user owns the timesheet
    if timesheet.user_id != current_user.id:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('routes.my_timesheet'))

    if timesheet.status != 'Pending':
        flash("You cannot update an approved or rejected timesheet.", "warning")
        return redirect(url_for('routes.my_timesheet'))

    # Get form data safely
    try:
        timesheet.project_name = request.form.get('project_name', timesheet.project_name)
        timesheet.jira_task = request.form.get('jira_task', timesheet.jira_task)

        timesheet.mon = float(request.form.get('mon', 0))
        timesheet.tue = float(request.form.get('tue', 0))
        timesheet.wed = float(request.form.get('wed', 0))
        timesheet.thu = float(request.form.get('thu', 0))
        timesheet.fri = float(request.form.get('fri', 0))
        timesheet.sat = float(request.form.get('sat', 0))
        timesheet.sun = float(request.form.get('sun', 0))

        db.session.commit()
        flash("Timesheet updated successfully!", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error updating timesheet: {str(e)}", "danger")

    return redirect(url_for('routes.my_timesheet'))



@bp.route('/delete_timesheet/<int:timesheet_id>', methods=['POST'])
@login_required
def delete_timesheet(timesheet_id):
    timesheet = Timesheet.query.get_or_404(timesheet_id)

    if timesheet.user_id != current_user.id:
        flash("You are not authorized to delete this timesheet.", "danger")
        return redirect(url_for('routes.my_timesheet'))

    if timesheet.status != 'Pending':
        flash("Only Pending timesheets can be deleted.", "warning")
        return redirect(url_for('routes.my_timesheet'))

    db.session.delete(timesheet)
    db.session.commit()
    flash("Timesheet deleted successfully.", "success")
    return redirect(url_for('routes.my_timesheet'))