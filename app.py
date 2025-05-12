from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import re
import os
from dotenv import load_dotenv
import logging
from functools import wraps
import csv
from io import StringIO
from flask import send_file

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()

app = Flask(__name__, 
    template_folder='templates',
    instance_path=os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance'),
    instance_relative_config=True)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    description = db.Column(db.String(200))
    users = db.relationship('User', backref='role', lazy=True)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    last_name = db.Column(db.String(50))
    first_name = db.Column(db.String(50), nullable=False)
    middle_name = db.Column(db.String(50))
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    visit_logs = db.relationship('VisitLog', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self):
        return self.role and self.role.name == 'Администратор'

class VisitLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

def check_rights(required_rights):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('У вас недостаточно прав для доступа к данной странице.')
                return redirect(url_for('index'))
            
            if current_user.is_admin:
                return f(*args, **kwargs)
            
            if 'view_own_profile' in required_rights and kwargs.get('user_id') == current_user.id:
                return f(*args, **kwargs)
            
            if 'edit_own_profile' in required_rights and kwargs.get('user_id') == current_user.id:
                return f(*args, **kwargs)
            
            flash('У вас недостаточно прав для доступа к данной странице.')
            return redirect(url_for('index'))
        return decorated_function
    return decorator

@app.before_request
def log_visit():
    if request.endpoint and 'static' not in request.endpoint:
        visit_log = VisitLog(
            path=request.path,
            user_id=current_user.id if current_user.is_authenticated else None
        )
        db.session.add(visit_log)
        db.session.commit()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def validate_password(password):
    if len(password) < 8 or len(password) > 128:
        return False, "Password must be between 8 and 128 characters"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit"
    if re.search(r'\s', password):
        return False, "Password cannot contain spaces"
    if not re.match(r'^[a-zA-Zа-яА-Я0-9~!?@#$%^&*_\-+()\[\]{}><\/\\|"\'\.,:;]+$', password):
        return False, "Password contains invalid characters"
    return True, ""

@app.route('/')
def index():
    users = User.query.all()
    return render_template('index.html', users=users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        user = User.query.filter_by(login=login).first()
        
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid login or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/user/<int:user_id>')
@login_required
@check_rights(['view_own_profile'])
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('view_user.html', user=user)

@app.route('/user/new', methods=['GET', 'POST'])
@login_required
@check_rights(['create_user'])
def create_user():
    if not current_user.is_admin:
        flash('У вас недостаточно прав для доступа к данной странице.')
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        middle_name = request.form.get('middle_name')
        role_id = request.form.get('role_id')

        if not login or not password or not first_name:
            flash('Required fields cannot be empty')
            return render_template('user_form.html', roles=Role.query.all())

        if not re.match(r'^[a-zA-Z0-9]{5,}$', login):
            flash('Login must be at least 5 characters long and contain only Latin letters and numbers')
            return render_template('user_form.html', roles=Role.query.all())

        is_valid, message = validate_password(password)
        if not is_valid:
            flash(message)
            return render_template('user_form.html', roles=Role.query.all())

        user = User(
            login=login,
            first_name=first_name,
            last_name=last_name,
            middle_name=middle_name,
            role_id=role_id if role_id else None
        )
        user.set_password(password)

        try:
            db.session.add(user)
            db.session.commit()
            flash('User created successfully')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Error creating user')
            return render_template('user_form.html', roles=Role.query.all())

    return render_template('user_form.html', roles=Role.query.all())

@app.route('/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
@check_rights(['edit_own_profile'])
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Regular users can only edit their own profile and cannot change their role
    if not current_user.is_admin and current_user.id != user_id:
        flash('У вас недостаточно прав для доступа к данной странице.')
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        middle_name = request.form.get('middle_name')
        role_id = request.form.get('role_id')

        if not first_name:
            flash('First name cannot be empty')
            return render_template('user_form.html', user=user, roles=Role.query.all())

        user.first_name = first_name
        user.last_name = last_name
        user.middle_name = middle_name
        
        # Only admin can change role
        if current_user.is_admin:
            user.role_id = role_id if role_id else None

        try:
            db.session.commit()
            flash('User updated successfully')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating user')
            return render_template('user_form.html', user=user, roles=Role.query.all())

    return render_template('user_form.html', user=user, roles=Role.query.all())

@app.route('/user/<int:user_id>/delete', methods=['POST'])
@login_required
@check_rights(['delete_user'])
def delete_user(user_id):
    if not current_user.is_admin:
        flash('У вас недостаточно прав для доступа к данной странице.')
        return redirect(url_for('index'))
        
    user = User.query.get_or_404(user_id)
    try:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully')
    except Exception as e:
        db.session.rollback()
        flash('Error deleting user')
    return redirect(url_for('index'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        old_password = request.form.get('old_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if not current_user.check_password(old_password):
            flash('Current password is incorrect')
            return render_template('change_password.html')

        if new_password != confirm_password:
            flash('New passwords do not match')
            return render_template('change_password.html')

        is_valid, message = validate_password(new_password)
        if not is_valid:
            flash(message)
            return render_template('change_password.html')

        current_user.set_password(new_password)
        try:
            db.session.commit()
            flash('Password changed successfully')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash('Error changing password')
            return render_template('change_password.html')

    return render_template('change_password.html')

@app.route('/visit-logs')
@login_required
def visit_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    if current_user.is_admin:
        logs = VisitLog.query.order_by(VisitLog.created_at.desc()).paginate(page=page, per_page=per_page)
    else:
        logs = VisitLog.query.filter_by(user_id=current_user.id).order_by(VisitLog.created_at.desc()).paginate(page=page, per_page=per_page)
    
    return render_template('visit_logs.html', logs=logs)

@app.route('/visit-logs/by-page')
@login_required
def visit_logs_by_page():
    if not current_user.is_admin:
        flash('У вас недостаточно прав для доступа к данной странице.')
        return redirect(url_for('index'))
        
    page_stats = db.session.query(
        VisitLog.path,
        db.func.count(VisitLog.id).label('count')
    ).group_by(VisitLog.path).order_by(db.desc('count')).all()
    
    return render_template('visit_logs_by_page.html', page_stats=page_stats)

@app.route('/visit-logs/by-user')
@login_required
def visit_logs_by_user():
    if not current_user.is_admin:
        flash('У вас недостаточно прав для доступа к данной странице.')
        return redirect(url_for('index'))
        
    user_stats = db.session.query(
        User,
        db.func.count(VisitLog.id).label('count')
    ).outerjoin(VisitLog).group_by(User.id).order_by(db.desc('count')).all()
    
    return render_template('visit_logs_by_user.html', user_stats=user_stats)

@app.route('/visit-logs/by-page/export')
@login_required
def export_visit_logs_by_page():
    if not current_user.is_admin:
        flash('У вас недостаточно прав для доступа к данной странице.')
        return redirect(url_for('index'))
        
    page_stats = db.session.query(
        VisitLog.path,
        db.func.count(VisitLog.id).label('count')
    ).group_by(VisitLog.path).order_by(db.desc('count')).all()
    
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Страница', 'Количество посещений'])
    for path, count in page_stats:
        cw.writerow([path, count])
    
    output = si.getvalue()
    si.close()
    
    return send_file(
        StringIO(output),
        mimetype='text/csv',
        as_attachment=True,
        download_name='visit_logs_by_page.csv'
    )

@app.route('/visit-logs/by-user/export')
@login_required
def export_visit_logs_by_user():
    if not current_user.is_admin:
        flash('У вас недостаточно прав для доступа к данной странице.')
        return redirect(url_for('index'))
        
    user_stats = db.session.query(
        User,
        db.func.count(VisitLog.id).label('count')
    ).outerjoin(VisitLog).group_by(User.id).order_by(db.desc('count')).all()
    
    si = StringIO()
    cw = csv.writer(si)
    cw.writerow(['Пользователь', 'Количество посещений'])
    for user, count in user_stats:
        user_name = f"{user.last_name or ''} {user.first_name} {user.middle_name or ''}".strip()
        cw.writerow([user_name or 'Неаутентифицированный пользователь', count])
    
    output = si.getvalue()
    si.close()
    
    return send_file(
        StringIO(output),
        mimetype='text/csv',
        as_attachment=True,
        download_name='visit_logs_by_user.csv'
    )

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logger.error(f"Internal Server Error: {error}")
    return render_template('error.html', error="Внутренняя ошибка сервера"), 500

@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error="Страница не найдена"), 404

with app.app_context():
    try:
        db.create_all()
        logger.info("Database tables created successfully")
    except Exception as e:
        logger.error(f"Error creating database tables: {e}")

if __name__ == '__main__':
    app.run(debug=True) 