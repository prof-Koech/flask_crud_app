# ──────────────────────────────────────────────────────────────
#  app.py  —  Flask CRUD | Auth | Email Confirmation | REST API
# ──────────────────────────────────────────────────────────────

from flask import (
    Flask, render_template, request,
    redirect, url_for, flash, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required,
    logout_user, current_user
)
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from datetime import datetime
# from dotenv import load_dotenv
# import os

# load_dotenv()

# app.config.update(
#     MAIL_USERNAME       = os.getenv('MAIL_USERNAME'),
#     MAIL_PASSWORD       = os.getenv('MAIL_PASSWORD'),
#     MAIL_DEFAULT_SENDER = os.getenv('MAIL_USERNAME'),
# )


# ── App & Config ───────────────────────────────────────────────

app = Flask(__name__)

app.config.update(
    SECRET_KEY                     = 'change-this-in-production',
    SQLALCHEMY_DATABASE_URI        = 'sqlite:///app.db',
    SQLALCHEMY_TRACK_MODIFICATIONS = False,

    # Flask-Mail (Gmail)
    MAIL_SERVER                    = 'smtp.gmail.com',
    MAIL_PORT                      = 587,
    MAIL_USE_TLS                   = True,
    MAIL_USERNAME                  = 'in4testpurposesonly@gmail.com',
    MAIL_PASSWORD                  = 'xatyrfvkvdzsndzl',
    MAIL_DEFAULT_SENDER            = 'in4testpurposesonly@gmail.com',
)

db            = SQLAlchemy(app)
mail          = Mail(app)
serializer    = URLSafeTimedSerializer(app.config['SECRET_KEY'])
login_manager = LoginManager(app)
login_manager.login_view             = 'login'
login_manager.login_message          = 'Please login to access this page.'
login_manager.login_message_category = 'error'


# ── Models ──────────────────────────────────────────────────────

class Admin(UserMixin, db.Model):
    """Authenticated admin accounts."""
    __tablename__ = 'admins'

    id            = db.Column(db.Integer,     primary_key=True)
    username      = db.Column(db.String(80),  unique=True, nullable=False)
    email         = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_verified   = db.Column(db.Boolean,     default=False)
    created_at    = db.Column(db.DateTime,    default=datetime.utcnow)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def __repr__(self) -> str:
        return f'<Admin {self.username}>'


class User(db.Model):
    """Managed user records (the CRUD resource)."""
    __tablename__ = 'users'

    id         = db.Column(db.Integer,     primary_key=True)
    name       = db.Column(db.String(100), nullable=False)
    email      = db.Column(db.String(120), unique=True, nullable=False)
    role       = db.Column(db.String(50),  default='user')
    created_at = db.Column(db.DateTime,    default=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            'id':         self.id,
            'name':       self.name,
            'email':      self.email,
            'role':       self.role,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }

    def __repr__(self) -> str:
        return f'<User {self.name}>'


@login_manager.user_loader
def load_user(user_id: str):
    return Admin.query.get(int(user_id))


# ── DB Init ────────────────────────────────────────────────────

with app.app_context():
    db.create_all()


# ── Email Helpers ──────────────────────────────────────────────

def send_confirmation_email(email: str) -> None:
    token = serializer.dumps(email, salt='email-confirm')
    link  = url_for('confirm_email', token=token, _external=True)
    msg   = Message('Confirm Your Email', recipients=[email])
    msg.body = (
        f'Hi there!\n\n'
        f'Please confirm your email by clicking the link below:\n\n'
        f'{link}\n\n'
        f'This link expires in 1 hour.\n\n'
        f'If you did not register, please ignore this email.'
    )
    mail.send(msg)


def send_password_reset_email(email: str) -> None:
    token = serializer.dumps(email, salt='password-reset')
    link  = url_for('reset_password', token=token, _external=True)
    msg   = Message('Password Reset Request', recipients=[email])
    msg.body = (
        f'Hi,\n\n'
        f'Click the link below to reset your password:\n\n'
        f'{link}\n\n'
        f'This link expires in 30 minutes.\n\n'
        f'If you did not request this, ignore this email.'
    )
    mail.send(msg)


# ══════════════════════════════════════════════════════════════
#  AUTH ROUTES
# ══════════════════════════════════════════════════════════════

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email',    '').strip()
        password = request.form.get('password', '').strip()

        if not all([username, email, password]):
            flash('All fields are required.', 'error')
            return render_template('register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('register.html')

        if Admin.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
            return render_template('register.html')

        if Admin.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return render_template('register.html')

        admin = Admin(username=username, email=email)
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()

        try:
            send_confirmation_email(email)
            flash('Account created! Check your email to confirm your account.', 'success')
        except Exception as e:
            flash(f'Account created but confirmation email failed: {e}', 'error')

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=3600)
    except SignatureExpired:
        flash('Confirmation link has expired. Please request a new one.', 'error')
        return redirect(url_for('resend_confirmation'))
    except BadSignature:
        flash('Invalid confirmation link.', 'error')
        return redirect(url_for('register'))

    admin = Admin.query.filter_by(email=email).first()

    if not admin:
        flash('Account not found.', 'error')
        return redirect(url_for('register'))

    if admin.is_verified:
        flash('Email already confirmed. Please login.', 'info')
    else:
        admin.is_verified = True
        db.session.commit()
        flash('Email confirmed successfully! You can now login.', 'success')

    return redirect(url_for('login'))


@app.route('/resend-confirmation', methods=['GET', 'POST'])
def resend_confirmation():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        admin = Admin.query.filter_by(email=email).first()

        if not admin:
            flash('No account found with that email.', 'error')
        elif admin.is_verified:
            flash('This email is already verified. Please login.', 'info')
        else:
            try:
                send_confirmation_email(email)
                flash('Confirmation email resent! Check your inbox.', 'success')
            except Exception as e:
                flash(f'Failed to send email: {e}', 'error')

        return redirect(url_for('login'))

    return render_template('resend_confirmation.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        admin    = Admin.query.filter_by(username=username).first()

        if not admin or not admin.check_password(password):
            flash('Invalid username or password.', 'error')
        elif not admin.is_verified:
            flash('Please confirm your email before logging in.', 'error')
        else:
            login_user(admin)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        admin = Admin.query.filter_by(email=email).first()

        if admin and admin.is_verified:
            try:
                send_password_reset_email(email)
            except Exception as e:
                flash(f'Failed to send reset email: {e}', 'error')
                return render_template('forgot_password.html')

        flash('If that email exists, a reset link has been sent.', 'info')
        return redirect(url_for('login'))

    return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset', max_age=1800)
    except SignatureExpired:
        flash('Reset link has expired. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))
    except BadSignature:
        flash('Invalid reset link.', 'error')
        return redirect(url_for('forgot_password'))

    admin = Admin.query.filter_by(email=email).first()
    if not admin:
        flash('Account not found.', 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        confirm  = request.form.get('confirm_password', '').strip()

        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return render_template('reset_password.html', token=token)

        if password != confirm:
            flash('Passwords do not match.', 'error')
            return render_template('reset_password.html', token=token)

        admin.set_password(password)
        db.session.commit()
        flash('Password reset successfully! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


# ══════════════════════════════════════════════════════════════
#  CRUD ROUTES  (protected — login required)
# ══════════════════════════════════════════════════════════════

@app.route('/')
@login_required
def index():
    search   = request.args.get('search', '').strip()
    page     = request.args.get('page', 1, type=int)
    per_page = 5

    query = User.query
    if search:
        like  = f'%{search}%'
        query = query.filter(
            User.name.ilike(like) | User.email.ilike(like)
        )

    pagination = query.order_by(User.id.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return render_template(
        'index.html',
        users      = pagination.items,
        pagination = pagination,
        search     = search,
    )


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        name  = request.form.get('name',  '').strip()
        email = request.form.get('email', '').strip()
        role  = request.form.get('role',  'user')

        if not name or not email:
            flash('Name and email are required.', 'error')
            return render_template('create.html')

        if User.query.filter_by(email=email).first():
            flash('A user with that email already exists.', 'error')
            return render_template('create.html')

        db.session.add(User(name=name, email=email, role=role))
        db.session.commit()
        flash('User created successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('create.html')


@app.route('/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit(user_id):
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        name  = request.form.get('name',  '').strip()
        email = request.form.get('email', '').strip()
        role  = request.form.get('role',  'user')

        if not name or not email:
            flash('Name and email are required.', 'error')
            return render_template('edit.html', user=user)

        duplicate = User.query.filter(
            User.email == email, User.id != user_id
        ).first()
        if duplicate:
            flash('That email is already used by another user.', 'error')
            return render_template('edit.html', user=user)

        user.name  = name
        user.email = email
        user.role  = role
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('edit.html', user=user)


@app.route('/delete/<int:user_id>', methods=['POST'])
@login_required
def delete(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash(f'User "{user.name}" has been deleted.', 'info')
    return redirect(url_for('index'))


# ══════════════════════════════════════════════════════════════
#  REST API ROUTES
# ══════════════════════════════════════════════════════════════

@app.route('/api/users', methods=['GET'])
def api_get_users():
    search   = request.args.get('search',   '').strip()
    page     = request.args.get('page',     1,  type=int)
    per_page = request.args.get('per_page', 10, type=int)

    query = User.query
    if search:
        like  = f'%{search}%'
        query = query.filter(
            User.name.ilike(like) | User.email.ilike(like)
        )

    pagination = query.order_by(User.id.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    return jsonify({
        'users':        [u.to_dict() for u in pagination.items],
        'total':        pagination.total,
        'pages':        pagination.pages,
        'current_page': page,
        'per_page':     per_page,
    })


@app.route('/api/users/<int:user_id>', methods=['GET'])
def api_get_user(user_id):
    return jsonify(User.query.get_or_404(user_id).to_dict())


@app.route('/api/users', methods=['POST'])
def api_create_user():
    data = request.get_json(silent=True)

    if not data:
        return jsonify({'error': 'Request body must be JSON.'}), 400

    name  = data.get('name',  '').strip()
    email = data.get('email', '').strip()
    role  = data.get('role',  'user')

    if not name or not email:
        return jsonify({'error': 'name and email are required.'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists.'}), 409

    user = User(name=name, email=email, role=role)
    db.session.add(user)
    db.session.commit()
    return jsonify(user.to_dict()), 201


@app.route('/api/users/<int:user_id>', methods=['PUT'])
def api_update_user(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json(silent=True)

    if not data:
        return jsonify({'error': 'Request body must be JSON.'}), 400

    if 'name' in data:
        user.name = data['name'].strip()

    if 'email' in data:
        new_email = data['email'].strip()
        duplicate = User.query.filter(
            User.email == new_email, User.id != user_id
        ).first()
        if duplicate:
            return jsonify({'error': 'Email already in use.'}), 409
        user.email = new_email

    if 'role' in data:
        user.role = data['role']

    db.session.commit()
    return jsonify(user.to_dict())


@app.route('/api/users/<int:user_id>', methods=['DELETE'])
def api_delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': f'User "{user.name}" deleted successfully.'})


# ── Error Handlers ─────────────────────────────────────────────

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Resource not found.'}), 404
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error.'}), 500
    return render_template('500.html'), 500


# ── Entry Point ────────────────────────────────────────────────

if __name__ == '__main__':
    app.run(debug=True)