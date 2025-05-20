from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from app.models import db, User, Formulir
from functools import wraps

admin = Blueprint('admin', __name__)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@admin.route('/dashboard')
@login_required
@admin_required
def dashboard():
    users = User.query.filter_by(role='user').all()
    pending_forms = Formulir.query.join(User).filter(User.is_accepted.is_(None)).all()
    accepted_forms = Formulir.query.join(User).filter(User.is_accepted.is_(True)).all()
    rejected_forms = Formulir.query.join(User).filter(User.is_accepted.is_(False)).all()
    
    return render_template('admin/dashboard.html',
                         users=users,
                         pending_forms=pending_forms,
                         accepted_forms=accepted_forms,
                         rejected_forms=rejected_forms)

@admin.route('/review/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def review_application(user_id):
    try:
        user = User.query.get_or_404(user_id)
        action = request.form.get('action')
        
        if action == 'accept':
            user.is_accepted = True
            flash(f'Application for {user.username} has been accepted', 'success')
        elif action == 'reject':
            user.is_accepted = False
            flash(f'Application for {user.username} has been rejected', 'warning')
        else:
            flash('Invalid action', 'error')
            return redirect(url_for('admin.dashboard'))
        
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        flash(f'Error processing application: {str(e)}', 'error')
    
    return redirect(url_for('admin.dashboard'))