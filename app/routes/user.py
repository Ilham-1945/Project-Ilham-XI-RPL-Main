from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from app.models import db, Formulir

user = Blueprint('user', __name__)

@user.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('admin.dashboard'))
    return render_template('user/dashboard.html')

@user.route('/formulir', methods=['GET', 'POST'])
@login_required
def formulir():
    if current_user.formulir:
        flash('You have already submitted a form', 'warning')
        return redirect(url_for('user.dashboard'))

    if request.method == 'POST':
        try:
            formulir = Formulir(
                user_id=current_user.id,
                nama=request.form.get('nama'),
                alamat=request.form.get('alamat'),
                nilai=float(request.form.get('nilai'))
            )
            db.session.add(formulir)
            db.session.commit()
            flash('Form submitted successfully', 'success')
            return redirect(url_for('user.dashboard'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error submitting form: {str(e)}', 'error')
    
    return render_template('user/formulir.html')