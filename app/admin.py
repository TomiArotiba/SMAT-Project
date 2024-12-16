from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from app.models import User, Report
from app import db

admin = Blueprint('admin', __name__)

# Custom decorator to restrict access to admin users
def admin_required(func):
    @login_required
    def wrapper(*args, **kwargs):
        if current_user.role != 'admin':
            flash("Access restricted to admin users.", "danger")
            return redirect(url_for('main.index'))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

# Admin dashboard route
@admin.route('/admin')
@admin_required
def admin_dashboard():
    users = User.query.all()  # Fetch all users
    return render_template('admin_dashboard.html', users=users)

# View user details route
@admin.route('/admin/user/<int:user_id>')
@admin_required
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('view_user.html', user=user)

# Delete user account route
@admin.route('/admin/user/<int:user_id>/delete', methods=['GET', 'POST'])
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        flash("Admins cannot delete their account.", "danger")
        return redirect(url_for('admin.admin_dashboard'))

    # Delete user and their reports
    if request.method == 'POST':
        for report in user.reports:
            db.session.delete(report)
        db.session.delete(user)
        db.session.commit()
        flash("User deleted successfully.", "success")
        return redirect(url_for('admin.admin_dashboard'))
    
    return render_template('delete_user.html', user=user)
