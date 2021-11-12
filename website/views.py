from flask import Blueprint, render_template, request, flash, redirect, url_for
from flask_login import login_user, login_required, logout_user, current_user
views = Blueprint('views', __name__)

@views.route('/')
def index():
	return render_template('index.html')

@views.route('/dashboard')
@login_required
def dashboard():
	return render_template('dashboard.html')
