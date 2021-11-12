from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, current_app, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import current_user, login_user, logout_user, login_required
from datetime import datetime, date
from .models import User
from . import db
import os, os.path
import json
from flask_principal import Principal, identity_changed, Identity, AnonymousIdentity

auth = Blueprint('auth', __name__)

@auth.errorhandler(403)
def page_not_found(e):
	session['redirected_from'] = request.url
	return redirect(url_for('auth.login'))


@auth.route('/login', methods=['GET', 'POST'])
def login():
	if request.method == 'POST':
		formdata = json.loads(request.data)
		email = formdata['login_email']
		password = formdata['login_password']

		user = User.query.filter_by(email=email).first()
		if user:
			if check_password_hash(user.password, password):
				flash('Login successful', category = 'success')
				login_user(user, remember = True)
				print("user has loggedin")
				if user.role == 'admin':
					identity_changed.send(current_app._get_current_object(),
                                  identity=Identity(user.id))
					return redirect(url_for('views.dashboard'))
			else:
				flash('Incorrect password, try again', category='error')
		else:
			flash('Email does not exist', category='error')
	return render_template('index.html', user=current_user)


@auth.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
	logout_user()
	for key in ('identity.name', 'identity.auth_type'):
		session.pop(key, None)
	identity_changed.send(current_app._get_current_object(), identity = AnonymousIdentity())

	return redirect(url_for('auth.login'))