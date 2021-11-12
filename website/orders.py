from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, current_app, session, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import current_user, login_user, logout_user, login_required
from datetime import datetime, date
from .models import Product, CustomerOrder, Link
from . import db
import os, os.path
import json

from flask_principal import Principal, Permission, RoleNeed

orders = Blueprint('orders', __name__)
admin_permission = Permission(RoleNeed('admin'))

@orders.errorhandler(403)
def page_not_found(e):
	session['redirected_from'] = request.url
	return redirect(url_for('auth.login'))

@orders.route('/', methods=['GET', 'POST'])
@login_required
@admin_permission.require(http_exception=403)
def get_orders():

    return render_template('orders.html')
