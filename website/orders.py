from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, current_app, session, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import current_user, login_user, logout_user, login_required
from datetime import datetime, date
from .models import Product, CustomerOrder
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
def index():
	return render_template('orders.html')

@orders.route('/orders-get', methods=['GET', 'POST'])
@login_required
@admin_permission.require(http_exception=403)
def get_orders():
	if request.method == 'GET':
		customer_order = db.session.query(CustomerOrder).group_by(CustomerOrder.anonymous_user_id, CustomerOrder.timestamp).all()
		column_keys1 = CustomerOrder.__table__.columns.keys()
    # Temporary dictionary to keep the return value from table
		rows_dic_temp1 = {}
		rows_dic1 = []
    # Iterate through the returned output data set
		for row1 in customer_order:
			for col1 in column_keys1:
				rows_dic_temp1[col1] = getattr(row1, col1)
			rows_dic1.append(rows_dic_temp1)
			rows_dic_temp1= {}
		print("THIS IS PRINTED", customer_order[0].product_id)
		return jsonify(rows_dic1)
	#return render_template('orders.html')

@orders.route('/order-now', methods=['GET', 'POST'])
def order_now():
	if request.method ==  "POST":
		formdata = json.loads(request.data)
		formdata['anonymous_user_id'] = session['anonymous_user_id']
		print(formdata)
		#from_cart = json.loads(session['cart'])
	
		#print(json.dumps(c))

		for key, product in session['cart'].items():
			d = {**formdata, **product}
			d.pop('paymentMethod')
			d.pop('product_price')
			d.pop('product_title')


			new_customer_order = CustomerOrder(**d)

			db.session.add(new_customer_order)
			db.session.flush()
			db.session.commit()

			print(d)
	return jsonify({})
