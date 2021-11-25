from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, current_app, session
from flask_login import login_required
from .models import Product, CustomerOrder
from . import db
import os, os.path	
import json
from flask_principal import Permission, RoleNeed
import uuid

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
		customer_order = db.session.query(CustomerOrder).group_by(CustomerOrder.invoice).filter_by(order_status = 'Pending').all()
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
		# print("THIS IS PRINTED", customer_order[0].product_id)
		return jsonify(rows_dic1)
	#return render_template('orders.html')


@orders.route('/orders-fulfillment/<id>/<status>', methods=['GET', 'POST'])
@login_required
@admin_permission.require(http_exception=403)
def order_fulfillment(id, status):
	order = CustomerOrder.query.get(id)
	order.order_status = status
	
	if status == 'Fulfilled':
		order_qty = order.order_qty
		product = Product.query.get(order.product_id)
		product.product_qty = product.product_qty - order_qty
	#elif status == 'Cancel':


	db.session.commit()
	return redirect(request.referrer)

@orders.route('/orders-details/<invoice>', methods=['GET', 'POST'])
@login_required
@admin_permission.require(http_exception=403)
def get_order_detail(invoice):	
	#formdata = json.loads(request.data)
	#anon_user_id = formdata['anon_user_id']
	#anon_user_id = request.json['anon_user_id']

	if request.method == 'GET':
		order_details = db.session.query(CustomerOrder, Product)\
		.filter_by(invoice = invoice, order_status = 'Pending')\
		.join(Product, Product.id == CustomerOrder.product_id).all()

		#json_object = json.dumps(order_details, cls=AlchemyEncoder)
	# 	column_keys1 = CustomerOrder.__table__.columns.keys()
	# 	print(order_details)
    # # Temporary dictionary to keep the return value from table
	# 	rows_dic_temp1 = {}
	# 	rows_dic1 = []
    # # Iterate through the returned output data set
	# 	for row1 in order_details[0]:
	# 		for col1 in column_keys1:
	# 			# if column_keys1 == CustomerOrder.product_id:
	# 			rows_dic_temp1[col1] = getattr(row1, col1)
	# 		rows_dic1.append(rows_dic_temp1)
	# 		rows_dic_temp1= {}
	# 	print(rows_dic1)

		return render_template('order_detail.html', order_details = order_details)

# @orders.route('/order-now', methods=['GET', 'POST'])
# def order_now():

# 	return render_template('order_detail.html', order_details = order_details)

def my_random_string(string_length=10):
    """Returns a random string of length string_length."""
    random = str(uuid.uuid4()) # Convert UUID format to a Python string.
    random = random.upper() # Make all characters uppercase.
    random = random.replace("-","") # Remove the UUID '-'.
    return random[0:string_length] # Return the random string.

@orders.route('/order-now', methods=['GET', 'POST'])
def order_now():
	if request.method == "POST" and 'cart' in session:
		formdata = json.loads(request.data)
		formdata['anonymous_user_id'] = session['anonymous_user_id']
		formdata['invoice'] = my_random_string(7)
		
		#from_cart = json.loads(session['cart'])
	
		#print(json.dumps(c))

		for key, product in session['cart'].items():
			d = {**formdata, **product}
			d.pop('paymentMethod')
			d.pop('product_price')
			d.pop('product_title')
			d.pop('product_qty')
			print(d)

			new_customer_order = CustomerOrder(**d)

			db.session.add(new_customer_order)
			db.session.flush()
			db.session.commit()
			
			
			print(d)
		session.pop('cart')
		return jsonify({})
	else:
		return 'forbidden', 403

@orders.route('/orders-fulfilled-canceled', methods=['GET', 'POST'])
def orders_fulfilled_canceled():
	if request.method ==  "POST":
		pass
	elif request.method == "GET":
		order_details = db.session.query()\
		.filter(CustomerOrder.order_status == 'Canceled')

		order_details = db.session.query()\
		.filter(CustomerOrder.order_status == 'Fulfilled')


		order_details = db.session.query(CustomerOrder, Product)\
		.join(Product, Product.id == CustomerOrder.product_id)

		result = order_details.all()
		print(result)
		
		return render_template('orders-fulfilled-canceled.html', order_details = result)
	return jsonify({})