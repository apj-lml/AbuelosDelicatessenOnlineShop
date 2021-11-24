
from . import db
from flask_login import UserMixin
from sqlalchemy.sql import func
from sqlalchemy_serializer import SerializerMixin

class User(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key = True)
	name = db.Column(db.String(250))
	email = db.Column(db.String(100), unique = True)
	password = db.Column(db.String(250))
	last_name = db.Column(db.String(250))
	first_name = db.Column(db.String(250))
	middle_name = db.Column(db.String(250))
	name_extn = db.Column(db.String(250))
	address = db.Column(db.String(250))
	role = db.Column(db.String(100))
	product = db.relationship('Product')

class CustomerOrder(db.Model, SerializerMixin):
	id = db.Column(db.Integer, primary_key = True)
	anonymous_user_id = db.Column(db.String(250))
	invoice = db.Column(db.String(250))
	last_name = db.Column(db.String(250))
	first_name = db.Column(db.String(250))
	middle_name = db.Column(db.String(250))
	address = db.Column(db.String(250))
	#product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
	email_address = db.Column(db.String(250))
	contact_number = db.Column(db.String(50))
	order_qty = db.Column(db.Integer)
	order_status = db.Column(db.String(20), default='Pending', nullable = False)
	timestamp = db.Column(db.DateTime(timezone=True), default=func.now())
	#products = db.relationship('Product', secondary='link', backref=db.backref('orders'))
	product_id = db.Column(db.Integer, db.ForeignKey('product.id'))

# class Link (db.Model):
# 	order_id = db.Column(db.Integer, db.ForeignKey('customer_order.id'), primary_key = True)
# 	product_id = db.Column(db.Integer, db.ForeignKey('product.id'), primary_key = True)

class Product(db.Model, SerializerMixin):
	id = db.Column(db.Integer, primary_key = True)
	timestamp = db.Column(db.DateTime(timezone=True), default=func.now())
	product_title = db.Column(db.String(250))
	product_description = db.Column(db.String(250))
	product_price = db.Column(db.String(250))
	product_qty = db.Column(db.Integer)
	product_category = db.Column(db.String(250))
	product_special = db.Column(db.String(250), default='not spl')
	product_image = db.relationship('ProductImage')
	user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
	customer_orders = db.relationship('CustomerOrder')

	#customer_orders = db.relationship('CustomerOrder',secondary='link')
	#customer_order = db.Column(db.Integer, db.ForeignKey('customer_order.id'))
	
class ProductImage(db.Model, SerializerMixin):
	id = db.Column(db.Integer, primary_key = True)
	image_path = db.Column(db.String(250))
	file_name = db.Column(db.String(250))
	product_id = db.Column(db.Integer, db.ForeignKey('product.id'))

