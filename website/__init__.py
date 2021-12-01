from flask import Flask
from flask_login import LoginManager, current_user
from werkzeug.security import generate_password_hash
from flask_sqlalchemy import SQLAlchemy
from os import path
import os
from flask_principal import identity_loaded, Principal, UserNeed, RoleNeed

db = SQLAlchemy()

#DB_NAME = 'abuelosdelicatessen_database.db'
#DB_NAME = 'abuelosdelicatessen_database'
#DB_USER = 'root'

#pyhtonanywhere setup
DB_USER = 'abuelosdelicates'
DB_NAME = 'abuelosdelicates$abuelosdelicatessen_database'

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(APP_ROOT, 'static', 'img/product_images/')

def create_app():
	app = Flask(__name__)
	app.config['SECRET_KEY'] = 'random secret key xyz 123'
	#sqlite-connector
	#app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
	
	#mysql-local-connector
	#app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USER}:rootpassword@localhost/{DB_NAME}'

	#pythonanywhere-mysql-connector
	app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql+pymysql://{DB_USER}:rootpassword@abuelosdelicatessen.mysql.pythonanywhere-services.com/{DB_NAME}'

	app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
	db.init_app(app)
	
	from .auth import auth
	from .views import views
	from .product import product
	from .orders import orders
	from .cart import carts


	app.register_blueprint(views, url_prefix = '/')
	app.register_blueprint(auth, url_prefix = '/auth')
	app.register_blueprint(product, url_prefix = '/product')
	app.register_blueprint(orders, url_prefix = '/orders')
	app.register_blueprint(carts, url_prefix = '/carts')


	from . models import User, Product, ProductImage, CustomerOrder

	create_database(app)

	login_manager = LoginManager()
	login_manager.login_view = 'auth.login'
	login_manager.init_app(app)

	@login_manager.user_loader
	def load_user(id):
		return User.query.get(int(id))

	principals = Principal()
	principals.init_app(app)

	@identity_loaded.connect_via(app)
	def on_identity_loaded(sender, identity):
		identity.user = current_user
		if hasattr(current_user, 'id'):
			identity.provides.add(UserNeed(current_user.id))
		if hasattr(current_user, 'role'):
			identity.provides.add(RoleNeed(str(current_user.role)))

	return app

def create_database(app):
	#if not path.exists('website/'+DB_NAME):
	with app.app_context():
		db.create_all()
		from website.models import User
		user = User.query.filter_by(email='admin@admin').first()
		if not user:
			admin_user = User(name = 'Store Owner', email = 'admin@admin', password = generate_password_hash('admin'), last_name='admin', first_name = 'admin', middle_name = 'admin', name_extn = 'admin', address = 'admin', role = 'admin')
			db.session.add(admin_user)
			db.session.commit()
		print('database created')
