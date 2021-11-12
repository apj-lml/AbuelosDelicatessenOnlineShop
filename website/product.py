from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, current_app, session, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_login import current_user, login_user, logout_user, login_required
from datetime import datetime, date
from .models import Product, CustomerOrder, Link, ProductImage
from . import db
import os, os.path
import json
import time

from flask_principal import Principal, Permission, RoleNeed

ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

product = Blueprint('product', __name__)
admin_permission = Permission(RoleNeed('admin'))

@product.errorhandler(403)
def page_not_found(e):
	session['redirected_from'] = request.url
	return redirect(url_for('auth.login'))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@product.route('add-product', methods=['GET', 'POST'])
@login_required
@admin_permission.require(http_exception=403)
def add_product():
    print("SOMETHING")
    if request.method == 'POST':
        #formdata = json.loads(request.data)
        formdata = request.form.to_dict()
        print(request.files['product_images[]'])
        if formdata['add_or_update'] == 'add':

            formdata.pop('add_or_update')
            formdata.pop('product_id')

            formdata['user_id'] = current_user.id
            new_product = Product(**formdata)

            db.session.add(new_product)
            db.session.flush()
            db.session.commit()

            #------------------this is for file upload--------------
            final_name = ''
            for afile in request.files:
                file = request.files[afile]

                print(f'print file: {afile}')
                if afile not in request.files:
                    print('No file selected part')
                    return redirect(request.url)

                if not file and allowed_file(file.filename):
                    print('Invalid file submitted')
                    return redirect(request.url)
                else:
                    milliseconds = int(round(time.time() * 1000))
                    file_extension = file.filename.rsplit('.', 1)[1].lower()
                    file_name = file.filename.rsplit('.', 1)[0]
                    final_name = secure_filename(formdata['product_title'] +'_' + str(milliseconds) +'.'+file_extension)
                    if os.path.isfile(current_app.config['UPLOAD_FOLDER']):
                        print('path does not exist... creating path')
                        os.mkdir(current_app.config['UPLOAD_FOLDER'])
                    else:
                        print('path exist!')
                        file.save(os.path.join(current_app.config['UPLOAD_FOLDER'], final_name))

                        #saving upload info to database
                        files_to_upload = ProductImage(image_path = '\\static\\img\\product_images\\'+final_name, file_tag = afile, user_id = new_product.id)
                        db.session.add(files_to_upload)
                        db.session.commit()
        #------------------end of file upload--------------------
        else:
            product = Product.query.get(formdata['product_id'])
            product.product_title = formdata['product_title']
            product.product_description = formdata['product_description']
            product.product_price = formdata['product_price']
            product.product_qty = formdata['product_qty']
            product.product_category = formdata['product_category']

            db.session.commit()

        return 'ok', 200
    return render_template('dashboard.html')

@product.route('product-order', methods=['GET', 'POST'])
@login_required
@admin_permission.require(http_exception=403)
def product_order():

    co = db.session.query(CustomerOrder, Product).filter(Link.product_id == Product.id, Link.order_id == CustomerOrder.id).all()
    for x in co:
        print ("Customer: {} Product: {}".format(x.CustomerOrder.last_name, x.Product.product_title))
    if co:
        print(co)
    else:
        print('----- NO CO SELECTED -----')
    return 'ok', 200

@product.route('product-get', methods=['GET', 'POST'])
# @login_required
# @admin_permission.require(http_exception=403)
def product_get():

    #products = Product.as_dict(Product.query().all())
    if request.method == 'GET':
        products = db.session.query(Product).all()
        column_keys = Product.__table__.columns.keys()
    # Temporary dictionary to keep the return value from table
        rows_dic_temp = {}
        rows_dic = []
    # Iterate through the returned output data set
        for row in products:
            for col in column_keys:
                rows_dic_temp[col] = getattr(row, col)
            rows_dic.append(rows_dic_temp)
            rows_dic_temp= {}
        return jsonify(rows_dic)
    else:
        formdata = json.loads(request.data)
        product_id = formdata['id']
        products = Product.query.get(product_id)
        result = products.to_dict()
        print(result)
        return jsonify(result)

@product.route('product-delete', methods=['GET', 'POST'])
@login_required
@admin_permission.require(http_exception=403)
def product_delete():
    formdata = json.loads(request.data)
    product_id = formdata['product_id']
    product = Product.query.get(product_id)
    if product:
        db.session.delete(product)
        db.session.commit()
        return jsonify({})
    else:
        print('deteltion failed')

    # print(products)
    # return jsonify({})