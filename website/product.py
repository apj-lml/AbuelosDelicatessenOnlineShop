from flask import Blueprint, render_template, request, redirect, url_for, jsonify, current_app, session
from werkzeug.utils import secure_filename
from flask_login import current_user, login_required
from .models import Product, ProductImage
from . import db
import os, os.path
import json
import time

from flask_principal import Principal, Permission, RoleNeed

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

product = Blueprint('product', __name__)
admin_permission = Permission(RoleNeed('admin'))

@product.errorhandler(403)
def page_not_found(e):
	session['redirected_from'] = request.url
	return redirect(url_for('auth.login'))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@product.route('add-product-images', methods=['GET', 'POST'])
@login_required
@admin_permission.require(http_exception=403)
def add_product_images():
    
    formdata = request.form.to_dict()
    final_name = ''
    items = request.files.getlist("product_images[]")

    print(formdata)
    for afile in items:
        print(afile.filename)

        if not afile and allowed_file(afile.filename):
            print('Invalid file submitted')
            return redirect(request.url)
        else:
            milliseconds = int(round(time.time() * 1000))
            file_extension = afile.filename.rsplit('.', 1)[1].lower()
            file_name = afile.filename.rsplit('.', 1)[0]
            final_name = secure_filename(formdata['images_product_title'] +'_' + str(milliseconds) +'.'+file_extension)
            print('file name: ', file_name)
            if os.path.isfile(current_app.config['UPLOAD_FOLDER']):
                print('path does not exist... creating path')
                os.mkdir(current_app.config['UPLOAD_FOLDER'])
            else:
                print('path exist!')
                afile.save(os.path.join(current_app.config['UPLOAD_FOLDER'], final_name))

                #saving upload info to database
                files_to_upload = ProductImage(image_path = '\\static\\img\\product_images\\'+final_name, file_name = final_name, product_id = formdata['images_product_id'])
                db.session.add(files_to_upload)
                db.session.commit()
    return jsonify({})

@product.route('remove-product-images', methods=['GET', 'POST'])
@login_required
@admin_permission.require(http_exception=403)
def remove_product_images():

    formdata = json.loads(request.data)
    image_id = formdata['image_id']
    product_image = ProductImage.query.get(image_id)
    if product_image:
        db.session.delete(product_image)
        db.session.commit()
        return jsonify({})
    else:
        print('deteltion failed')

    return jsonify({})

@product.route('add-product', methods=['GET', 'POST'])
@login_required
@admin_permission.require(http_exception=403)
def add_product():

    if request.method == 'POST':
        #formdata = json.loads(request.data)
        formdata = request.form.to_dict()

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
            items = request.files.getlist("product_images[]")

            for afile in items:
                print(afile.filename)

                if not afile and allowed_file(afile.filename):
                    print('Invalid file submitted')
                    return redirect(request.url)
                else:
                    milliseconds = int(round(time.time() * 1000))
                    file_extension = afile.filename.rsplit('.', 1)[1].lower()
                    file_name = afile.filename.rsplit('.', 1)[0]
                    final_name = secure_filename(formdata['product_title'] +'_' + str(milliseconds) +'.'+file_extension)
                    print('file name: ', file_name)
                    if os.path.isfile(current_app.config['UPLOAD_FOLDER']):
                        print('path does not exist... creating path')
                        os.mkdir(current_app.config['UPLOAD_FOLDER'])
                    else:
                        print('path exist!')
                        afile.save(os.path.join(current_app.config['UPLOAD_FOLDER'], final_name))

                        #saving upload info to database
                        files_to_upload = ProductImage(image_path = '\\static\\img\\product_images\\'+final_name, file_name = final_name, product_id = new_product.id)
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

        #return 'ok', 200
    return render_template('dashboard.html')

@product.route('product-get', methods=['GET', 'POST'])
# @login_required
# @admin_permission.require(http_exception=403)
def product_get():

    #products = Product.as_dict(Product.query().all())
    if request.method == 'GET':
        products = db.session.query(Product).all()
    #     column_keys = Product.__table__.columns.keys()
    # # Temporary dictionary to keep the return value from table
        rows_dic_temp = {}
        rows_dic = []
    # # Iterate through the returned output data set
    #     for row in products:
    #         for col in column_keys:
    #             rows_dic_temp[col] = getattr(row, col)
    #         rows_dic.append(rows_dic_temp)
    #         rows_dic_temp= {}

        for item in products:
            #print(item.to_dict())
            rows_dic.append(item.to_dict())
        #result = products.to_dict()
        return jsonify(rows_dic)
    else:
        formdata = json.loads(request.data)
        
        if 'page' in formdata:
            products = db.session.query(Product).filter(Product.product_qty > 0).all()
            rows_dic = []
            for item in products:
            #print(item.to_dict())
                rows_dic.append(item.to_dict())
            return jsonify(rows_dic)
        else:
            product_id = formdata['id']
            products = Product.query.get(product_id)
        result = products.to_dict()
       # print(result)
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
        print('deletion failed')

    # print(products)
    # return jsonify({})
