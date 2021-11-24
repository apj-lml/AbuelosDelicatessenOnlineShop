from flask import Blueprint, render_template, session, redirect, url_for, jsonify, request
from .models import Product
from . import db
import json
import uuid
carts = Blueprint('cart', __name__)

@carts.route('/cs')
def cs():
    session.clear()
    return redirect(url_for('auth.login'))

def mergeDicts(dict1,dict2):
    if isinstance(dict1,dict) and isinstance(dict2,dict):
        return dict(list(dict1.items()) + list(dict2.items()))

@carts.route('/view-cart', methods=['GET', 'POST'])
def view_cart():
    #print(session['cart'])
    #return render_template('cart.html')
    return render_template('cart2.html')

@carts.route('/add-cart', methods=['GET', 'POST'])
def add_cart():

    formdata = json.loads(request.data)
    product_id = formdata['product_id']
    order_qty = formdata['order_qty']

    product = Product.query.filter_by(id = formdata["product_id"]).first()

    if request.method ==  "POST":
        session['anonymous_user_id'] = uuid.uuid4().hex
        dictItems = {product_id:{'product_id':product.id, 'product_title':product.product_title, 'product_price': product.product_price, 'product_qty': product.product_qty, 'order_qty': order_qty}}

        if 'cart' in session:
            if product_id in session['cart']:
                session.modified = True
                #print('value of order qty: '+ str(session['cart'][product_id]['order_qty']))
                new_qty = int(session['cart'][product_id]['order_qty'])+int(order_qty)
                
                if product_id in session['cart'].keys():
                    session['cart'][product_id].update({'order_qty':new_qty})

                    print(session['cart'])
            else:
                session['cart'] = mergeDicts(session['cart'], dictItems)
                print(session['cart'])
            return jsonify({})
        else:
            session['cart'] = dictItems
            return jsonify({})

@carts.route('/remove-item/<id>', methods=['GET', 'POST'])
def remove_item(id):
    session['cart'].pop(id)
    print(session['cart'])

    return redirect(request.referrer)