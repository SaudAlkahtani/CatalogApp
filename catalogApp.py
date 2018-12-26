#!/usr/bin/env python2.7
from flask import Flask, render_template, request, redirect, url_for
from flask import jsonify, flash
from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from database_setup import Category, Item, User, Base
engine = create_engine('sqlite:///itemcatalog.db?check_same_thread=False')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Catalog Application"

app = Flask(__name__)


@app.route('/')
# main page, it will show the categories and latest added items
def displayCategories():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    Categories = session.query(Category).all()
    items = session.query(Item).order_by("id desc").limit(12).all()
    if login_session.get('logged_in') is not None:
        if login_session['logged_in']:
            return render_template('privateHtml.html',
                                   Categories=Categories, latest=items)
        else:
            return render_template('publicHtml.html', Categories=Categories,
                                   latest=items, STATE=login_session['state'])
    else:
        login_session['logged_in'] = False
        return redirect(url_for('displayCategories'))


# when the user is logged in , show him this page
@app.route('/private')
def privateHome():
    if 'username' not in login_session:
        flash('You have to be logged in to view this page!', category='danger')
        return redirect(url_for('displayCategories'))
    Categories = session.query(Category).all()
    items = session.query(Item).order_by("id desc").limit(11).all()
    flash('You are now logged in as %s' % login_session['email'],
          category='info')
    return render_template('privateHtml.html', Categories=Categories,
                           latest=items)


@app.route('/gconnect', methods=['POST'])
def gconnect():

    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('User already Connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['logged_in'] = True
    # check if new user exsits in database or add him
    check = session.query(User).filter_by(email=login_session['email']).first()
    if check is None:
        newUser = User(email=login_session['email'],
                       fullname=login_session['username'],
                       photo=login_session['picture'])
        session.add(newUser)
        session.commit()
    return redirect(url_for('privateHome'))


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'),
                                 401)
        response.headers['Content-Type'] = 'application/json'
        flash('You dont have token to deactivite!', category='danger')
        return redirect(url_for('displayCategories'))
    url = 'https://accounts.google.com/o/oauth2/revoke?token={token}'.format(
        token=login_session['access_token'])
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        login_session['logged_in'] = False
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash('Sucessfully logged out!', category='success')
        return redirect(url_for('displayCategories'))
    else:
        response = make_response(json.dumps('Failed to revoke token for user.',
                                 400))
        response.headers['Content-Type'] = 'application/json'
        flash('there was a problem when logging out!', category='warning')
        return redirect(url_for('displayCategories'))


@app.route('/Catalog/json')
def catalogJSON():
    Categories = session.query(Category).all()
    info = {}
    info['Category'] = [c.serialize for c in Categories]

    for c in info['Category']:
        items = session.query(Item).filter_by(catg_id=c['Id'])
        c['items'] = [i.serialize for i in items]

    return jsonify(info)


@app.route('/item/<id>')
def itemJSON(id):
    item = session.query(Item).filter_by(id=id).first()
    if item is None:
        flash('No item found with this id', category='warning')
        return redirect(url_for('displayCategories'))
    item = session.query(Item).filter_by(id=id).one()
    return jsonify(item.serialize)


@app.route('/Catalog/<title>/items')
def browseCategory(title):
    # show all items in Category
    AllCat = session.query(Category).all()
    Cat = session.query(Category).filter_by(title=title).first()
    items = session.query(Item).filter_by(catg_id=Cat.id).all()
    logged_in = login_session['logged_in']

    return render_template('items.html', Categories=AllCat, items=items,
                           Cat=Cat, logged_in=logged_in,
                           STATE=login_session['state'])


@app.route('/Catalog/<cat>/<item>')
def ItemInfo(cat, item):
    # show 1 item info
    it = session.query(Item).filter_by(id=item).one()
    if login_session['logged_in']:
        em = login_session['email']
        owner = session.query(User).filter_by(id=it.user_id).one()
        return render_template('itemInfo.html', item=it, owner=owner,
                               registered=em, log=login_session['logged_in'])
    else:
        return render_template('itemInfo.html', item=it,
                               log=login_session['logged_in'],
                               STATE=login_session['state'])


@app.route('/Catalog/<item>/edit', methods=['GET', 'POST'])
def editItem(item):
    if not login_session['logged_in']:
        flash('You must be logged in to edit items!', category='danger')
        return redirect(url_for('displayCategories'))
    registered = session.query(User).\
        filter_by(email=login_session['email']).one()
    editedItem = session.query(Item).filter_by(id=item).one()
    if not editedItem.user_id == registered.id:
        flash('You have to be the owner of the item to edit it!',
              category='warning')
        return redirect(url_for('displayCategories'))
    oldCateg = session.query(Category).filter_by(id=editedItem.catg_id).one()
    if request.method == 'POST':
        if request.form['title']:
            editedItem.title = request.form['title']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['category'] != "nothing":
            newCat = session.query(Category).\
              filter_by(id=request.form['category']).one()
            editedItem.catg_id = newCat.id
        if request.form['category'] == "nothing":
            flash('Please choose new Category for the item!',
                  category='warning')
            return redirect(url_for('editItem', item=item))
        session.add(editedItem)
        session.commit()
        flash('Item was edited Succesfully!', category='success')
        return redirect(url_for('displayCategories'))

    else:
        it = session.query(Item).filter_by(id=item).first()
        cat = session.query(Category).all()
        return render_template('edititem.html', item=it,
                               categories=cat, oldCateg=oldCateg)


@app.route('/Catalog/<item>/delete', methods=['GET', 'POST'])
def deleteItem(item):
    if not login_session['logged_in']:
        flash('You must be logged in to delete items!', category='danger')
        return redirect(url_for('displayCategories'))
    registered = session.query(User).\
        filter_by(email=login_session['email']).one()
    itemToDelete = session.query(Item).filter_by(id=item).one()
    if not itemToDelete.user_id == registered.id:
        flash('You have to be the owner of the item to delete it!',
              category='warning')
        return redirect(url_for('displayCategories'))

    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit
        flash('Item was deleted Successfully!', category='success')
        return redirect(url_for('displayCategories'))
    else:
        return render_template('deleteItem.html', item=itemToDelete)


@app.route('/addNewItem', methods=['GET', 'POST'])
def addNewItem():
    categories = session.query(Category).all()
    if request.method == 'POST':
        if (request.form['title'] and request.form['description'] and
                request.form['category'] != "nothing"):
            # if all the fields are filled
            user1 = session.query(User). \
                filter_by(email=login_session['email']).one()
            newItem = Item(title=request.form['title'],
                           description=request.form['description'],
                           catg_id=request.form['category'], user_id=user1.id)
            session.add(newItem)
            session.commit
            flash('Item was added Successfully!', category='success')
            return redirect(url_for('displayCategories'))
        else:
            flash('please provide all the info!', category='warning')
            return render_template('addNewItem.html', categories=categories)
    else:
        if login_session['logged_in']:
            return render_template('addNewItem.html', categories=categories)
        else:
            flash('You must be logged in to add new items!', category='danger')
            return redirect(url_for('displayCategories'))

# this method is used to clear your tokens and info if you have
# problems logging out


@app.route('/forceLogout')
def forceLogout():
    del login_session['access_token']
    del login_session['gplus_id']
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    login_session['logged_in'] = False
    return redirect(url_for('displayCategories'))

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
