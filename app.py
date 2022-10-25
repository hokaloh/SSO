from multiprocessing.connection import Client
from flask import Flask, render_template, request, session, flash, jsonify, make_response, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_mysqldb import MySQL
import MySQLdb.cursors
import json
import os
import re
import hashlib
import requests
from flask_httpauth import HTTPBasicAuth
import jwt
from datetime import datetime, timedelta
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] = 'Konohagakure'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'oauth'
 
mysql = MySQL(app)
auth = HTTPBasicAuth()



# manually create database and table  # 
#cursor.execute("CREATE TABLE users (id INT AUTO_INCREMENT PRIMARY KEY, , email VARCHAR(255), name VARCHAR(255), password VARCHAR(255))")
# describe <table>


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if 'x-access-tokens' in request.headers:
            token = request.headers['x-access-tokens']
        #token = request.args.get('token')
        if not token:
            return jsonify({'message': 'a valid token is missing'})
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])

        except Exception as e:
            print(e)
            return jsonify({'message': 'token is invalid'})
 
        return f(data,*args, **kwargs)
    return decorator


@app.route('/')
@app.route('/login', methods = ['POST', 'GET'])
def login():
    msg = ''
    if request.method == 'POST':
        email = request.form['email']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = % s AND password = % s', (email, password, ))
        user = cursor.fetchone()
        if user:
            session['loggedin'] = True
            session['id'] = user['id']
            session['email'] = user['email']
            msg = 'Logged in successfully !'
            token = jwt.encode({'user': user['name'],'exp' : datetime.utcnow() + timedelta(minutes = 30)}, app.config['SECRET_KEY'])
            r = make_response(render_template('index.html'))
            r.headers.set('x-access-tokens', token)
            return r
        else:
            msg = 'Incorrect username / password !'

    return render_template('login.html', msg = msg)

@app.route('/protected')
@token_required
def protected(data):
    print(data)
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute('SELECT * FROM users WHERE name = % s', (data['user'], ))
    current_user = cursor.fetchone()
    return data

@app.route('/konoha')
@token_required
def konoha(data):
    return data

@app.route('/registration', methods = ['POST', 'GET'])
def registration():
    msg=''
    if request.method == 'POST':
        name = request.form['username']
        email = request.form['email']   
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = % s',(email, ))

        # used when you want to select only the first row from the table, This method only returns the first row from the MySQL table
        user = cursor.fetchone()
        if user:
            msg = 'Account already exists!'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = 'Invalid email address!'
        elif not re.match(r'[A-Za-z0-9]+', name):
            msg = 'Username must contain only characters and numbers!'
        elif not name or not password or not email:
            msg = 'Please fill out the form!'
        else:
            cursor.execute('INSERT INTO users (email,name, password) VALUE (% s, % s, % s)', (email, name, password, ))
            mysql.connection.commit()
            msg = 'You have successfully registered !'

    elif request.method == 'POST':
        msg = 'Please fill out the form !'
    return render_template('registration.html', msg=msg)


@auth.verify_password
def verify_password(username, password):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    password = hashlib.sha256(password.encode()).hexdigest()
    if cursor.execute('SELECT * FROM users WHERE name = % s AND password = % s', (username, password, )):
        return cursor.fetchone()


@app.route('/api/auth/token')
@auth.login_required
def auth_token():
    user = auth.current_user()
    if user:
        token = jwt.encode({'user': user['name'],'exp' : datetime.utcnow() + timedelta(minutes = 10)}, app.config['SECRET_KEY'])
        return make_response(jsonify({'token' : token.decode('UTF-8')}), 201)

@app.route('/api/auth/register', methods=['POST'])
def auth_resgister():
    msg=''
    try:
        email = request.json.get("email")
        username = request.json.get("username")
        password = hashlib.sha256(request.json.get("password").encode()).hexdigest()
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = % s',(email, ))
        user = cursor.fetchone()
        print(cursor)

        if user:
            msg = {'Account':'Account already exists!'}
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = {'Email':'Invalid email address!'}
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = {'username':'Username must contain only characters and numbers!'}
        elif not username or not password or not email:
            msg = {'Please fill out the form!'}
        else:
            cursor.execute('INSERT INTO users (email,name, password) VALUE (% s, % s, % s)', (email, username, password, ))
            mysql.connection.commit()
            msg = {'account': f'successfully registered as {username}'}
    except: 
        msg = {'Format':'Invalid Format'}
    return jsonify(msg), 201

@app.route('/api/auth/delete', methods=['DELETE'])
@token_required
def auth_delete(data):
    msg=''
    try:
        email = request.json.get("email")
        username = request.json.get("username")
        password = hashlib.sha256(request.json.get("password").encode()).hexdigest()
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM users WHERE email = % s',(email, ))
        user = cursor.fetchone()
        if username == data['user']:
            cursor.execute('DELETE FROM users WHERE email = % s AND name = % s AND password= % s', (email, username, password, ))
            mysql.connection.commit()
            msg = {'Account':f'successfully delete user {username}'}
        else:
            msg={'Account':'Delete Not Invalid'}
    except Exception as e :
        print(e)
        msg = {'Format':'Invalid Format'}

    return jsonify(msg), 201

if __name__ == "__main__":
    app.run(debug=True)



