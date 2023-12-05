from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from sqlalchemy import create_engine
from flask_sqlalchemy import SQLAlchemy
from database import create_connection_string
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pandas as pd
import plotly.express as px
import random
import plotly.io as pio
import os


app = Flask(__name__)

# random secret generated from os module in python for session management

app.secret_key = 'b3aa0e719a713e06c410ad1f'

app.config['SQLALCHEMY_DATABASE_URI'] = create_connection_string()
# app.config['SQLALCHEMY_ECHO'] = True


db = SQLAlchemy(app)


class UserCredentials(db.Model):
    __tablename__ = 'usercredentials'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    age = db.Column(db.Integer, nullable=False)
    gender = db.Column(db.String, nullable=False)
    emergencycontactno = db.Column(db.String, nullable=False)
    createddate = db.Column(db.DateTime, nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey(
        'roles.roleid'), nullable=False)
    users = db.relationship('HeartRate', backref='author', lazy=True)
    profileimage = db.Column(db.Text, nullable=True)


class Roles(db.Model):
    roleid = db.Column(db.Integer, primary_key=True)
    rolename = db.Column(db.String, nullable=False)
    createddate = db.Column(db.DateTime, nullable=False)
    roles = db.relationship('Users', backref='author', lazy=True)


class HeartRate(db.Model):
    __tablename__ = 'heartrate'
    heartrateid = db.Column(db.Integer, primary_key=True)
    heartbeatvalue = db.Column(db.Integer, nullable=False)
    userid = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    createddate = db.Column(db.DateTime, nullable=False)


connection_string = create_connection_string()
engine = create_engine(connection_string)


@app.route('/')
@app.route('/home')
def home():
    # logic for redirecting to login if user is not logged in

    if 'user_id' not in session:
        return redirect('/login')

    return redirect('/dashboard')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        hashed_password = generate_password_hash(
            password, method='pbkdf2:sha256')
        new_user_cred = UserCredentials(
            username=username, password_hash=hashed_password)
        db.session.add(new_user_cred)
        db.session.commit()

        # logic for creating a new user record

        new_user = Users(name=username, gender='', age=0,
                         emergencycontactno='', createddate=datetime.utcnow(), role_id=2)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = False
    try:
        if request.method == 'POST':
            username = request.form['username']
            password = request.form['password']

            user = UserCredentials.query.filter_by(username=username).first()
            user_details = Users.query.filter_by(name=username).first()
            if user and check_password_hash(user.password_hash, password):
                session['user_id'] = user_details.id
                if user_details.role_id == 1:
                    session['isAdmin'] = True
                return redirect('/dashboard')

            error = True

        return render_template('login.html', hasError=error)
    except:
        return redirect('home')


@app.route('/profile', methods=['POST'])
def profile():
    try:
        userdetails = Users.query.filter_by(
            id=request.get_json()['id']).first()
        genders = ['Male', 'Female']
        return render_template('profile.html', userdetails=userdetails, genders=genders)
    except Exception as e:
        print(e)
        return redirect('home')


@app.route('/updateProfile', methods=['POST'])
def updateProfile():
    try:
        if request.method == 'POST':
            name = request.form['username']
            emergencycontactno = request.form['emergencycontactno']
            age = request.form['age']
            gender = request.form['gender']
            userdetails = Users.query.filter_by(name=name).first()
            userdetails.emergencycontactno = emergencycontactno
            userdetails.age = age
            userdetails.gender = gender
            db.session.commit()
            return redirect('/dashboard')
    except Exception as e:
        print(e)
        return redirect('home')


@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        if 'isAdmin' in session and session['isAdmin'] == True:
            res = Users.query.all()
        else:
            print(session['user_id'])
            res = Users.query.filter_by(id=int(session['user_id']))
        return render_template('/dashboard.html', users=res)
    else:
        return redirect('/login')


@app.route('/logout', methods=['POST'])
def logout():
    session.pop('user_id', None)
    session.pop('isAdmin', None)
    return redirect(url_for('home'))


@app.route('/deleteFile', methods=['DELETE'])
def deleteFile():
    print('DELETE hit')
    filePath = os.getcwd()+'/files/test.html'
    if os.path.exists(filePath):
        os.remove(filePath)
        return True
    return False


@app.route('/visualize', methods=['POST'])
def visualizeHeartRate():
    selectedUserId = request.get_json()['id']
    selectedUserHeartData = HeartRate.query.filter_by(
        userid=selectedUserId).all()
    userheartRate = [data.heartbeatvalue for data in selectedUserHeartData]

    heartBeatRange = [random.randint(40, 120)
                      for i in range(len(userheartRate))]

    df = pd.DataFrame({'X': userheartRate, 'Y': heartBeatRange})

    # Create a line plot using Plotly Express
    fig = px.line(df, x='X', y='Y', title='Heart Beat Chart')

    fileName = 'test_'+datetime.now().strftime("%Y%m%d%H%M%S")+'f.html'
    filePath = os.getcwd()+'/templates/'+fileName
    fig.write_html(filePath)

    return render_template(fileName)


@app.route('/health')
def appstatus():
    return 'Success'


@app.route('/arduino/data', methods=['POST'])
def receive_data():
    if request.method == 'POST':
        data = request.get_json()
        # Process your data (e.g., store in database)
        # ...
        return "Data received successfully!", data
    return "Invalid request method", 400


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

    app.run()
