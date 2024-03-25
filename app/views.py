from app import app

from flask import render_template, session
from app.special_functions import check_session

@app.route('/')
def home_page():
    if session.get('id'):
        return render_template('dashboard.html', title="PW - Dashboard")
    return render_template('login.html', title="PW - Log in")

@app.route('/registration', methods=['GET', 'POST'])
def registration():
    return render_template('registration.html', title='PW - Registration')

@app.route('/login', methods=['GET', 'POST'])
def login():
    return render_template('login.html', title='PW - Log in')

@app.route('/password-wallet')
@check_session
def dashboard():
    return render_template('dashboard.html', title='PW - Dashboard')

@app.route('/change-password')
@check_session
def user_panel():
    return render_template('change_password.html', title='PW - User Panel')