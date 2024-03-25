from flask import jsonify, redirect, request, session, url_for
from app import app
from app.database.models import User, Password

### CRUD for User

@app.route('/users')
def get_users():
    return jsonify(User.get_all())

@app.route('/users/<int:id>')
def get_user(id: int):
    return User.get_by_id(id)

@app.route('/users', methods=['POST'])
def create_user():
    data = request.json
    new_user = User.create_user(data)
    return new_user, 201

@app.route('/users/<int:id>', methods=['PATCH'])
def update_user(id: int):
    data = request.json
    user = User.get_by_id(id)
    updated_user = User.update_db(user, data)
    return updated_user

@app.route('/users/<int:id>', methods=['DELETE'])
def delete_user(id: int):
    user = User.get_by_id(id)
    User.delete(user)
    return {'detail': 'User deleted succesfully.'}

# SESSION MANAGER

@app.route('/check-user-credentials', methods=['POST'])
def check_user_credentials():
    data = request.json
    passwords_match, user = User.check_password(data['login'], data['password'])
    if passwords_match: 
        session['login'] = user.login
        session['id'] = user.id
    return {'detail': passwords_match}

@app.route('/logout/')
def logout():
    session['login'] = None
    session['id'] == None
    return redirect(url_for("login"))
    
### CRUD for PASSWORDS

@app.route('/passwords')
def get_passwords():
    return jsonify([password.to_dict() for password in Password.get_all()])

@app.route('/passwords/<int:id>')
def get_password(id: int):
    return Password.get_by_id(id)

@app.route('/passwords', methods=['POST'])
def create_password():
    data = request.json
    new_password = Password.create_password(data)
    return new_password, 201

@app.route('/passwords/<int:id>', methods=['PATCH'])
def update_password(id: int):
    data = request.json
    password = Password.get_by_id(id)
    updated_password = Password.update_db(password, data)
    return updated_password

@app.route('/passwords/<int:id>', methods=['DELETE'])
def delete_password(id: int):
    password = Password.get_by_id(id)
    password.delete()
    return {'detail': 'Password deleted succesfully.'}
