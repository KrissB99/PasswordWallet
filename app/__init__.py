from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.app_context().push()

file_path = os.path.abspath(os.getcwd())+"\database.db"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+file_path
app.config['SECRET_KEY'] = '7c1c22fd86ddc29d543940008034dc8beddb85d73f6c2d4178060cb3072e1c5f32604f893e8f4ab81aca72c9525778a9f3ee'

db = SQLAlchemy(app)

from app import views, routes