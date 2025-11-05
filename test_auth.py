from flask import Flask
from database import init_db
from auth import authenticate_user

app = Flask(__name__)
init_db(app)

with app.app_context():
    user = authenticate_user('admin', 'password')
    print('Auth result:', user)
    print('Type:', type(user))
