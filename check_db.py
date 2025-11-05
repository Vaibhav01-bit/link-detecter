from flask import Flask
from database import init_db, query_db
from auth import create_user

app = Flask(__name__)
init_db(app)

with app.app_context():
    users = query_db('SELECT * FROM users')
    print('Users before:', users)
    if not users:
        create_user('admin', 'password', 'admin')
        print('Admin user created')
    users_after = query_db('SELECT * FROM users')
    print('Users after:', users_after)
