from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from .models import db, User 
import os

def create_app():
    app = Flask(__name__)
    app.secret_key = 'random23'

    #Configure database
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    #Initialize database and Flask extensions
    db.init_app(app)
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'

    #Define the user_loader function for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))  #Query user from the database by ID

    #Import and register blueprints
    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    #Ensure database tables exist
    with app.app_context():
        db.create_all()

    return app
