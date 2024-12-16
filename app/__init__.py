from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from .models import db, User 
from .routes import main as main_blueprint
from .admin import admin
import os

mail = Mail()

def create_app():
    app = Flask(__name__)
    app.secret_key = 'random23'

    #Configure database
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    # Flask-Mail Configuration
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'tomiloba4real@gmail.com'
    app.config['MAIL_PASSWORD'] = 'ysaw ynbi daat ffks'
    app.config['MAIL_DEFAULT_SENDER'] = 'tomiloba4real@gmail.com'

    #Initialize database and Flask extensions
    db.init_app(app)
    mail.init_app(app)
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'

    #Define the user_loader function for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))  #Query user from the database by ID

    #Import and register blueprints
    app.register_blueprint(main_blueprint)
    app.register_blueprint(admin, url_prefix='/admin')

    #Ensure database tables exist
    with app.app_context():
        db.create_all()

    return app
