from flask import Flask, redirect, url_for, abort, request, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from flask_wtf.csrf import CSRFProtect
from http import HTTPStatus
from flask_migrate import Migrate
from flask_bootstrap import Bootstrap5
from dotenv import load_dotenv
from login_app.models import db, ma, User 
from flask_mail import Mail
from flask_login import LoginManager
from flask_jwt_extended import JWTManager
from datetime import datetime, timedelta
import os 

load_dotenv()
login_manager = LoginManager()
csrf = CSRFProtect()
bootstrap = Bootstrap5()
mail = Mail()
jwt = JWTManager()

PARENT_DOMAIN = os.getenv('PARENT_DOMAIN')

'''
with app.test_request_context():
    print(url_for('index'))
    print(url_for('auth.login'))
    print(url_for('auth.login', next='/'))
    print(url_for('user.index', username='John Doe'))

'''

def create_app():
    app = Flask(__name__, static_url_path='/static')  
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///login.sqlite'
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
    app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET_KEY')
    app.config['JWT_TOKEN_LOCATION'] = ['cookies']
    app.config['JWT_COOKIE_CSRF_PROTECT'] = False
    app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  
    app.config['PARENT_DOMAIN'] = PARENT_DOMAIN
    app.config['ADMIN_USER'] = os.getenv('ADMIN_USER')
    app.config['ADMIN_PASS'] = os.getenv('ADMIN_PASS')
    app.config['MAIL_SERVER'] = 'smtp.mailgun.org'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USE_SSL'] = False
    app.config['MAIL_USERNAME'] = os.getenv('MAILGUN_USERNAME')
    app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
    app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
    app.config['BOOTSTRAP_BOOTSWATCH_THEME'] = 'lumen'

    db.init_app(app) 
    ma.init_app(app)
    migrate = Migrate(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    jwt.init_app(app)
    csrf.init_app(app)
    mail.init_app(app)
    bootstrap.init_app(app)


    from login_app.models import User
    
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))
    
    @login_manager.unauthorized_handler
    def unauthorized():
        if request.blueprint == 'mgmt':
            abort(HTTPStatus.UNAUTHORIZED)
        return redirect(url_for('auth.login'))

    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint, url_prefix='/auth')

    from .user import user as user_blueprint
    app.register_blueprint(user_blueprint, url_prefix='/user')
    
    @app.errorhandler(404)
    def page_not_found(error):
        return render_template('page_not_found.html'), 404

    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect("http://www.savantlab.org", code=302)
        return redirect(url_for('auth.register'))    
      
    
    # Create database tables
    with app.app_context():
        db.create_all()

    return app

__all__ = ['db', 'create_app']
