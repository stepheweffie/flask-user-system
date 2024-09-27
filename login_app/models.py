from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_marshmallow import Marshmallow
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import orm
import sqlalchemy as sa
import secrets

# Base = declarative_base()
db = SQLAlchemy()
ma = Marshmallow()
# engine = sa.create_engine('sqlite:///login.db')


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=True, index=True, default=None)
    password_hash = db.Column(db.String(128))
    shortcode = db.Column(db.String(6), nullable=True, default=None)
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime, default=datetime.now, nullable=True)
    current_auth_time = db.Column(db.DateTime, default=datetime.now, nullable=True)
    auth_link_route = db.Column(db.String(60), nullable=True, default=None)
    # verification_token = db.relationship('VerificationToken', backref='user', uselist=False, cascade='all, delete-orphan')

    __table_args__ = (
        db.UniqueConstraint('username', name='user_account_username'),
        db.UniqueConstraint('email', name='user_account_email'),
    )

    def __init__(self, username, password):
        self.username = username
        self.set_password(password)    
   
    def is_authenticated(self):
        return True

    def is_active(self):   
        return True           

    def is_anonymous(self):
        return False          

    def get_id(self):         
        return str(self.id)

    def get_active_verification_token(self):
        return VerificationToken.query.filter_by(user_id=self.id, is_used=False).order_by(VerificationToken.created_at.desc()).first()

    def check_verification_token(self, token):
        verification_token = VerificationToken.query.filter_by(user_id=self.id, token=token, is_used=False).first()
        if verification_token and not verification_token.is_expired():
            return True
        return False

    def generate_verification_token(self):
        token = VerificationToken(user_id=self.id, token=secrets.token_urlsafe(32))
        db.session.add(token)

    
    def use_verification_token(self, token):
        #  verification_token = VerificationToken.query.filter_by(user_id=self.id, token=token, is_used=False).first()
        auth = self.check_verification_token(token)
        if auth:
            self.verification_token.is_used = True
            db.session.commit()
            return True
        return False


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    def __repr__(self):
         return f'<User {self.username}>'


# You want to add verification tokens
class VerificationToken(db.Model):
    __tablename__ = 'verification_token'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False, default=None)
    created_at = db.Column(db.DateTime, default=datetime.now)
    user = db.relationship('User', backref=db.backref('verification_token', uselist=False))
    is_used = db.Column(db.Boolean, default=False)

    def is_expired(self, expiration_hours=1):
        return datetime.datetime.now() > self.created_at + timedelta(hours=expiration_hours) 
    def __repr__(self):
        return f'<VerificationToken {self.token}>'


class UserSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = User
        include_relationships = True
        load_instance = True
        exclude = ("password_hash", "email")


class VerificationTokenSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = VerificationToken
        include_relationships = True
        load_instance = True

  
user_schema = UserSchema()
users_schema = UserSchema(many=True)
verification_token_schema = VerificationTokenSchema()
verification_tokens_schema = VerificationTokenSchema(many=True)





