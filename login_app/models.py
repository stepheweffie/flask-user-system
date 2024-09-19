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
# engine = sa.create_engine('sqlite:///users.db')


class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=True, index=True)
    password_hash = db.Column(db.String(128))
    shortcode = db.Column(db.String(6), nullable=True, default=None)
    is_admin = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime, default=datetime.now, nullable=True)
    current_auth_time = db.Column(db.DateTime, default=datetime.now, nullable=True)
    subscriber = db.relationship('Subscriber', back_populates='user', uselist=False)

    __table_args__ = (
        db.UniqueConstraint('username', name='user_account_username'),
        db.UniqueConstraint('email', name='user_account_email'),
    )

    def __init__(self, username, password):
        self.username = username
        self.set_password(password)    

    def generate_verification_token(self):
        token = VerificationToken(user_id=self.id, token=secrets.token_urlsafe(32))
        db.session.add(token)
        db.session.commit()
    
    # verification_token = db.relationship('VerificationToken', backref='user', uselist=False, cascade='all, delete-orphan')
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
    token = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    user = db.relationship('User', backref=db.backref('verification_token', uselist=False))
    def is_expired(self, expiration_hours=1):
        return datetime.datetime.now() > self.created_at + timedelta(hours=expiration_hours) 
    def __repr__(self):
        return f'<VerificationToken {self.token}>'


class Subscriber(db.Model):
    __tablename__ = 'subscriber'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    tier = db.Column(db.String(50), nullable=False)
    start_date = db.Column(db.DateTime, default=datetime.now)
    end_date = db.Column(db.DateTime)

    user = db.relationship('User', back_populates='subscriber')

    def __repr__(self):
        return f'<Subscriber {self.user.username} - Tier: {self.tier}>'


class SubscriptionTier(db.Model):
    __tablename__ = 'subscription_tier'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    price = db.Column(db.Float, nullable=False)

    def __repr__(self):
        return f'<SubscriptionTier {self.name}>'


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


class SubscriberSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = Subscriber
        include_relationships = True
        load_instance = True


class SubscriptionTierSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = SubscriptionTier
        load_instance = True


subscriber_schema = SubscriberSchema()
subscribers_schema = SubscriberSchema(many=True)
subscription_tier_schema = SubscriptionTierSchema()
subscription_tiers_schema = SubscriptionTierSchema(many=True)
user_schema = UserSchema()
users_schema = UserSchema(many=True)
verification_token_schema = VerificationTokenSchema()
verification_tokens_schema = VerificationTokenSchema(many=True)





