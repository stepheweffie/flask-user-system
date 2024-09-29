from flask import jsonify, Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
import jwt
from flask_jwt_extended import jwt_required, get_jwt_identity
import datetime
from login_app.auth import get_user
from login_app.forms import LoginForm
from login_app.models import User, user_schema, users_schema, db
import datetime 

user = Blueprint('user', __name__)


def generate_auth_link(username):
    logged_in = get_user(username)
    auth_str = '-random-insults/'
    auth_link = auth_str + str(username)
    logged_in.auth_link_route = str(auth_link)
    db.session.commit()
    return auth_link


@user.route('/<username>', methods=['GET', 'POST'])
@jwt_required()
def index(username):
    
    current_user_id = get_jwt_identity()
    current_user = User.query.filter_by(username=current_user_id).first()
    
    if not current_user:
        return redirect(url_for('auth.login'))
    
    if current_user.username != username:
        return redirect(url_for('auth.register', username=current_user.username))

    if current_user.is_admin:
        if current_user.is_verified:
            # Generate a JWT token for admin authentication
            token = jwt.encode({
                'user_id': current_user.id,
                'username': current_user.username,
                'is_admin': True,
                'exp': datetime.datetime.now() + datetime.timedelta(minutes=525600)
            }, app.config['SECRET_KEY'], algorithm='HS256')

            # Redirect to admin subdomain with the token
            return redirect(f'https://login.savantlab.org/Savantlab')
 

    if current_user.is_active:
        if current_user.is_verified is False:
            link = current_user.auth_link_route
            token = generate_auth_link(username)
        return redirect('https://savantlab.org')
    
    return redirect('https://login.savantlab.org')


@user.route('/<username>/get/users', methods=['GET'])
@login_required
def get_users(username):
    user = get_user(username)
    if user.is_admin is False:
        return redirect(url_for('user.index', username=username))

    users = User.query.all()
    return users_schema.dump(users)


@user.route('/get/<int:user_id>', methods=['GET'])
@login_required
def get_user(user_id):
    if current_user.is_authenticated and hasattr(current_user, 'is_admin'):
        if current_user.is_admin:
            user = User.query.get_or_404(user_id)
            return user_schema.dump(user)
        
    return redirect(url_for('user.index', username=current_user.username))


