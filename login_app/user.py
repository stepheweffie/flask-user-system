from flask import jsonify, Blueprint, render_template, redirect, url_for, request, flash
from flask_login import login_required, current_user
import jwt
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
@login_required
def index(username):
    
        # connect login.db to users.db and instantiate a session for current_user
        # logged_in = get_user(username)  

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
            return redirect(f'https://admin.savantlab.org/auth/{token}')
 

    if current_user.is_authenticated:

        if not current_user.is_verified:
            link = current_user.auth_link_route
            if link is None:
                auth_link = generate_auth_link(username)
                #  return redirect(url_for('auth.send_code_auth', username=username))

        return redirect('https://savantlab.org')


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


