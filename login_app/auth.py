from flask import jsonify, Blueprint, abort, render_template, redirect, url_for, request, flash, session
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from login_app import mail 
from flask_mail import Message
from login_app.models import User, db
import random 
from login_app.forms import LoginForm, RegisterForm, VerifyForm, AuthForm
from sqlalchemy.exc import IntegrityError

auth = Blueprint('auth', __name__)


def generate_shortcode():
    code = random.randint(100000, 999999)
    return code


def verify_current_user(username):   
    try:     
        shortcode = generate_shortcode()
        user = get_user(username)         
        user.shortcode = shortcode
        db.session.commit()
           
    except Exception as e:
        flash(f'Error sending verification email: {str(e)}') 


def get_user(uname):
    user = User.query.filter_by(username=uname).first()
    if user:
        return user
    return False


@auth.route('/login/post', methods=["GET", "POST"])
def login_post():

    form = LoginForm()
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = get_user(username)    
        
        try: 
            if user.check_password(password):
                login_user(user, remember=True, force=True, fresh=True)    
                return redirect(url_for('auth.authorize', username=username))
                      
            flash('Incorrect Password', 'warning')

        except AttributeError:
            return redirect('https://login.savantlab.org/auth/register') 
   


@auth.route('/verify/<username>', methods=['GET'])
@login_required 
def verify(username):

    form = VerifyForm()
    user = get_user(username)
    user_email = user.email 
     
    if user_email is not None:
        return redirect(url_for('user.index', username=username))    
    
    return render_template('verify.html', username=username, form=form)


@auth.route("/verify/<username>", methods=['GET','POST'])
@login_required
def verify_post(username):
    user = get_user(username)
    verified = user.is_verified

    if request.method == 'POST':
        if verified is False:
            try:
                user_email = request.form["email"]

                # Check if the email already exists in the database
                existing_user = User.query.filter_by(email=user_email).first()
                if existing_user and existing_user.id != user.id:
                    flash('Please enter a unique email address.', 'warning')
                    return redirect(url_for('auth.verify', username=username))

                # verify if it's a real email address (you may want to add more robust validation)
                if len(user_email) < 6 or '@' not in user_email or '.' not in user_email:
                    flash('Please enter a valid email address.', 'warning')
                    return redirect(url_for('auth.verify', username=username))
                
                try: 
                    user.email = user_email  
                    db.session.commit()
                    return redirect(url_for('auth.send_onboard_email', username=username))
                    
                except IntegrityError:
                    db.session.rollback()
                    flash('An error occurred. Please try again.', 'danger')

                return redirect(url_for('auth.verify', username=username))
            except KeyError:
                flash('Email is required.', 'info')

    return redirect(url_for('auth.authorize', username=username))


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(username=username).first()
        
        try:
            if user.check_password(password):
                login_user(user, remember=remember, force=True, fresh=True)
                return redirect(url_for('auth.authorize', username=username))

            flash('Incorrect Password', 'warning')

        except AttributeError:
            return redirect('https://login.savantlab.org/auth/register')

        if not user or not user.check_password(password):
            flash('Please check your login details and try again.')
            return redirect(url_for('auth.login'))
        
        return redirect(url_for('user.index', username=user.username))
    
    form = LoginForm()
    return render_template('login.html', form=form)


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()

    if current_user.is_authenticated:
        return redirect('https://savantlab.org')

    if form.validate_on_submit():
        username = request.form.get('username')
        password = request.form.get('password')
        user = get_user(username)

        if user is False:
            new_user = User(username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            
            # Try to log in the user
            login_result = login_user(new_user)
            
            if login_result:
                flash('Logged in successfully.', 'success')
                # Add debug information
                print(f"User {username} registered and logged in successfully")
                return redirect(url_for('auth.authorize', username=username))
            else:
                flash('Failed to log in after registration.', 'error')
                print(f"Failed to log in user {username} after registration")
                return jsonify({"error": "Login failed after registration"}), 500

        flash('Username already exists.', 'error')
        return redirect(url_for("auth.login"))

    return render_template('register.html', form=form)


@auth.route('/send-onboard-email/<username>', methods=['GET'])
@login_required
def send_onboard_email(username):
    user = get_user(username)  
    # get_toke = user.get_active_verification_token()
    # token = user.check_verification_token(get_toke)

    if user.email is not None:
        greeting = 'Hey, Thanks!'
        message = 'Some Content Here'
        try:
            # Send an email with Flask-Mail
            msg = Message(
                greeting,
                recipients=[user.email],
                body=message
                )
            mail.send(msg) 
            user.is_active = True
            return redirect(url_for('user.index', username=username))

        except TypeError:
            return redirect(url_for('auth.authorize', username=username))

    return redirect(url_for('auth.authorize', username=username))


@auth.route('/send-code-auth/<username>', methods=['GET'])
@login_required
def send_code_auth(username):
    user = get_user(username)
    verified = user.is_verified
    shortcode = user.shortcode
    link = user.auth_link_route
    token = user.check_verification_token
    # If the verification token has been generated, create the link route for email message

    if current_user.is_authenticated and current_user.is_verified:
        return redirect(url_for('user.index', username=username))
    
    if current_user.is_authenticated and hasattr(current_user, 'is_active'):

        if current_user.is_authenticated and hasattr(current_user, 'sms'): 
            if 'shortcode' not in session:
                session['shortcode'] = 0
                message = 'Welcome to Savantlab.org! Click HERE to enter the following shortcode: ' + str(shortcode)
                return redirect(url_for('auth.authorize', username=username))

        if current_user.is_authenticated and hasattr(current_user, 'email'):
            
            link = user.auth_link_route
            if link is None:
                return redirect(url_for('user.index', username=username))
 
            if token is True: 
                # Add the URL link https://login.savantlab.org/auth/authorize/{username}/{auth_link_route} to the email 
                greeting = 'Hello, There!'
                message = 'Welcome to Savantlab.org! Click HERE: ' + str(link) 
                
                try: 
                    # Send an email with Flask-Mail
                    msg = Message(
                        greeting,
                    recipients=[user.email],
                    body=message
                    )
                    mail.send(msg)
                    user.use_verification_token() 
                    return redirect(url_for('user.index', username=username))
                
                except TypeError:
                    return redirect(url_for('auth.authorize', username=username))
    
    return redirect(url_for('auth.verify', username=username))


@auth.route('/authorize/post/<username>', methods=['GET', 'POST'])
@login_required
def authorize_post(username):
    form = AuthForm()
    user = get_user(username) 
    shortcode = user.shortcode
    # Initialize attempt counter in session if it doesn't exist    
    if request.method == 'POST':
        if 'shortcode_attempts' not in session:
            session['shortcode_attempts'] = 0
        
        shortcode_data = request.form['shortcode']

        if shortcode == shortcode_data:
            user.is_verified = True
            user.shortcode = None
            db.session.commit()

            # Send Thank You/Onboard Email 
            # Reset attempts counter
            
            session.pop('shortcode_attempts', None)
            session['shortcode'] = 2
            return redirect(url_for('auth.send_auth_onboard_email', username=username))
            # return redirect(url_for('user.index', username=username))
        else:
            session['shortcode_attempts'] += 1
            attempts_left = 3 - session['shortcode_attempts']

            if attempts_left > 0:
                flash(f'Incorrect shortcode. You have {attempts_left} attempts left.', 'warning')
            
            if attempts_left == 0:
                user.shortcode = None
                db.session.commit()
                # Reset attempts counter
                session.pop('shortcode_attempts', None)
                session.pop('shortcode', None) 
                return redirect(url_for('auth.authorize', username=username))
   
    return redirect(url_for('auth.authorize', username=username))


@auth.route('/authorize/<username>', methods=['GET'])
@login_required
def authorize(username): 
    form = AuthForm()
    user = get_user(username)
    shortcode = user.shortcode 
    verified = user.is_verified 

    if current_user.is_authenticated and hasattr(current_user, 'sms'):
        if 'shortcode' not in session:  
            if verified is False:
                verify_current_user(username) 
                return redirect(url_for('auth.send_code_auth', username=username))
        # user_phone = user.phone
        # flash(f'Please check text {user_text}', 'info')
        return render_template('auth.html', username=username, form=form)
    
    if current_user.is_authenticated:   
        
        if not current_user.is_active: 
            return redirect(url_for('auth.send_onboard_email', username=username))
        
        token = current_user.get_active_verification_token()
        if token:
            return redirect(url_for('auth.send_code_auth', username=username))

        return redirect(url_for('user.index', username=username))    
    
    return redirect(url_for('auth.verify', username=username))


@auth.route('/authorize/<username>/<auth_link_route>', methods=['GET'])
@login_required
def authorize_link(username, auth_link_route):
    user = get_user(username)
    link_route = user.auth_link_route
    if auth_link_route == link_route:
        user.is_verified = True
        db.session.commit()
    return redirect(url_for('user.index', username=username))
    


@auth.route('/logout', methods=["GET", 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

