from flask_wtf import FlaskForm
from wtforms import QuerySelectField, StringField, PasswordField, BooleanField, SubmitField, validators, IntegerField

def tier_query():
    return SubscriptionTier.query.all()

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[validators.DataRequired(), validators.Length(1, 20)])
    password = PasswordField('Password', validators=[validators.DataRequired(), validators.Length(8, 150)])
    remember = BooleanField('Remember me')
    submit = SubmitField()

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[validators.DataRequired(), validators.Length(1, 20)])
    password = PasswordField('Password', validators=[validators.DataRequired(), validators.Length(8, 150)])
    submit = SubmitField()

class VerifyForm(FlaskForm):
    email = StringField('Email', validators=[validators.DataRequired(), validators.Length(5, 60)])
    submit = SubmitField()

class AuthForm(FlaskForm):
    shortcode = IntegerField('Shortcode', validators=[validators.DataRequired(), validators.Length(1, 7)])
    submit = SubmitField()
 
class SubscriberForm(FlaskForm):
    tier = QuerySelectField('Subscription Tier', 
                            query_factory=tier_query, 
                            get_label='name',
                            allow_blank=True,
                            blank_text='Select a tier...')
    submit = SubmitField('Subscribe')
