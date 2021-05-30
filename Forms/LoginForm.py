from flask_wtf import FlaskForm
from wtforms import *
from wtforms.validators import DataRequired


class LoginForm(FlaskForm):
    email = StringField('email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Ok')
