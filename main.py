from flask import *
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired

app = Flask(__name__)
db = SQLAlchemy()
db.init_app(app)
app.config['SECRET_KEY'] = "mouahahaahahaah"
app.config["SQLALCHEMY_DATABASE_URI"]  = 'mysql://root:@127.0.0.1:3306/oauth'

    SQLALCHEMY_TRACK_MODIFICATIONS = False

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        return redirect('/home')
    return render_template('login.html', title='Se connecter', form=form)


@app.route("/home")
def index():
    user = {"name": "gaetan", "password": "password"}
    return render_template('index.html', title='Index', user=user)


if __name__ =="__main__":
    app.run()
