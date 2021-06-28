import os

import flask
from flask import *
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import ValidationError
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from Forms.LoginForm import LoginForm
from flask_login import logout_user, login_required, LoginManager, login_user

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)
login_manager = LoginManager()
app.config['SECRET_KEY'] = "mouahahaahahaah"
app.config["SQLALCHEMY_DATABASE_URI"]  = 'sqlite:///' + os.path.join(basedir, 'auth.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager.init_app(app)
errors = ""


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(30), unique=True)
    authenticated = db.Column(db.Boolean, default=False)


    def generate_auth_token(self, expiration=600):
        s = Serializer(app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})


    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        user = User.query.get(data['id'])
        return user



    def is_active(self):
        """True, as all users are active."""
        return True

    def get_id(self):
        """Return the email address to satisfy Flask-Login's requirements."""
        return self.id

    def is_authenticated(self):
        """Return True if the user is authenticated."""
        return self.authenticated

    def is_anonymous(self):
        """False, as anonymous users aren't supported."""
        return False

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)



@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email, password=password).first()
        if user:
            login_user(user)
            session['token'] = user.generate_auth_token()
            return redirect("/home")

        else:
            errors ={
                "message": "utilisatieur introuvable"
            }
            return render_template('login.html', title='Se connecter', form=form, errors=errors)
    return render_template('login.html', title='Se connecter', form=form)


@app.route("/create", methods=['GET', 'POST'])
def create():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form["email"]
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email address already exists')
            return redirect("login")
        else :
            user = User(email=email, password=password)
            db.session.add(user)
            db.session.commit()
            return redirect("login")
    return render_template("create.html", form=form, title="creer un compte")


def is_auth_or_token(req):
    token = session['token']
    if token:
        user = User.verify_auth_token(token)
        if user:
            return True
        else:
            return False
    else:
        return False


@app.route("/home")
@login_required
def index():
    print(session)

    if is_auth_or_token(request):
        return render_template('index.html', title='Index')
    else:
        return redirect("login")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    session['token'] = ""
    return redirect("/login" )


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@login_manager.unauthorized_handler
def need_to_be_logged():
    return  redirect('/login')


if __name__ =="__main__":
    app.run()
