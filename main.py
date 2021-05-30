import os

from flask import *
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import ValidationError

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

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form["email"]
        password = request.form["password"]
        user = User.query.filter_by(email=email, password=password).first()
        if user:
            login_user(user)
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
        else :
            user = User(email=email, password=password)
            db.session.add(user)
            db.session.commit()
            redirect("login")
    return render_template("create.html", form=form, title="creer un compte")



@app.route("/home")
@login_required
def index():
    return render_template('index.html', title='Index')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login" ,)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@login_manager.unauthorized_handler
def need_to_be_logged():
    return  redirect('/login')





if __name__ =="__main__":
    app.run()
