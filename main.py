from flask import *
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from Models.User import *
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired
from flask_login import login_user, logout_user, login_required, LoginManager

app = Flask(__name__)
login_manager = LoginManager()
app.config['SECRET_KEY'] = "mouahahaahahaah"
app.config["SQLALCHEMY_DATABASE_URI"]  = 'mysql://root:@127.0.0.1:3306/oauth'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager.init_app(app)
errors = ""


class LoginForm(FlaskForm):
    username = StringField('username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Sign In')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username, password=password).first()
        if user:
            print("user")
            redirect("home")
        else:
            errors ={
                "message": "utilisatieur introuvable"
            }
            return render_template('login.html', title='Se connecter', form=form, errors=errors)
    return render_template('login.html', title='Se connecter', form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")


@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@login_manager.unauthorized_handler
def need_to_be_logged():
    return  redirect('/login')


@app.route("/home")
@login_required
def index():
    user = {"name": "gaetan", "password": "password"}
    return render_template('index.html', title='Index', user=user)


if __name__ =="__main__":
    app.run()
