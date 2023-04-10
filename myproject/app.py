from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from config import Config
from forms.user_forms import RegistrationForm, LoginForm
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
app.config['SQLALCHEMY_ECHO'] = True
migrate = Migrate(app, db)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.password_hash}')"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_raw_password(self):
        return self.password_hash


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/")
@login_required
def home():
    return render_template("base.html")


@app.route('/register', methods=['GET', 'POST'])
@login_required
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data

        # Comprueba si el nombre de usuario ya existe
        user = User.query.filter_by(username=username).first()
        if user:
            flash('El nombre de usuario ya existe. Por favor, elige otro.', 'error')
            return redirect(url_for('register'))

        # Si no existe, crea un nuevo registro
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registro exitoso. Por favor, inicie sesión.', 'success')
        return redirect(url_for('user_list'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])

def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(url_for('user_list')) if next_page else redirect(url_for('user_list'))
        else:
            flash('Usuario o contraseña incorrectos.', 'error')
    return render_template('login.html', form=form)


@app.route("/user_list")
@login_required
def user_list():
    users = User.query.all()
    return render_template("user_list.html", users=users)


@app.route("/barra")
@login_required
def barra():
    return render_template("barra.html")


if __name__ == "__main__":
    app.run(debug=True)


@app.route('/logout', methods=['POST'], endpoint='logout_user')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))
