from flask import Flask, render_template, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import InputRequired, Length, ValidationError, DataRequired
#Make sure that flask_login and bcrypt are installed
from flask_login import login_user,logout_user,current_user,UserMixin, LoginManager, login_required
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bcrypt import Bcrypt
from datetime import datetime


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db' 
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
#Position all of this after the db and app have been initialised
bcrypt = Bcrypt(app)
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def user_loader(user_id):
    #TODO change here
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False, unique=True)
    email = db.Column(db.String(40), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    todos = db.relationship('Todo', backref='user', lazy=True)

    def __repr__(self):
        return '<User {}>'.format(self.username)

class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    task = db.Column(db.String, nullable=False)
    completed = db.Column(db.Boolean, default=False)  # Use Boolean for completed
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Use 'users.id' for foreign key
    date_created = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"Todo('{self.task}', '{self.completed}')"

class RegisterForm(FlaskForm):
    username = StringField(validators = [InputRequired(), Length
    (min=8, max=20)], render_kw={"placeholder": "John Doe"})

    email = EmailField(validators = [InputRequired(), Length
    (min=8, max=30)], render_kw={"placeholder": "Johndoe@yahoo.co"})
    
    password = PasswordField(validators = [InputRequired(), Length
    (min=8, max=30)], render_kw={"placeholder": "password"})

    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    username = StringField(validators = [InputRequired(), Length
    (min=8, max=30)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators = [InputRequired(), Length
    (min=8, max=30)], render_kw={"placeholder": "password"})

    submit = SubmitField("Login")

class TaskForm(FlaskForm):
    task = StringField(validators = [InputRequired(), Length
    (min=1, max=500)], render_kw={"placeholder": "Add Task"})

    submit = SubmitField("Add Task")

class UpdateForm(FlaskForm):
    task = StringField(validators = [InputRequired(), Length
    (min=1, max=500)], render_kw={"placeholder": "Add Task"})

    submit = SubmitField("Update Task")


@app.route('/')
def home():
    return render_template("index.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            try:
                return redirect(url_for('dashboard'))
            except:
                return "Error signing user in"
                # return redirect(url_for('login'))
        else:
            # return redirect(url_for('login'))
            return "Invalid Credentials"
    else:
        print(form.errors)

    return render_template("login.html", form= form)

@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    
    if form.validate_on_submit():
        existing_user = User.query.filter(
            (User.username == form.username.data) |
            (User.email == form.email.data)
        ).first()

        if existing_user:
            return "Email or Username has been taken"
        else:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(username=form.username.data,  email=form.email.data, password = hashed_password)
            try:
                db.session.add(new_user)
                db.session.commit()
                return redirect(url_for('login'))
            except:
                return "<h1>There is an issue creating your account</h1>"
            
    return render_template("register.html", form=form)

@app.route('/add', methods = ['POST','GET'])
@login_required
def add():
    form = TaskForm()

    if form.validate_on_submit():
        new_task = Todo(task=form.task.data, user_id=current_user.id)

        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect(url_for('dashboard'))
        except:
            return "There was an issue adding task"
    return render_template("add.html", form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    tasks = Todo.query.filter_by(user_id=current_user.id).order_by(Todo.date_created).all()
    return render_template("dashboard.html", tasks = tasks)

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    task_to_delete = Todo.query.get_or_404(id)

    try:
        db.session.delete(task_to_delete)
        db.session.commit()
        return redirect(url_for('dashboard'))
    except:
        return "There was an error deleting the task"

@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    form = UpdateForm()
    task_update = Todo.query.get_or_404(id)

    if form.validate_on_submit():
        task_update.task = form.task.data

        try:
            db.session.commit()
            return redirect(url_for('dashboard'))
        except Exception as e:
            return f'There was an issue adding your task: {str(e)}'


    form.task.data = task_update.task
    return render_template("update.html", form = form, task = task_update)

@app.route('/logout')
@login_required
def logout():
    logout_user()

    return redirect(url_for('login'))
if __name__ == '__main__':
 app.run(debug=True)