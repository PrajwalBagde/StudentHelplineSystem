from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

    def __repr__(self):
        return f'<User {self.email}>'

@app.route('/')
def login_page():
    return render_template('login.html')

@app.route('/register_page')
def register_page():
    return render_template('register.html')

@app.route('/action_page', methods=['POST'])
def action_page():
    email = request.form['email']
    password = request.form['psw'].encode('utf-8')
    repeat_password = request.form['psw-repeat'].encode('utf-8')

    if password != repeat_password:
        return 'Passwords do not match', 400

    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

    user = User(email=email, password=hashed_password)
    db.session.add(user)
    db.session.commit()

    return redirect(url_for('index'))

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password'].encode('utf-8')

    user = User.query.filter_by(email=username).first()
    if user and bcrypt.checkpw(password, user.password):
        return redirect(url_for('index'))
    else:
        return 'Incorrect email or password', 401


@app.route('/index')
def index():
    users = User.query.all()
    return render_template('index.html', users=users)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
