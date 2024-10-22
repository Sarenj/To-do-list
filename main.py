from flask import Flask, render_template, redirect, url_for, request, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Database connection
def get_db_connection():
    conn = sqlite3.connect('todo.db')
    conn.row_factory = sqlite3.Row
    return conn

# Initialize the database
def init_db():
    with get_db_connection() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS user (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS todo (
                id INTEGER PRIMARY KEY,
                task TEXT NOT NULL,
                user_id INTEGER,
                FOREIGN KEY (user_id) REFERENCES user (id)
            )
        ''')
        conn.commit()

@login_manager.user_loader
def load_user(user_id):
    with get_db_connection() as conn:
        user = conn.execute('SELECT * FROM user WHERE id = ?', (user_id,)).fetchone()
    return User(user['id'], user['username']) if user else None

class User(UserMixin):
    def __init__(self, id, username):
        self.id = id
        self.username = username

@app.route('/')
@login_required
def index():
    with get_db_connection() as conn:
        todos = conn.execute(
            'SELECT * FROM todo WHERE user_id = ?', (current_user.id,)
        ).fetchall()
    return render_template('index.html', todos=todos)

@app.route('/add', methods=['POST'])
@login_required
def add_todo():
    task = request.form.get('task')
    with get_db_connection() as conn:
        conn.execute(
            'INSERT INTO todo (task, user_id) VALUES (?, ?)', 
            (task, current_user.id)
        )
        flash('Task added!', 'success')
    return redirect(url_for('index'))

@app.route('/delete/<int:todo_id>')
@login_required
def delete_todo(todo_id):
    with get_db_connection() as conn:
        conn.execute(
            'DELETE FROM todo WHERE id = ? AND user_id = ?', 
            (todo_id, current_user.id)
        )
        flash('Task deleted!', 'success')
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password)
        with get_db_connection() as conn:
            try:
                conn.execute(
                    'INSERT INTO user (username, password) VALUES (?, ?)', 
                    (username, hashed_password)
                )
                flash('Registration successful! Please log in.', 'success')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username already exists.', 'danger')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with get_db_connection() as conn:
            user = conn.execute(
                'SELECT * FROM user WHERE username = ?', 
                (username,)
            ).fetchone()
        if user and check_password_hash(user['password'], password):
            login_user(User(user['id'], user['username']))
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your username and password.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()  # Initialize the database
    app.run(host='0.0.0.0', port=3000)