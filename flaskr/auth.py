import functools
from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for
from flaskr.db import get_db
from werkzeug.security import check_password_hash, generate_password_hash

bp = Blueprint('auth', __name__, url_prefix='/auth')
#db = get_db()

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@bp.route('/register', methods=('POST', 'GET'))
def register():
    if request.method == "POST":
        username = request.form['username']
        password = request.form['password']

        #cria uma instancia do datebase, e assign it to a variable
        db = get_db()
        error = None

        if not username:
            error = 'Username is required'
        elif not password:
            error = 'Password is required'

        if error is None:
            try:
                db.execute(
                    'INSERT INTO user (username, password) VALUES (?,?)', 
                    (username, generate_password_hash(password))
                )
                db.commit() #para atualizar o database
            except db.IntegrityError:
                error = f"User {username} is already register"
            else:
                return redirect(url_for('auth.login'))
            
    return render_template('auth/register.html')

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        #request username and password from the form 
        username = request.form['username']
        password = request.form['password']

        #store an instance of the database in a temp variable to use it
        db = get_db()
        error = None

        #after geting username from the user, check if it exists on the database
        user = db.execute("SELECT * FROM user WHERE username = ?", (username,)).fetchone()
        
        #Validating username
        if user is None:
            error = 'Incorrect username'
        #valitdating password with check_password_hash
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password'

        #creates session and sends user to the main page, or any other of your choice
        if error is None:
            session.clear()
            session['user_id'] = user['id']

            return redirect(url_for('index'))
        
        flash(error)

    return render_template('auth/login.html')

@bp.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    return redirect(url_for('index'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view

