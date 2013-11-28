# -*- coding: utf-8 -*-
"""
    MiniTwit
    ~~~~~~~~

    A microblogging application written with Flask and sqlite3.

    :copyright: (c) 2010 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""

import time
from sqlite3 import dbapi2 as sqlite3
from hashlib import md5
from datetime import datetime
from flask import Flask, request, session, url_for, redirect, \
     render_template, abort, g, flash, _app_ctx_stack
from werkzeug import check_password_hash, generate_password_hash

# configuration
DATABASE = '/tmp/minitwit.db'
DEBUG = True
SECRET_KEY = 'development key'

# create our little application :)
app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('MINITWIT_SETTINGS', silent=True)

def get_db():
    """Opens a new database connection if there is none yet for the
    current application context.
    """
    top = _app_ctx_stack.top
    if not hasattr(top, 'sqlite_db'):
        top.sqlite_db = sqlite3.connect(app.config['DATABASE'])
        top.sqlite_db.row_factory = sqlite3.Row
    return top.sqlite_db

@app.teardown_appcontext
def close_database(exception):
    """Closes the database again at the end of the request."""
    top = _app_ctx_stack.top
    if hasattr(top, 'sqlite_db'):
        top.sqlite_db.close()

def init_db():
    """Creates the database tables."""
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv

def get_user_id(email):
    """Convenience method to look up the id for a username."""
    rv = query_db('select user_id from user where email = ?',
                  [email], one=True)
    return rv[0] if rv else None

def get_team_id(name):
    """Convenience method to look up the id for a team."""
    rv = query_db('select team_id from team where name = ?',
	    [name], one=True)
    return rv[0] if rv else None

def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')

def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address."""
    return 'http://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
        (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)

@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = query_db('select * from user where user_id = ?',
                          [session['user_id']], one=True)

@app.route('/')
def home():
    """Displays the latest counts from all teams and users."""
    user_count = len(query_db("select * from user"))
    team_count = len(query_db("select * from team"))
    return render_template('home.html', user_count=user_count, team_count=team_count)

@app.route('/user/<user_id>')
def user_profile(user_id):
    """Display's a users profile"""
    profile_user = query_db('select * from user where user_id = ?',
                            [user_id], one=True)
    if profile_user is None:
        abort(404)
    if g.user:
        return render_template('profile.html', profile_user=profile_user)

@app.route('/team/<team_id>')
def team_profile(team_id):
    """Display's a teams profile page."""
    team = query_db('select * from team where team_id = ?', [team_id], one=True)
    if team is None:
	abort(404)
    if g.user:
	return render_template('team_profile.html', team=team)

@app.route('/add_message', methods=['POST'])
def add_message():
    """Registers a new message for the user."""
    if 'user_id' not in session:
        abort(401)
    if request.form['text']:
        db = get_db()
        db.execute('''insert into message (author_id, text, pub_date)
          values (?, ?, ?)''', (session['user_id'], request.form['text'],
                                int(time.time())))
        db.commit()
        flash('Your message was recorded')
    return redirect(url_for('timeline'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    if g.user:
        return redirect(url_for('user_profile', user_id=g.user.id))
    error = None
    if request.method == 'POST':
        user = query_db('''select * from user where
            email = ?''', [request.form['email']], one=True)
        if user is None:
            error = 'Invalid email'
        elif not check_password_hash(user['pw_hash'],
                                     request.form['password']):
            error = 'Invalid password'
        else:
            flash('You were logged in')
            session['user_id'] = user['user_id']
            return redirect(url_for('profile'))
    return render_template('login.html', error=error)

@app.route('/team_register', methods=['GET', 'POST'])
def team_register():
    """Registers the team."""
    error = None
    if not g.user:
	flash('You need to be logged in to do that!')
	return redirect(url_for('login'))
    if request.method == 'POST':
	if not request.form['name']:
	    error = 'You have to enter a valid team name'
	elif get_team_id(request.form['name']) is not None:
	    error = 'That team name is already taken'
	else:
	    db = get_db()
	    db.execute('''insert into team (name) values (?)''', [request.form['name']])
	    db.commit()
	    team_id = get_team_id(request.form['name'])
	    print team_id
	    print g.user['user_id']
	    db.execute('''update user set team_id = ? where user_id = ?''', [team_id, g.user['user_id']])
	    db.commit()
	    flash("You successfully registered {team_name}!".format(team_name=request.form['name']))
	    return redirect(url_for('profile'))
    teams = query_db('select * from team')
    return render_template('team_register.html', error=error, teams=teams)

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if g.user:
        return redirect(url_for('profile'))
    error = None
    if request.method == 'POST':
	if not request.form['name']:
	    error = 'You have to enter a valid name'
        elif not request.form['email'] or \
                 '@mtu.edu' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['email']) is not None:
            error = 'The email is already registered'
        else:
            db = get_db()
            db.execute('''insert into user (
              name, email, pw_hash) values (?, ?, ?)''',
              [request.form['name'], request.form['email'],
               generate_password_hash(request.form['password'])])
            db.commit()
            flash('You were successfully registered and can login now')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)

@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('public_timeline'))

# add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url

if __name__ == '__main__':
    init_db()
    app.run()
