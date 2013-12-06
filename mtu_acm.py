# -*- coding: utf-8 -*-
"""
    TechHacks Registration
    ~~~~~~~~

    author: Mike Grimes

    modified from MiniTwit example app, which was originally made by:

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
DATABASE = '/tmp/mtu_acm.db'
DEBUG = True
SECRET_KEY = 'development key'

admin_emails = ["magrimes@mtu.edu", "tjscanlo@mtu.edu", "kelwert@mtu.edu", "ntpeters@mtu.edu"]

# create our little application :)
app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('MTU_ACM_SETTINGS', silent=True)

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
    return render_template('home.html')

@app.route('/user/<int:user_id>', methods=['GET', 'POST'])
def user_profile(user_id):
    """Display's a users profile"""
    profile_user = query_db('select * from user where user_id = ?',
                            [user_id], one=True)

    if request.method == 'POST':
        if profile_user['user_id'] == g.user['user_id']:
            db = get_db()
            if 'shirtsize' in request.form and request.form['shirtsize'] != \
                    profile_user['shirt_size']:
                db.execute('''update user set shirt_size = ? where user_id = ?
                    ''', [request.form['shirtsize'], profile_user['user_id']])
                flash('Shirt size updated.')
            learn = 1 if 'learn' in request.form else 0
            if learn != profile_user['learn']:
                db.execute('''update user set learn = ? where user_id = ?
                        ''', [1 if 'learn' in request.form else 0, profile_user['user_id']])
                flash('Learn status updated.')
            db.commit()

        else:
            flash("You are not authorized to do that.")
        return redirect(url_for('user_profile', user_id = g.user['user_id']))

    else:
        if profile_user['team_id'] != None:
            profile_user_team = query_db('select * from team where team_id = ?',
                    [profile_user['team_id']], one=True)
        else:
            profile_user_team = None

        if profile_user is None:
            abort(404)
        return render_template('profile.html', profile_user=profile_user,
                profile_user_team=profile_user_team, shirt_size=profile_user['shirt_size'], learn=profile_user['learn'])

@app.route('/schedule', methods=['GET'])
def schedule():
    return render_template('schedule.html')

@app.route('/rules', methods=['GET'])
def rules():
    return render_template('rules.html')

@app.route('/user/<int:user_id>/delete', methods=['GET'])
def delete_user(user_id):
    if is_admin(g.user['email']):
        db = get_db()
        user = query_db('select * from user where user_id = ?', [user_id], one=True)
        db.execute('delete from user where user_id = ?', [user_id])
        db.commit()
        flash("User {user_name} deleted. Hope you really wanted to do that.".format(user_name=user['name']))
        return redirect(url_for('admin'))
    else:
        flash("You are not an administrator.")
        return redirect(url_for('home'))

@app.route('/team/<int:team_id>/delete', methods=['GET'])
def delete_team(team_id):
    if is_admin(g.user['email']):
        db = get_db()
        team = query_db('select * from team where team_id = ?', [team_id], one=True)
        db.execute('delete from team where team_id = ?', [team_id])
        db.execute('update user set team_id = ? where team_id = ?', [None, team_id])
        db.commit()
        flash("Team {team_name} deleted. Hope you really wanted to do that.".format(team_name=team['name']))
        return redirect(url_for('admin'))
    else:
        flash("You are not an administrator.")
        return redirect(url_for('home'))

@app.route('/team/<int:team_id>/leave', methods=['GET'])
def leave_team(team_id):
    team = query_db('select * from team where team_id = ?', [team_id], one=True)
    if g.user:
        if g.user['team_id'] == team_id:
            db = get_db()
            db.execute('update user set team_id = ? where user_id = ?', [None, g.user['user_id']])
            flash('You have left {team_name}'.format(team_name=team['name']))

            if len(query_db('select * from user where team_id = ?', [team_id])) < 1:
                db.execute('delete from team where team_id = ?', [team_id])
                db.commit()
                return redirect(url_for('user_profile', user_id=g.user['user_id']))

            if team['admin_id'] == g.user['user_id']:
                new_admin = query_db('select * from user where team_id = ?', [team_id], one=True)
                db.execute('''update team set admin_id = ? where team_id = ?
                        ''', [new_admin['user_id'], team_id])

            db.commit()
            return redirect(url_for('team_profile', team_id=team_id))
        else:
            flash("You are not on that team.")
            return redirect(url_for('team_profile', team_id=team_id))
    else:
        flash("You are not logged in.")
        return redirect(url_for('team_profile.html', team_id=team_id))

@app.route('/team/<int:team_id>/delete', methods=['GET'])
def team_delete(team_id):
    team = query_db('select * from team where team_id = ?', [team_id], one=True)

    if g.user['user_id'] == team['admin_id']:
        db = get_db()
        db.execute('delete from team where team_id = ?', [team_id])
        db.execute('update user set team_id = ? where team_id = ?', [None, team_id])
        db.commit()
        flash("{team_name} has been deleted.".format(team_name=team['name']))
        return redirect(url_for('user_profile', user_id=g.user['user_id']))
    else:
        flash("You are not the administrator of this team.")
        return render_template('team_profile', team_id=team_id)


@app.route('/team/<int:team_id>', methods=['GET', 'POST'])
def team_profile(team_id):
    """Display's a teams profile page."""
    team = query_db('select * from team where team_id = ?', [team_id], one=True)
    members = query_db('select * from user where team_id = ?', [team_id])

    if request.method == 'POST':
        if g.user['user_id'] == team['admin_id']:
            db = get_db()
            if request.form['name']:
                if len(request.form['name']) > 52:
                    flash("Team name must be less than 52 characters.")
                else:
                    old_name = team['name']
                    db.execute('''update team set name = ? where team_id = ?
                            ''', [request.form['name'], team_id])
                    flash('''{old_name} renamed to {new_name}
                            '''.format(old_name=old_name, new_name=request.form['name']))
            update_skills = team['skills'] and request.form['skills'].strip() != \
                    team['skills'].strip()
            update_looking = ('looking' in request.form) != team['looking']
            if update_looking or update_skills:
                flash("Looking for members status updated.")
                db.execute('''update team set looking = ?, skills = ? where team_id = ?
                ''', [1 if 'looking' in request.form else 0, request.form['skills'].strip(), team_id])
            db.commit()
            return redirect(url_for('team_profile', team_id=team_id))

        else:
            flash("You are not the administrator of this team.")
            return render_template('team_profile.html', team=team)
    else:
        if team is None:
            abort(404)
        return render_template('team_profile.html', team=team, members=members)

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
        return redirect(url_for('user_profile', user_id=g.user['user_id']))
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
            return redirect(url_for('user_profile', user_id=session['user_id']))
    if error:
        flash(error)
    return render_template('login.html')

@app.route('/team/<int:team_id>/join')
def join_team(team_id):
    """Adds the current user as a member of the team, given
    the team is looking for members and the team is not already full"""
    user_count = len(query_db('select * from user where team_id = ?', [team_id]))
    if g.user:
        if g.user['team_id']:
            flash("You are already on a team.")
        elif user_count >= 5:
            flash("That team is full.")
        else:
            db = get_db()
            db.execute('update user set team_id = ? where user_id = ?', [team_id, g.user['user_id']])
            db.commit()
            team = query_db('select * from team where team_id = ?', [team_id], one=True)
            flash('You successfully joined {team}'.format(team=team['name']))
        return redirect(url_for('team_profile', team_id=team_id))
    else:
        flash("You are not logged in.")
        return redirect(url_for('home'))


@app.route('/team_register', methods=['GET', 'POST'])
def team_register():
    """Registers the team."""
    error = None

    teams = query_db('select * from team')
    join_team = len(teams) > 0

    if g.user['team_id'] is not None:
        flash("You are already signed up for a team.")
        return redirect(url_for('team_profile', team_id=g.user['team_id']))

    if not g.user:
        flash('You need to be logged in to do that.')
        return redirect(url_for('login'))

    if request.method == 'POST':

        hardware = 0
        create_team = False
        if not request.form['name']:
            if not request.form['select_name']:
                flash('You have to enter a valid team name')
                return render_template('team_register.html', teams=teams, join_team=join_team)
            else:
                name = request.form['select_name']
        else:
            create_team = True
            if 'hardware' in request.form:
                hardware = 1
            name = request.form['name']
            if len(name) > 62:
                flash('Team name must be less than 62 characters long')
                return render_template('team_register.html', teams=teams, join_team=join_team)

        db = get_db()
        flash_string = 'joined'
        team_id = get_team_id(name)
        if create_team:
            if team_id is not None:
                flash('That team name is already taken')
            else:
                db.execute('''insert into team (name, admin_id, hardware) values
                        (?, ?, ?)''', [name, g.user['user_id'], hardware])
                db.commit()
                flash_string = 'created'
                team_id = get_team_id(name) # gotta get team id so we can build url

        current_members = query_db('''select * from user where team_id = ?''', [team_id])

        if len(current_members) > 4:
            flash('''{team_name} is currently full, please choose another team
                or create a new one.'''.format(team_name=name))
            return render_template('team_register.html', teams=teams)
        else:
            db.execute('''update user set team_id = ?
                            where user_id = ?''', [team_id, g.user['user_id']])
            db.commit()
            flash('''You successfully {flash_string} {team_name}!
                    '''.format(flash_string=flash_string, team_name=name))
            return redirect(url_for('team_profile', team_id=team_id))

    return render_template('team_register.html', teams=teams, join_team=join_team)

@app.route('/users', methods=['GET'])
def all_users():
    if g.user:
        users = query_db('select * from user')
        return render_template('users.html', users=users)
    else:
        flash('You need to be logged in to do that')
        return redirect(url_for('home'))

@app.route('/teams', methods=['GET'])
def all_teams():
    if g.user:
        teams = query_db('select t.team_id, t.name, count(u.user_id) as size from team t left join user u on t.team_id=u.team_id group by t.team_id order by size, t.name')
        return render_template('teams.html', teams=teams)

@app.route('/faq', methods=['GET'])
def faq():
    return render_template('faq.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if g.user:
        return redirect(url_for('profile'))
    error = None
    if request.method == 'POST':
        if not request.form['name']:
            error = 'You have to enter a valid name'
        elif len(request.form['name']) > 52:
            error = 'Name must be less than 52 characters'
        elif not request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['email']) is not None:
            error = 'The email is already registered'
        elif 'shirtsize' not in request.form:
            error = 'You need to pick a t-shirt size.'
        else:
            db = get_db()
            db.execute('''insert into user (
              name, email, shirt_size, pw_hash, learn) values (?, ?, ?, ?, ?)''',
              [request.form['name'], request.form['email'], request.form['shirtsize'],
               generate_password_hash(request.form['password']), \
                       1 if 'learn' in request.form else 0])
            db.commit()
            flash('Registration successful. You are now logged in.')
            user = query_db('''select * from user where email = ?
                    ''', [request.form['email']], one=True)
            session['user_id'] = user['user_id']
            return redirect(url_for('home'))
    if error:
        flash(error)
    return render_template('register.html')


@app.route('/find_team')
def find_team():
    if not g.user:
        flash('You need to be logged in to do that.')
        return redirect(url_for('home'))
    elif g.user['team_id']:
        flash('You are already on a team.')
        return redirect(url_for('home'))
    else:
        # select all teams who are looking for people
        # pass them to template :)
        teams = query_db('select t.team_id, t.name, t.skills, count(u.user_id) as user_count from team t left join user u on t.team_id=u.team_id where t.looking = 1 group by t.team_id having user_count < 5')
        return render_template('find_team.html', teams=teams)

@app.route('/admin')
def admin():
    ''' builds the data for the admin panel page - this
    can be optimized a lot more '''
    if not g.user or not is_admin(g.user['email']):
        flash("You are not an administrator.")
        return render_template('home.html')
    else:
        user_data = {}
        users = query_db('select * from user')
        team_data = {}
        teams = query_db('select * from team')
        for team in teams:
            team_data[team['team_id']] = []
        for user in users:
            if user['team_id']:
                print "adding"
                team_data[user['team_id']].append(user)

        for user in users:
            if user['team_id']:
                user_data[user['user_id']] = query_db('''
                select * from team where team_id = ?''', [user['team_id']], one=True)

        return render_template('admin.html', users=users, user_data=user_data, teams=teams, team_data=team_data)

@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('home'))

def possess(name):
    if name[-1] == 's':
        return ''.join([name, '\''])
    else:
        return ''.join([name, '\'s'])

def user_count():
    # Don't ask me why [0] is needed and not .count
    return query_db("select count(*) from user", one=True)[0]

def team_count():
    # Don't ask me why [0] is needed and not .count
    return query_db("select count(*) from team", one=True)[0]

def is_admin(email):
    return email in admin_emails

# add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url
app.jinja_env.filters['possess'] = possess
app.jinja_env.filters['is_admin'] = is_admin
app.jinja_env.globals.update(user_count=user_count)
app.jinja_env.globals.update(team_count=team_count)

if __name__ == '__main__':
    init_db()
    app.run()
