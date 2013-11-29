# -*- coding: utf-8 -*-
"""
    TechHacks Registration Tests
    ~~~~~~~~~~~~~~

    Modified by: Mike Grimes

    Tests the TechHacks Registration application.

    modified from the "MiniTwit" Flask example app
    which can be found at:

    (https://github.com/mitsuhiko/flask/examples/minitwit)

    and was written by:

    :copyright: (c) 2010 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""
import os
import mtu_acm
import unittest
import tempfile


class MiniTwitTestCase(unittest.TestCase):

    def setUp(self):
        """Before each test, set up a blank database"""
        self.db_fd, minitwit.app.config['DATABASE'] = tempfile.mkstemp()
        self.app = minitwit.app.test_client()
        minitwit.init_db()

    def tearDown(self):
        """Get rid of the database again after each test."""
        os.close(self.db_fd)
        os.unlink(minitwit.app.config['DATABASE'])

    # helper functions

    def register(self, name, email, password, password2=None):
        """Helper function to register a user"""
        if password2 is None:
            password2 = password
        return self.app.post('/register', data={
            'name':	    name,
            'password':     password,
            'password2':    password2,
            'email':        email,
        }, follow_redirects=True)

    def login(self, email, password):
        """Helper function to login"""
        return self.app.post('/login', data={
            'email': email,
            'password': password
        }, follow_redirects=True)

    def register_and_login(self, email, password):
        """Registers and logs in in one go"""
	self.register('test', email, password)
	self.logout()
        return self.login(email, password)

    def logout(self):
        """Helper function to logout"""
        return self.app.get('/logout', follow_redirects=True)

    def add_message(self, text):
        """Records a message"""
        rv = self.app.post('/add_message', data={'text': text},
                                    follow_redirects=True)
        if text:
            assert b'Your message was recorded' in rv.data
        return rv

    def create_team(self, team_name):
	"""Creates a team"""
	return self.app.post('/team_register', data = {
	    'name' : team_name
	}, follow_redirects = True)

    # testing functions

    def test_register(self):
        """Make sure registering works"""
        rv = self.register('user1', 'user@mtu.edu', 'default')
        assert b'You were successfully registered ' \
               b'and can login now' in rv.data
        rv = self.register('user1', 'user@mtu.edu', 'default')
        assert b'The email is already registered' in rv.data
        rv = self.register('', 'user@mtu.edu', 'default')
        assert b'You have to enter a valid name' in rv.data
        rv = self.register('meh', 'user@mtu.edu', '')
        assert b'You have to enter a password' in rv.data
        rv = self.register('meh', 'user@mtu.edu', 'x', 'y')
        assert b'The two passwords do not match' in rv.data
        rv = self.register('meh', 'broken', 'foo')
        assert b'You have to enter a valid email address' in rv.data

    def test_login_logout(self):
        """Make sure logging in and logging out works"""
        rv = self.register_and_login('user@mtu.edu', 'default')
        assert b'You were logged in' in rv.data
        rv = self.logout()
        assert b'You were logged out' in rv.data
        rv = self.login('user@mtu.edu', 'wrongpassword')
        assert b'Invalid password' in rv.data
        rv = self.login('user2@mtu.edu', 'wrongpassword')
        assert b'Invalid email' in rv.data

    def test_team_create(self):
	"""Make sure team creation works"""
	self.register_and_login('user@mtu.edu', 'default')
	rv = self.create_team("test team")
	assert b'You successfully registered test team!' in rv.data
	rv = self.create_team("test team")
	assert b'That team name is already taken' in rv.data
	rv = self.create_team("")
	assert b' You have to enter a valid team name' in rv.data

if __name__ == '__main__':
    unittest.main()
