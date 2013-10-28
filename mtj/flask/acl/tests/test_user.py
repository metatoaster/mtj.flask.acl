import os
import unittest
import tempfile

from flask import Flask, session
from flask.ext.principal import PermissionDenied
from werkzeug.exceptions import Forbidden

from mtj.flask.acl.base import SetupAcl
from mtj.flask.acl.base import anonymous

from mtj.flask.acl import flask
from mtj.flask.acl import user


class UserTestCase(unittest.TestCase):

    def setUp(self):
        self.auth = SetupAcl('user', 'password')

        app = Flask('mtj.flask.acl')
        app.config['SECRET_KEY'] = 'test_secret_key'
        auth = self.auth(app, permission_denied_handler=None)

        app.register_blueprint(user.acl_front, url_prefix='/acl')

        app.config['TESTING'] = True
        self.app = app

    def tearDown(self):
        pass

    def test_core(self):
        # ensure the admin role is correctly added.
        self.assertEqual(self.app.config['MTJ_ACL'], self.auth)
        self.assertTrue('admin' in flask._roles)

    def test_login_form(self):
        with self.app.test_client() as c:
            rv = c.get('/acl/login')
            self.assertFalse('<input type="hidden" name="next"' in rv.data)

            rv = c.get('/acl/login?n=%2Fpage')
            self.assertTrue('<input type="hidden" name="next" value="/page"' 
                in rv.data)

            rv = c.post('/acl/login',
                data={'login': 'admin', 'password': 'wrongpassword'})
            self.assertFalse('<input type="hidden" name="next"' in rv.data)

            rv = c.post('/acl/login',
                data={'login': 'admin', 'password': 'wrongpassword',
                    'next': '/page'})
            self.assertTrue('<input type="hidden" name="next" value="/page"' 
                in rv.data)

    def test_login_pass(self):
        with self.app.test_client() as c:
            rv = c.post('/acl/login',
                data={'login': 'admin', 'password': 'password'})
            self.assertEqual(rv.status_code, 302)
            self.assertEqual(rv.headers['location'], 'http://localhost/')

        with self.app.test_client() as c:
            rv = c.post('/acl/login',
                data={'login': 'admin', 'password': 'password',
                    'next': '/page'})
            self.assertEqual(rv.status_code, 302)
            self.assertEqual(rv.headers['location'], 'http://localhost/page')

    def test_login_fail(self):
        with self.app.test_client() as c:
            rv = c.post('/acl/login',
                data={'login': 'admin', 'password': 'fail'})
            self.assertEqual(rv.status_code, 200)
            self.assertTrue('Invalid credentials' in rv.data)

    def test_list_user(self):
        with self.app.test_client() as c:
            # rv = c.get('/acl/list')
            # self.assertFalse('<td>admin</td>' in rv.data)

            self.assertRaises(PermissionDenied, c.get, '/acl/list')

            rv = c.post('/acl/login',
                data={'login': 'admin', 'password': 'password'})
            rv = c.get('/acl/list')
            self.assertTrue('<td>admin</td>' in rv.data)

    def test_current_user_options(self):
        with self.app.test_client() as c:
            rv = c.post('/acl/login',
                data={'login': 'admin', 'password': 'password'})
            rv = c.get('/acl/current')
            self.assertTrue('<a href="add">' in rv.data)
            self.assertTrue('<a href="list">' in rv.data)

            rv = c.post('/acl/logout')
            self.assertTrue(flask.getCurrentUser() in (None, anonymous))

            rv = c.post('/acl/login',
                data={'login': 'user', 'password': 'password'})
            rv = c.get('/acl/current')
            self.assertFalse('<a href="add">' in rv.data)
            self.assertFalse('<a href="list">' in rv.data)

    def test_edit_user(self):
        with self.app.test_client() as c:
            rv = c.post('/acl/login',
                data={'login': 'admin', 'password': 'password'})
            rv = c.get('/acl/edit/admin')
            self.assertTrue('value="admin">' in rv.data)
            rv = c.get('/acl/edit/nouser')
            self.assertTrue('<h1>Not Found</h1>' in rv.data)

    def test_passwd(self):
        with self.app.test_client() as c:
            rv = c.post('/acl/login',
                data={'login': 'admin', 'password': 'password'})

            rv = c.post('/acl/passwd')
            self.assertTrue('Please fill out all the required fields.'
                in rv.data)

            rv = c.post('/acl/passwd', data={
                'old_password': 'fail', 'password': 'newpassword',
                'confirm_password': 'failure'})
            self.assertTrue('Old password incorrect' in rv.data)

            rv = c.post('/acl/passwd', data={
                'old_password': 'password', 'password': 'newpassword',
                'confirm_password': 'failure'})
            self.assertTrue('Password and confirmation password mismatched.'
                in rv.data)

            rv = c.post('/acl/passwd', data={
                'old_password': 'password', 'password': '1',
                'confirm_password': '1'})
            self.assertTrue('New password too short.' in rv.data)

            rv = c.post('/acl/passwd', data={
                'old_password': 'password', 'password': '123456',
                'confirm_password': '123456'})
            self.assertTrue('Error updating password.' in rv.data)


if __name__ == '__main__':
    unittest.main()
