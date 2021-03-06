from unittest import TestCase, TestSuite, makeSuite

from flask import Flask, session
from flask.ext.principal import PermissionDenied

from mtj.flask.acl import sql
from mtj.flask.acl import flask
from mtj.flask.acl import user

def filter_gn(groups):
    results = [ug.name for ug in groups]
    return tuple(sorted(results))


class AclTestCase(TestCase):

    def setUp(self):
        self.auth = sql.SqlAcl()

    def tearDown(self):
        pass

    def test_core_acl(self):
        auth = self.auth
        self.assertTrue(auth.register('admin', 'password'))
        users = auth.listUsers()
        self.assertEqual(users[0].login, 'admin')
        self.assertNotEqual(users[0].password, 'password')

        self.assertFalse(auth.authenticate('admin', 'nope'))
        self.assertTrue(auth.authenticate('admin', 'password'))

    def test_too_short_password(self):
        # too short of a password
        self.assertFalse(self.auth.register('admin', ''))
        self.assertFalse(self.auth.register('admin', '1'))

    def test_list_users(self):
        auth = self.auth
        auth.register('admin', 'password')
        auth.register('user', 'secret')
        users = auth.listUsers()
        self.assertEqual(users[0].login, 'admin')
        self.assertNotEqual(users[0].password, 'password')
        self.assertEqual(users[1].login, 'user')
        self.assertNotEqual(users[1].password, 'secret')

        self.assertEqual(auth.getUser('admin').login, 'admin')
        self.assertEqual(auth.getUser('user').login, 'user')

    def test_edit_user(self):
        auth = self.auth
        auth.register('user', 'password')
        user = auth.getUser('user')
        self.assertEqual(user.name, None)
        self.assertEqual(user.email, None)
        auth.editUser('user', 'User Name', 'user@example.com')
        user = auth.getUser('user')
        self.assertEqual(user.name, 'User Name')
        self.assertEqual(user.email, 'user@example.com')

    def test_edit_passwd(self):
        auth = self.auth
        auth.register('user', 'password')
        user = auth.getUser('user')
        self.assertTrue(auth.validate('user', 'password'))

        self.assertFalse(auth.updatePassword('user', None))
        self.assertTrue(auth.validate('user', 'password'))

        self.assertFalse(auth.updatePassword('user', 'short'))
        self.assertTrue(auth.validate('user', 'password'))

        self.assertTrue(auth.updatePassword('user', 'secret'))
        self.assertFalse(auth.validate('user', 'password'))
        self.assertTrue(auth.validate('user', 'secret'))

    def test_dupe_register(self):
        auth = self.auth
        self.assertTrue(auth.register('admin', 'password'))
        self.assertFalse(auth.register('admin', 'password', 'bad@example.com'))

    def test_bad_login(self):
        auth = self.auth
        self.assertFalse(auth.authenticate('admin', 'password'))
        self.assertFalse(auth.authenticate('no', 'user'))

    def test_group_base(self):
        auth = self.auth
        auth.addGroup('admin',)
        auth.addGroup('user', 'Normal users')

        groups = auth.listGroups()
        # builtin.
        self.assertEqual(groups[0].name, 'admin')
        self.assertEqual(groups[1].name, 'user')
        self.assertEqual(groups[1].description, 'Normal users')

        self.assertEqual(auth.getGroup('user').description, 'Normal users')
        self.assertEqual(auth.getGroup('dummy'), None)

    def test_user_group(self):
        auth = self.auth
        auth.register('admin', 'password')
        auth.addGroup('admin')
        auth.addGroup('user')

        admin_user = auth.getUser('admin')

        self.assertEqual(filter_gn(auth.getUserGroups(admin_user)), ())
        auth.setUserGroups(admin_user, ('admin',))
        self.assertEqual(filter_gn(auth.getUserGroups(admin_user)), ('admin',))
        auth.setUserGroups(admin_user, ('user',))
        self.assertEqual(filter_gn(auth.getUserGroups(admin_user)), ('user',))
        auth.setUserGroups(admin_user, ('user', 'admin'))
        self.assertEqual(filter_gn(auth.getUserGroups(admin_user)),
            ('admin', 'user',))

        # Addition of non-existent groups fail silently.
        auth.setUserGroups(admin_user, ('user', 'nimda'))
        self.assertEqual(filter_gn(auth.getUserGroups(admin_user)), ('user',))

    def test_group_roles(self):
        auth = self.auth
        auth.addGroup('nimda')
        group = auth.getGroup('nimda')
        self.assertEqual(auth.getGroupRoles(group), set())
        auth.setGroupRoles(group, ('admin',))
        self.assertEqual(auth.getGroupRoles(group), {'admin',})

        auth.setGroupRoles(group, ('admin', 'test'))
        self.assertEqual(auth.getGroupRoles(group), {'admin',})

        flask._roles.add('__test')
        auth.setGroupRoles(group, ('admin', '__test'))
        self.assertEqual(auth.getGroupRoles(group), {'admin', '__test'})
        flask._roles.remove('__test')

    def test_user_roles(self):
        flask._roles.add('__test1')
        flask._roles.add('__test2')

        auth = self.auth
        auth.addGroup('user')
        auth.addGroup('nimda')
        auth.register('user1', 'secret')
        auth.register('user2', 'secret')

        group_user = auth.getGroup('user')
        group_nimda = auth.getGroup('nimda')
        user1 = auth.getUser('user1')
        user2 = auth.getUser('user2')

        # null case
        self.assertEqual(auth.getUserRoles(user1), set())

        auth.setGroupRoles(group_user, ('__test1', '__test2'))
        auth.setGroupRoles(group_nimda, ('admin', '__test2'))

        auth.setUserGroups(user1, ('user',))
        self.assertEqual(auth.getUserRoles(user1), {'__test1', '__test2'})

        auth.setUserGroups(user2, ('nimda',))
        self.assertEqual(auth.getUserRoles(user2), {'admin', '__test2'})

        auth.setUserGroups(user1, ('user', 'nimda',))
        self.assertEqual(auth.getUserRoles(user1),
            {'admin', '__test1', '__test2'})

        auth.setGroupRoles(group_user, ('__test2',))
        self.assertEqual(auth.getUserRoles(user1), {'admin', '__test2'})
        self.assertEqual(auth.getUserRoles(user2), {'admin', '__test2'})

        auth.setGroupRoles(group_nimda, ())
        self.assertEqual(auth.getUserRoles(user1), {'__test2'})
        self.assertEqual(auth.getUserRoles(user2), set())

        flask._roles.remove('__test1')
        flask._roles.remove('__test2')

    def test_setup_login(self):
        auth = sql.SqlAcl(setup_login='admin')
        self.assertEqual(auth.getUser('admin'), None)
        auth = sql.SqlAcl(setup_login='admin', setup_password='password')
        self.assertEqual(auth.getUser('admin').login, 'admin')
        self.assertTrue(auth.authenticate('admin', 'password'))
        # XXX verify that the admin role is set correctly.

        admin_grp = auth.getGroup('admin')
        self.assertEqual(admin_grp.name,
            auth.getUserGroups(auth.getUser('admin'))[0].name)

        # revoke admin
        auth.setUserGroups(auth.getUser('admin'), ())
        auth._registerAdmin('admin', 'password')
        # Should not have any groups as this login was previously
        # registered.
        self.assertEqual(len(auth.getUserGroups(auth.getUser('admin'))), 0)


class UserSqlAclIntegrationTestCase(TestCase):

    def setUp(self):
        self.auth = sql.SqlAcl(setup_login='admin', setup_password='password')

        app = Flask('mtj.flask.acl')
        auth = self.auth(app, permission_denied_handler=None)

        app.config['SECRET_KEY'] = 'test_secret_key'
        app.register_blueprint(user.acl_front, url_prefix='/acl')

        app.config['TESTING'] = True
        self.app = app
        self.client = self.app.test_client()

        with self.client as c:
            rv = c.post('/acl/login',
                data={'login': 'admin', 'password': 'password'})

    def test_list_user(self):
        with self.client as c:
            rv = c.get('/acl/list')
            self.assertTrue('<td>admin</td>' in rv.data)

    def test_add_user(self):
        with self.client as c:
            rv = c.get('/acl/add')
            self.assertTrue('name="name" value=""' in rv.data)
            self.assertTrue('name="email" value=""' in rv.data)

            rv = c.post('/acl/add', data={
                'login': 'user',
                'password': 'userpassword',
                'name': 'User Name',
                'email': 'user@example.com',
            })
            self.assertEqual(rv.headers['location'],
                'http://localhost/acl/edit/user')

            r2 = c.get('/acl/edit/user')

            self.assertTrue('name="login" value="user"' in r2.data)
            self.assertTrue('name="name" value="User Name"' in r2.data)
            self.assertTrue('name="email" value="user@example.com"' in r2.data)

        with self.app.test_client() as c:
            # Now try logging in using the newly added user.
            rv = c.post('/acl/login',
                data={'login': 'user', 'password': 'userpassword'})
            self.assertEqual(rv.headers['location'],
                'http://localhost/')

            rv = c.get('/acl/current')
            self.assertTrue('Hello, user.' in rv.data)

    def test_edit_user(self):
        with self.client as c:
            rv = c.get('/acl/edit/admin')
            self.assertTrue('name="name" value=""' in rv.data)
            self.assertTrue('name="email" value=""' in rv.data)

            rv = c.post('/acl/edit/admin',
                data={'name': 'User Name', 'email': 'user@example.com'})
            rv = c.get('/acl/edit/admin')
            self.assertTrue('name="name" value="User Name"' in rv.data)
            self.assertTrue('name="email" value="user@example.com"' in rv.data)

            rv = c.get('/acl/edit/nouser')
            self.assertTrue('<h1>Not Found</h1>' in rv.data)

    def test_passwd(self):
        with self.app.test_client() as c:
            rv = c.post('/acl/login',
                data={'login': 'admin', 'password': 'password'})

            # kind of a waste repeating it here but eh.
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
            self.assertTrue(self.auth.validate('admin', '123456'))

    def test_passwd_other(self):
        self.auth.register('test_user', 'password')

        with self.app.test_client() as c:
            rv = c.post('/acl/login',
                data={'login': 'admin', 'password': 'password'})

            rv = c.post('/acl/passwd/test_user')
            self.assertTrue('New password too short.' in rv.data)

            rv = c.post('/acl/passwd/test_user', data={
                'password': 'newpassword', 'confirm_password': 'failure'})
            self.assertTrue('Password and confirmation password mismatched.'
                in rv.data)

            rv = c.post('/acl/passwd/test_user', data={
                'password': '1', 'confirm_password': '1'})
            self.assertTrue('New password too short.' in rv.data)

            rv = c.post('/acl/passwd/test_user', data={
                'password': '123456', 'confirm_password': '123456'})
            self.assertTrue(self.auth.validate('test_user', '123456'))

    def test_passwd_noperm(self):
        self.auth.register('test_user', 'password')
        with self.app.test_client() as c:
            rv = c.post('/acl/login',
                data={'login': 'test_user', 'password': 'password'})

            # rv = c.get('/acl/passwd')
            # self.assertEqual(rv.status_code, 403)

            self.assertRaises(PermissionDenied, c.get, '/acl/passwd')

    def test_user_group(self):
        auth = self.auth
        auth.register('test_user', 'password')
        auth.addGroup('user')
        auth.addGroup('reviewer')

        test_user = auth.getUser('test_user')

        with self.client as c:
            rv = c.get('/acl/group/user/test_user')
            self.assertTrue('value="test_user"' in rv.data)
            self.assertTrue('name="group" value="user"' in rv.data)
            self.assertTrue('name="group" value="reviewer"' in rv.data)

            # single group assignment
            rv = c.post('/acl/group/user/test_user',
                data={'group': 'user'})
            rv = c.get('/acl/group/user/test_user')
            self.assertEqual(filter_gn(auth.getUserGroups(test_user)),
                (u'user',))
            self.assertTrue('name="group" value="user" checked="checked"'
                in rv.data)

            # multiple group assignments
            rv = c.post('/acl/group/user/test_user',
                data={'group': ['user', 'reviewer']})
            rv = c.get('/acl/group/user/test_user')
            self.assertEqual(filter_gn(auth.getUserGroups(test_user)),
                (u'reviewer', u'user'))

            # non-existent group assignments
            rv = c.post('/acl/group/user/test_user',
                data={'group': ['user', 'fakegroup']})
            rv = c.get('/acl/group/user/test_user')
            self.assertEqual(filter_gn(auth.getUserGroups(test_user)),
                (u'user',))

            # Finally test that nouser will also 404.
            rv = c.get('/acl/group/edit/nouser')
            self.assertTrue('<h1>Not Found</h1>' in rv.data)

    def test_group_add(self):
        with self.client as c:
            rv = c.post('/acl/group/add', data={
                'name': 'testgroup',
                'description': 'A new test group',
            })
            self.assertEqual(rv.headers['location'],
                'http://localhost/acl/group/edit/testgroup')

            rv = c.get('/acl/group/edit/testgroup')
            self.assertTrue('value="testgroup"' in rv.data)
            self.assertTrue('value="A new test group"' in rv.data)

    def test_group_add_sanity_check(self):
        with self.client as c:
            rv = c.post('/acl/group/add', data={
                'name': '',
                'description': '',
            })
            self.assertNotEqual(rv.headers.get('location'),
                'http://localhost/acl/group/edit/')
            self.assertTrue('Name is required.' in rv.data)

            rv = c.post('/acl/group/add', data={'name': 'test'})
            rv = c.post('/acl/group/add', data={'name': 'test'})
            self.assertTrue('already exists.' in rv.data)

    def test_group_roles(self):
        flask._roles.add('__test1')
        flask._roles.add('__test2')

        auth = self.auth
        auth.addGroup('test_group')
        test_group = auth.getGroup('test_group')

        with self.client as c:
            rv = c.get('/acl/group/edit/test_group')
            self.assertTrue('value="test_group"' in rv.data)
            self.assertTrue('name="role" value="__test1"' in rv.data)
            self.assertTrue('name="role" value="__test2"' in rv.data)

            # single group assignment
            rv = c.post('/acl/group/edit/test_group', data={
                'description': 'Test',
                'role': ['__test2'],
            })
            rv = c.get('/acl/group/edit/test_group')
            self.assertEqual(auth.getGroup('test_group').description, 'Test')
            self.assertTrue('name="role" value="__test2" checked="checked"'
                in rv.data)

            # non-existent group assignments
            rv = c.post('/acl/group/edit/test_group', data={
                'role': ['__test1', 'nimda'],
            })
            self.assertEqual(auth.getGroupRoles(test_group), {'__test1'})

            # Finally test that a missing group will 404.
            rv = c.get('/acl/group/edit/no_group')
            self.assertTrue('<h1>Not Found</h1>' in rv.data)

        flask._roles.remove('__test1')
        flask._roles.remove('__test2')

    def test_group_list(self):
        auth = self.auth
        auth.addGroup('user')
        auth.addGroup('reviewer')

        with self.client as c:
            rv = c.get('/acl/group/list')
            self.assertTrue('<td>admin</td>' in rv.data)
            self.assertTrue('<td>user</td>' in rv.data)
            self.assertTrue('<td>reviewer</td>' in rv.data)


def test_suite():
    suite = TestSuite()
    suite.addTest(makeSuite(AclTestCase))
    suite.addTest(makeSuite(UserSqlAclIntegrationTestCase))
    return suite

if __name__ == '__main__':
    import unittest
    unittest.main()
