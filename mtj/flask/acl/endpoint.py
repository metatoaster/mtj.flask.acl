from __future__ import absolute_import

from flask import Blueprint, Flask, request, g, make_response, render_template
from flask import abort, flash, url_for, current_app, session, redirect

from mtj.flask.acl.base import anonymous
from mtj.flask.acl.exc import SiteAclMissingError
from mtj.flask.acl.flask import *

def login():
    acl_back = current_app.config.get('MTJ_ACL')
    if not acl_back:
        raise SiteAclMissingError

    if request.method == 'GET':
        result = render_template('login.jinja', next=request.args.get('n'))
        return result

    error = None
    login = request.form.get('login')
    password = request.form.get('password')
    user = acl_back.authenticate(login, password)

    if user:
        session['mtj.user'] = user
        flash('Welcome %s' % user['login'])
        script_root = getattr(request, 'script_root', '')
        return redirect(script_root + request.form.get('next', ''))
    else:
        error = 'Invalid credentials'

    result = render_template('login.jinja', error_msg=error,
        next=request.form.get('next'))
    return result

def logout():
    if getCurrentUser() not in (None, anonymous):
        session.pop('logged_in', None)
        session.pop('mtj.user', None)
        # cripes bad way to display a message while ensuring the nav
        # elements for logged in users are not displayed.
        return redirect(url_for('.logout'))
    result = render_template('logout.jinja')
    return result

def current():
    result = render_template('user.jinja', user=getCurrentUser(),
        permit_names=getCurrentUserPermits())
    return result

@require_permit('manager', 'admin')
def user_list():
    acl_back = current_app.config.get('MTJ_ACL')
    users = acl_back.listUsers()
    result = render_template('user_list.jinja', users=users)
    response = make_response(result)
    return response

@require_permit('manager', 'admin')
def user_add():
    acl_back = current_app.config.get('MTJ_ACL')

    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        name = request.form.get('name')
        email = request.form.get('email')
        result = acl_back.register(login, password, name, email)
        if result:
            flash('User created')
            return redirect(url_for('.user_edit', user_login=login))
        flash('Failed to create user %s as it already exists.' % login)

    result = render_template('user_add.jinja')
    response = make_response(result)
    return response

@require_permit('manager', 'admin')
def user_edit(user_login):
    acl_back = current_app.config.get('MTJ_ACL')

    user = acl_back.getUser(user_login)
    if user is anonymous or user is None:
        # XXX catching both variations?
        abort(404)

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        acl_back.editUser(user_login, name, email)
        flash('User updated')
        return redirect(url_for('.user_edit', user_login=user_login))

    result = render_template('user_edit.jinja', user=user)
    response = make_response(result)
    return response

def change_password_form(user, admin_mode=False):
    acl_back = current_app.config.get('MTJ_ACL')
    result = error_msg = None

    if request.method == 'POST':
        old_password = request.form.get('old_password')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # verification is done all the way through, but in reverse order
        if not (password and len(password) > 5):
            error_msg = 'New password too short.'
        if not password == confirm_password:
            error_msg = 'Password and confirmation password mismatched.'
        if not admin_mode:
            if not acl_back.validate(user.login, old_password):
                error_msg = 'Old password incorrect.'
        if not admin_mode:
            if not (old_password or password or confirm_password):
                error_msg = 'Please fill out all the required fields.'

        if not error_msg:
            result = acl_back.updatePassword(user.login, password)
            if result:
                flash('Password updated')
            else:
                error_msg = 'Error updating password.'

    result = render_template('user_passwd.jinja', user=user,
        admin_mode=admin_mode, error_msg=error_msg)
    response = make_response(result)
    return response

@require_permit('self_passwd', 'admin')
def passwd():
    user = getCurrentUser()
    return change_password_form(user)

@require_permit('admin')
def passwd_admin(user_login):
    acl_back = current_app.config.get('MTJ_ACL')
    user = acl_back.getUser(user_login)
    if user is anonymous or user is None:
        # XXX catching both variations?
        abort(404)
    return change_password_form(user, admin_mode=True)

# Group Management

@require_permit('manager', 'admin')
def group_list():
    acl_back = current_app.config.get('MTJ_ACL')
    groups = acl_back.listGroups()
    result = render_template('group_list.jinja', groups=groups)
    response = make_response(result)
    return response

@require_permit('manager', 'admin')
def group_user(user_login):
    acl_back = current_app.config.get('MTJ_ACL')
    error_msg = None

    user = acl_back.getUser(user_login)
    if user is anonymous or user is None:
        abort(404)

    if request.method == 'POST':
        acl_back.setUserGroups(user, request.form.getlist('group'))
        flash('Groups assigned to user.')
        return redirect(url_for('.group_user', user_login=user.login))

    all_groups = acl_back.listGroups()
    user_groups_names = [ug.name for ug in acl_back.getUserGroups(user)]

    result = render_template('group_user.jinja', user=user,
        user_groups_names=user_groups_names, all_groups=all_groups,
        error_msg=error_msg)
    response = make_response(result)
    return response

@require_permit('manager', 'admin')
def group_add():
    acl_back = current_app.config.get('MTJ_ACL')
    error_msg = None

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        if not name:
            error_msg = 'Name is required.'
        if acl_back.getGroup(name):
            error_msg = 'Group already exists.'

        if error_msg is None:
            acl_back.addGroup(name, description)
            flash('Group added.')
            return redirect(url_for('.group_edit', group_name=name))

    result = render_template('group_add.jinja', error_msg=error_msg)
    response = make_response(result)
    return response

@require_permit('manager', 'admin')
def group_edit(group_name):
    acl_back = current_app.config.get('MTJ_ACL')

    group = acl_back.getGroup(group_name)
    if group is None:
        abort(404)

    if request.method == 'POST':
        description = request.form.get('description')
        acl_back.editGroup(group_name, description)
        acl_back.setGroupPermits(group, request.form.getlist('permit'))
        flash('Group updated')
        return redirect(url_for('.group_edit', group_name=group_name))

    group_permits = acl_back.getGroupPermits(group)
    permits = getPermits()

    result = render_template('group_edit.jinja',
        group=group, permits=permits, group_permits=group_permits)
    response = make_response(result)
    return response