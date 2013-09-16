from __future__ import absolute_import

import functools

from flask import Blueprint, Flask, request, g, make_response, render_template
from flask import abort, flash, url_for, current_app, session, redirect
from flask import Markup

# TODO we should move this whole thing into a separate module.
from mtj.flask.acl.base import anonymous

from mtj.flask.acl import endpoint
from mtj.flask.acl.flask import *


def make_acl_front(name='acl_front', import_name='mtj.flask.acl.user',
        layout='layout.html', template_folder='templates'):

    acl_front = Blueprint(name, import_name, template_folder=template_folder)

    def render_with_layout(f):
        # XXX trap exceptions here?
        @functools.wraps(f)
        def wrapper(*a, **kw):
            contents = f(*a, **kw)
            if not isinstance(contents, basestring):
                return contents
            raw_contents = Markup(contents)
            result = render_template(layout, contents=raw_contents)
            response = make_response(result)
            return response
        return wrapper

    # XXX the following can probably be replaced with a dictionary and
    # some sort of constructer.

    @acl_front.route('/login', methods=['GET', 'POST'])
    @render_with_layout
    def login():
        return endpoint.login()

    @acl_front.route('/logout', methods=['GET', 'POST'])
    @render_with_layout
    def logout():
        return endpoint.logout()

    @acl_front.route('/current')
    @render_with_layout
    def current():
        return endpoint.current()

    @acl_front.route('/list')
    @render_with_layout
    def user_list():
        return endpoint.user_list()

    @acl_front.route('/add', methods=['GET', 'POST'])
    @render_with_layout
    def user_add():
        return endpoint.user_add()

    @acl_front.route('/edit/<user_login>', methods=['GET', 'POST'])
    @render_with_layout
    def user_edit(user_login):
        return endpoint.user_edit(user_login)

    @acl_front.route('/passwd', methods=['GET', 'POST'])
    @render_with_layout
    def passwd():
        return endpoint.passwd()

    @acl_front.route('/passwd/<user_login>', methods=['GET', 'POST'])
    @render_with_layout
    def passwd_admin(user_login):
        return endpoint.passwd_admin(user_login)

    # Group Management

    @acl_front.route('/group/list')
    @render_with_layout
    def group_list():
        return endpoint.group_list()

    @acl_front.route('/group/user/<user_login>', methods=['GET', 'POST'])
    @render_with_layout
    def group_user(user_login):
        return endpoint.group_user(user_login)

    @acl_front.route('/group/add', methods=['GET', 'POST'])
    @render_with_layout
    def group_add():
        return endpoint.group_add()

    @acl_front.route('/group/edit/<group_name>', methods=['GET', 'POST'])
    @render_with_layout
    def group_edit(group_name):
        return endpoint.group_edit(group_name)

    return acl_front

# Default
acl_front = make_acl_front()
