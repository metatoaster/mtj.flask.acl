from __future__ import absolute_import

from werkzeug.exceptions import HTTPException

from flask import current_app
from flask import abort
from flask import g
from flask import session
from flask import request

from flask.ext.principal import PermissionDenied

from flask.ext.principal import Principal
from flask.ext.principal import RoleNeed
from flask.ext.principal import identity_loaded

from flask.ext.principal import Identity
from flask.ext.principal import AnonymousIdentity

from .base import anonymous


class AclIdentity(Identity):

    def __init__(self, access_token, auth_type=None):
        Identity.__init__(self, None, auth_type)
        self.access_token = access_token


class AclAnonymousIdentity(AclIdentity, AnonymousIdentity):

    def __init__(self, access_token=None, auth_type=None):
        AclIdentity.__init__(self, None, auth_type)


def acl_session_identity_loader():
    if 'mtj.access_token' in session and 'identity.auth_type' in session:
        identity = AclIdentity(session['mtj.access_token'],
                            session['identity.auth_type'])
        return identity

def acl_session_identity_saver(identity):
    if isinstance(identity, AclIdentity):
        session['mtj.access_token'] = identity.access_token
        session['identity.auth_type'] = identity.auth_type
        session.modified = True

def handle_permission_denied(error):
    if g.identity and g.identity.id is not None:
        code = 403
    else:
        code = 401

    # XXX since the custom exception error handler is done after the
    # default http ones, we work around this limitation.
    try:
        abort(code)
    except HTTPException as e:
        return current_app.handle_http_exception(e)

def init_app(acl, app, mtjacl_sessions=True,
        permission_denied_handler=handle_permission_denied, *a, **kw):

    # Not using the default session.
    principal = Principal(app, use_sessions=False, *a, **kw)

    @identity_loaded.connect_via(app)
    def on_identity_loaded(sender, identity):
        if not isinstance(identity, AclIdentity):
            # Not doing anything on identities we don't care for.
            return

        # the identity is actually the raw token
        access_token = identity.access_token
        if access_token is None:
            user = anonymous
        else:
            user = acl.getUserFromAccessToken(access_token)
        # cache this value.
        g.mtj_user = user
        if user is anonymous:
            return
        roles = acl.getUserRoles(user)
        # TODO figure out how to do lazy loading of roles.
        for role in roles:
            identity.provides.add(RoleNeed(role))

        identity.id = user.login

    if mtjacl_sessions:
        principal.identity_loader(acl_session_identity_loader)
        principal.identity_saver(acl_session_identity_saver)

    app.config['MTJ_ACL'] = acl
    if callable(permission_denied_handler):
        app.errorhandler(PermissionDenied)(permission_denied_handler)

    app.before_request(_on_before_request(acl))

def _on_before_request(acl):
    def on_before_request():
        if g.get('mtj_user') in (anonymous, None):
            g.acl_items = [
                ('log in', acl.prefix + '/login'),
            ]
        else:
            g.acl_items = [
                (g.mtj_user.login, acl.prefix + '/current'),
                ('log out', acl.prefix + '/logout'),
            ]

    return on_before_request
