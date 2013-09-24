from __future__ import absolute_import

from werkzeug.exceptions import HTTPException

from flask import current_app
from flask import abort
from flask import g
from flask import session

from flask.ext.principal import PermissionDenied

from flask.ext.principal import Principal
from flask.ext.principal import RoleNeed
from flask.ext.principal import identity_loaded

from flask.ext.principal import Identity

from .base import anonymous


class AclIdentity(Identity):

    def __init__(self, access_token, auth_type=None):
        super(AclIdentity, self).__init__(None, auth_type)
        self.access_token = access_token


def acl_session_identity_loader():
    if 'mtj.access_token' in session and 'identity.auth_type' in session:
        identity = AclIdentity(session['mtj.access_token'],
                            session['identity.auth_type'])
        return identity

def acl_session_identity_saver(identity):
    if isinstance(identity, AclIdentity):
        session['mtj.access_token'] = identity.access_token
        session.modified = True

def init_app(acl, app, mtjacl_sessions=True, *a, **kw):

    # Not using the default session.
    principal = Principal(app, *a, **kw)

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
    @app.errorhandler(PermissionDenied)
    def permission_denied(error):
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
