from __future__ import absolute_import

from flask import abort
from flask import g

from flask.ext.principal import PermissionDenied

from flask.ext.principal import Principal
from flask.ext.principal import RoleNeed
from flask.ext.principal import identity_loaded

from flask.ext.principal import Identity

from .base import anonymous


def init_app(acl, app, use_sessions=True, *a, **kw):

    # Not using the default session.
    principal = Principal(app, use_sessions, *a, **kw)

    @identity_loaded.connect_via(app)
    def on_identity_loaded(sender, identity):
        # the identity is actually the raw token
        access_token = identity.id
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

    app.config['MTJ_ACL'] = acl
