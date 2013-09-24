from __future__ import absolute_import

from flask import abort, current_app, session, request, g
from flask.ext.principal import Permission, RoleNeed

from .base import anonymous

# Flask helpers.

_roles = set()
_blueprint_roles = {}

def getCurrentUser():
    return g.mtj_user

def getCurrentUserGroupNames():
    user = getCurrentUser()
    acl_back = current_app.config.get('MTJ_ACL')
    return [gp.name for gp in acl_back.getUserGroups(user)]

def getCurrentUserRoles():
    user = getCurrentUser()
    acl_back = current_app.config.get('MTJ_ACL')
    if acl_back is None:
        return []
    return acl_back.getUserRoles(user)

def getRoles():
    return sorted(list(_roles))

def register_role(role):
    _roles.add(role)
    return RoleNeed(role)

def verifyUserGroupByName(group):
    if not group in getCurrentUserGroupNames():
        abort(403)
    return True

def verifyUserRole(*roles):
    acl_back = current_app.config.get('MTJ_ACL')
    for role in roles:
        if role in getCurrentUserRoles():
            return True
    if not current_app.config.get('MTJ_IGNORE_PERMIT'):
        abort(403)

def verifyBlueprintRole():
    blueprint_role = getBlueprintRole(request.blueprint)
    if blueprint_role:
        verifyUserRole(blueprint_role)

def permission_from_roles(*roles):
    # XXX make this (rather, register_role) workable from within an app
    # context so that they get registered to just that app.
    return Permission(*[register_role(role) for role in roles])
