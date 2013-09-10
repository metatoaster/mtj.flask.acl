from __future__ import absolute_import

import functools

from flask import abort, current_app, session, request

from .base import anonymous

# Flask helpers.

_roles = set()
_blueprint_roles = {}

def getCurrentUser():
    access_token = session.get('mtj.user', {})
    acl_back = current_app.config.get('MTJ_ACL', None)
    if acl_back is None:
        return anonymous
    return acl_back.getUserFromAccessToken(access_token)

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

def registerRole(role_name):
    _roles.add(role_name)

def registerBlueprintRole(blueprint, role_name):
    # XXX blueprint needs to resolve to a name, but for now treat this
    # as a string.

    # one blueprint = one role for now.
    if hasattr(blueprint, 'name'):  # blueprints have name
        blueprint = blueprint.name
    _blueprint_roles[blueprint] = role_name
    registerRole(role_name)  # so it will be listed in getRoles

def getBlueprintRole(blueprint):
    return _blueprint_roles.get(blueprint, None)

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

def require_role(*role_names):
    """
    A decorator for specifying the required role to access the view
    this is decorated against.

    Roles are statically defined, and need to be hooked into groups
    which then can be freely customized and assigned with the rights to
    be granted.
    """

    # Add the role into some global list for ease of assignment.
    # Ideally this should be within the app the function will ultimately
    # be accessed from, but that is impossible to determine so just
    # store the role name into a global list available from within
    # this module.

    for role_name in role_names:
        registerRole(role_name)

    def decorator(f):
        @functools.wraps(f)
        def wrapper(*a, **kw):
            verifyUserRole(*role_names)
            return f(*a, **kw)
        return wrapper
    return decorator
