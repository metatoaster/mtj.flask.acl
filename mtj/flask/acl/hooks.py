from flask import g, request, current_app, abort

from mtj.flask.acl.flask import getCurrentUser
from mtj.flask.acl.base import anonymous

from . import csrf

def csrf_protect():
    current_user = getCurrentUser()
    if current_user in (anonymous, None):
        # zero protection for anonymous users.
        return
    g.csrf_input = current_app.config['MTJ_CSRF'].render()
    if request.method == 'POST':
        token = request.form.get(csrf.csrf_key)
        if token != current_app.config['MTJ_CSRF'].getSecretFor(
                current_user.login):
            # TODO make this 403 specific to token failure (tell user
            # to reload the form in case of changes in hash.
            abort(403)
