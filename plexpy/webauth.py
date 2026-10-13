# -*- coding: utf-8 -*-

#  This file is part of Tautulli.
#
#  Tautulli is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Tautulli is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with Tautulli.  If not, see <http://www.gnu.org/licenses/>.


# https://github.com/cherrypy/tools/blob/master/AuthenticationAndAccessRestrictions
# Form based authentication for CherryPy. Requires the
# Session tool to be loaded.

from datetime import datetime, timedelta, timezone
from hmac import compare_digest
from urllib.parse import quote, unquote

import cherrypy
from hashing_passwords import check_hash
import jwt

import plexpy
from plexpy import logger
from plexpy import oidc
from plexpy.database import MonitorDatabase
from plexpy.helpers import hash_pms_uuid, timestamp
from plexpy.session import generate_csrf_token
from plexpy.users import Users, refresh_users
from plexpy.plextv import PlexTV

# Monkey patch SameSite support into cookies.
# https://stackoverflow.com/a/50813092
try:
    from http.cookies import Morsel
except ImportError:
    from Cookie import Morsel
Morsel._reserved[str('samesite')] = str('SameSite')

JWT_ALGORITHM = 'HS256'
JWT_COOKIE_NAME = 'tautulli_token_'
OIDC_SESSION_KEY = '_oidc_login_requests'


def use_basic_auth(http_password, http_basic_auth):
    """Returns True if HTTP basic authentication protects the web interface."""
    return bool(http_password) and bool(http_basic_auth)


def use_form_auth(http_password, http_basic_auth, oidc_enabled):
    """Form login protects the web interface whenever any login method is configured,
    unless HTTP basic authentication replaces it. OIDC enables it on its own, without a password,
    so a broken OIDC config or provider outage leaves the web interface locked instead of open."""
    if use_basic_auth(http_password, http_basic_auth):
        return False
    return bool(http_password) or bool(oidc_enabled)


def plex_user_login(token=None, headers=None):
    user_token = None
    user_id = None

    # Try to login to Plex.tv to check if the user has a valid account
    if token:
        plex_tv = PlexTV(token=token, headers=headers)
        plex_user = plex_tv.get_plex_account_details()
        if plex_user:
            user_token = token
            user_id = plex_user['user_id']
    else:
        return None

    if user_token and user_id:
        # Try to retrieve the user from the database.
        # Also make sure guest access is enabled for the user and the user is not deleted or archived.
        user_data = Users()
        user_details = user_data.get_details(user_id=user_id)
        if user_id != str(user_details['user_id']):
            # The user is not in the database.
            return None
        elif plexpy.CONFIG.HTTP_PLEX_ADMIN and user_details['is_admin']:
            # Plex admin login
            return user_details, 'admin'
        elif not user_details['allow_guest'] or user_details['deleted_user'] or user_details['is_archived']:
            # Guest access is disabled or the user is deleted or archived.
            return None

        # Stop here if guest access is not enabled
        if not plexpy.CONFIG.ALLOW_GUEST_ACCESS:
            return None

        # The user is in the database, and guest access is enabled, so try to retrieve a server token.
        # If a server token is returned, then the user is a valid friend of the server.
        plex_tv = PlexTV(token=user_token, headers=headers)
        server_token = plex_tv.get_server_token()
        if server_token:

            # Register the new user / update the access tokens.
            monitor_db = MonitorDatabase()
            try:
                logger.debug("Tautulli WebAuth :: Registering token for user '%s' in the database."
                             % user_details['username'])
                result = monitor_db.action("UPDATE users SET server_token = ? WHERE user_id = ?",
                                           [server_token, user_details['user_id']])

                if result:
                    # Refresh the users list to make sure we have all the correct permissions.
                    refresh_users()
                    # Successful login
                    return user_details, 'guest'
                else:
                    logger.warn("Tautulli WebAuth :: Unable to register user '%s' in database."
                                % user_details['username'])
                    return None
            except Exception as e:
                logger.warn("Tautulli WebAuth :: Unable to register user '%s' in database: %s."
                            % (user_details['username'], e))
                return None
        else:
            logger.warn("Tautulli WebAuth :: Unable to retrieve Plex.tv server token for user '%s'."
                        % user_details['username'])
            return None

    elif token:
        logger.warn("Tautulli WebAuth :: Unable to retrieve Plex.tv user token for Plex OAuth.")
        return None


def check_credentials(username=None, password=None, token=None, admin_login='0', headers=None):
    """Verifies credentials for username and password.
    Returns True and the user group on success or False and no user group"""

    if username and password:
        if plexpy.CONFIG.HTTP_PASSWORD:
            user_details = {'user_id': None, 'username': username}
            if username == plexpy.CONFIG.HTTP_USERNAME and check_hash(password, plexpy.CONFIG.HTTP_PASSWORD):
                return True, user_details, 'admin'

    if plexpy.CONFIG.HTTP_PLEX_ADMIN or (not admin_login == '1' and plexpy.CONFIG.ALLOW_GUEST_ACCESS):
        plex_login = plex_user_login(token=token, headers=headers)
        if plex_login is not None:
            return True, plex_login[0], plex_login[1]

    return False, None, None


def jwt_cookie_name():
    return f"{JWT_COOKIE_NAME}{hash_pms_uuid()}"


def get_jwt_token():
    jwt_cookie = jwt_cookie_name()
    jwt_token = cherrypy.request.cookie.get(jwt_cookie)

    if jwt_token:
        return jwt_token.value


def check_jwt_token():
    jwt_token = get_jwt_token()

    if jwt_token:
        try:
            payload = jwt.decode(
                jwt_token, plexpy.CONFIG.JWT_SECRET, leeway=timedelta(seconds=10), algorithms=[JWT_ALGORITHM]
            )
        except (jwt.DecodeError, jwt.ExpiredSignatureError):
            return None

        if not Users().get_user_login(jwt_token=jwt_token):
            return None

        return payload


def check_auth(*args, **kwargs):
    """A tool that looks in config for 'auth.require'. If found and it
    is not None, a login is required and the entry is evaluated as a list of
    conditions that the user must fulfill"""
    conditions = cherrypy.request.config.get('auth.require', None)
    if conditions is not None:
        payload = check_jwt_token()

        if payload:
            cherrypy.request.login = payload

            for condition in conditions:
                # A condition is just a callable that returns true or false
                if not condition():
                    raise cherrypy.HTTPRedirect(plexpy.HTTP_ROOT)

        else:
            if cherrypy.request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                raise cherrypy.HTTPError(401)
            
            redirect_uri = cherrypy.request.path_info
            if redirect_uri:
                redirect_uri = '?redirect_uri=' + quote(redirect_uri)

            raise cherrypy.HTTPRedirect(plexpy.HTTP_ROOT + "auth/logout" + redirect_uri)


def requireAuth(*conditions):
    """A decorator that appends conditions to the auth.require config
    variable."""
    def decorate(f):
        if not hasattr(f, '_cp_config'):
            f._cp_config = dict()
        if 'auth.require' not in f._cp_config:
            f._cp_config['auth.require'] = []
        f._cp_config['auth.require'].extend(conditions)
        return f
    return decorate


# Conditions are callables that return True
# if the user fulfills the conditions they define, False otherwise
#
# They can access the current username as cherrypy.request.login
#
# Define those at will however suits the application.

def member_of(user_group):
    return lambda: cherrypy.request.login and cherrypy.request.login['user_group'] == user_group


def name_is(user_name):
    return lambda: cherrypy.request.login and cherrypy.request.login['user'] == user_name


# These might be handy

def any_of(*conditions):
    """Returns True if any of the conditions match"""
    def check():
        for c in conditions:
            if c():
                return True
        return False
    return check


# By default all conditions are required, but this might still be
# needed if you want to use it inside of an any_of(...) condition
def all_of(*conditions):
    """Returns True if all of the conditions match"""
    def check():
        for c in conditions:
            if not c():
                return False
        return True
    return check


def check_rate_limit(ip_address):
    monitor_db = MonitorDatabase()
    result = monitor_db.select("SELECT timestamp, success FROM user_login "
                               "WHERE ip_address = ? "
                               "AND timestamp >= ( "
                               "SELECT CASE WHEN MAX(timestamp) IS NULL THEN 0 ELSE MAX(timestamp) END "
                               "FROM user_login WHERE ip_address = ? AND success = 1) "
                               "ORDER BY timestamp DESC",
                               [ip_address, ip_address])

    try:
        last_timestamp = result[0]['timestamp']
    except IndexError:
        last_timestamp = 0

    try:
        last_success = max(login['timestamp'] for login in result if login['success'])
    except ValueError:
        last_success = 0

    max_timestamp = max(last_success, last_timestamp - plexpy.CONFIG.HTTP_RATE_LIMIT_ATTEMPTS_INTERVAL)
    attempts = [login for login in result if login['timestamp'] >= max_timestamp and not login['success']]

    if len(attempts) >= plexpy.CONFIG.HTTP_RATE_LIMIT_ATTEMPTS:
        return max(last_timestamp - (timestamp() - plexpy.CONFIG.HTTP_RATE_LIMIT_LOCKOUT_TIME), 0)


def check_csrf_token():
    if cherrypy.request.path_info.startswith('/api'):
        return

    if (apikey := cherrypy.request.headers.get('X-Api-Key')) and compare_digest(apikey, plexpy.CONFIG.API_KEY):
        return

    if cherrypy.request.method not in ('POST', 'PUT', 'DELETE'):
        return

    session_token = cherrypy.session.get('_csrf_token')
    header_token = cherrypy.request.headers.get('X-CSRF-Token')
    if not session_token or not header_token or not compare_digest(session_token, header_token):
        logger.error("Tautulli WebAuth :: CSRF token validation failed for %s", cherrypy.request.path_info)
        raise cherrypy.HTTPError(403)


# Controller to provide login and logout actions

class AuthController(object):

    def check_auth_enabled(self):
        # Follow the auth tool that is actually running. Settings saved since the last
        # restart must not make the login pages unreachable while pages still require a login.
        if plexpy.AUTH_ENABLED:
            return
        raise cherrypy.HTTPRedirect(plexpy.HTTP_ROOT)

    def on_login(self, username=None, user_id=None, user_group=None, success=False, oauth=False,
                 expiry=None, jwt_token=None, method=None):
        """Called on successful login"""

        # Save login to the database
        ip_address = cherrypy.request.remote.ip
        host = cherrypy.request.base
        user_agent = cherrypy.request.headers.get('User-Agent')

        Users().set_user_login(user_id=user_id,
                               user=username,
                               user_group=user_group,
                               ip_address=ip_address,
                               host=host,
                               user_agent=user_agent,
                               success=success,
                               expiry=expiry,
                               jwt_token=jwt_token)

        if success:
            method = method or ('Plex OAuth' if oauth else 'form')
            logger.debug("Tautulli WebAuth :: %s user '%s' logged into Tautulli using %s login."
                         % (user_group.capitalize(), username, method))

    def on_logout(self, username, user_group, jwt_token=None):
        """Called on logout"""
        jwt_token = get_jwt_token()
        if jwt_token:
            Users().clear_user_login_token(jwt_token=jwt_token)

        logger.debug("Tautulli WebAuth :: %s user '%s' logged out of Tautulli." % (user_group.capitalize(), username))

    def get_loginform(self, redirect_uri='', error=None):
        from plexpy.webserve import serve_template
        # The lock is released once at request end; never double-acquire
        # (serve_template's CSRF helper also acquires)
        if not cherrypy.session.locked:
            cherrypy.session.acquire_lock()
        cherrypy.session['_csrf_token'] = generate_csrf_token()
        return serve_template(template_name="login.html", title="Login", redirect_uri=unquote(redirect_uri),
                              error=error)

    def create_session(self, user_details, user_group, remember_me=False, oauth=False, method=None):
        """Issues the Tautulli JWT cookie for an authenticated user. Returns the JWT payload and token."""
        time_delta = timedelta(days=30) if remember_me else timedelta(minutes=60)
        expiry = datetime.now(tz=timezone.utc) + time_delta

        payload = {
            'user_id': user_details['user_id'],
            'user': user_details['username'],
            'user_group': user_group,
            'exp': expiry
        }

        jwt_token = jwt.encode(payload, plexpy.CONFIG.JWT_SECRET, algorithm=JWT_ALGORITHM)

        self.on_login(username=user_details['username'],
                      user_id=user_details['user_id'],
                      user_group=user_group,
                      success=True,
                      oauth=oauth,
                      expiry=expiry,
                      jwt_token=jwt_token,
                      method=method)

        jwt_cookie = jwt_cookie_name()
        cherrypy.response.cookie[jwt_cookie] = jwt_token
        cherrypy.response.cookie[jwt_cookie]['max-age'] = int(time_delta.total_seconds())
        cherrypy.response.cookie[jwt_cookie]['path'] = plexpy.HTTP_ROOT.rstrip('/') or '/'
        cherrypy.response.cookie[jwt_cookie]['httponly'] = True
        cherrypy.response.cookie[jwt_cookie]['samesite'] = 'lax'

        if not cherrypy.session.locked:
            cherrypy.session.acquire_lock()
        cherrypy.session['_csrf_token'] = generate_csrf_token()
        cherrypy.request.login = payload

        return payload, jwt_token

    def oidc_callback_url(self):
        """Returns the redirect URI to register with the identity provider."""
        # The provider only redirects to registered URLs, so a spoofed Host header cannot leak the code.
        base = plexpy.CONFIG.HTTP_BASE_URL.rstrip('/') or cherrypy.request.base.rstrip('/')
        return base + plexpy.HTTP_ROOT + 'auth/oidc_callback'

    @cherrypy.expose
    def index(self, *args, **kwargs):
        raise cherrypy.HTTPRedirect(plexpy.HTTP_ROOT + "auth/login")

    @cherrypy.expose
    def login(self, redirect_uri='', *args, **kwargs):
        self.check_auth_enabled()

        return self.get_loginform(redirect_uri=redirect_uri)

    @cherrypy.expose
    def logout(self, redirect_uri='', *args, **kwargs):
        self.check_auth_enabled()

        payload = check_jwt_token()
        if payload:
            self.on_logout(username=payload['user'],
                           user_group=payload['user_group'])

        jwt_cookie = jwt_cookie_name()
        cherrypy.response.cookie[jwt_cookie] = ''
        cherrypy.response.cookie[jwt_cookie]['max-age'] = 0
        cherrypy.response.cookie[jwt_cookie]['path'] = plexpy.HTTP_ROOT.rstrip('/') or '/'

        if plexpy.HTTP_ROOT != '/':
            # Also expire the JWT on the root path
            cherrypy.response.headers['Set-Cookie'] = jwt_cookie + '=""; max-age=0; path=/'

        cherrypy.request.login = None
        cherrypy.lib.sessions.expire()

        if redirect_uri:
            redirect_uri = '?redirect_uri=' + redirect_uri

        raise cherrypy.HTTPRedirect(plexpy.HTTP_ROOT + "auth/login" + redirect_uri)

    @cherrypy.expose
    @cherrypy.tools.allow(methods=['POST'])
    @cherrypy.tools.json_out()
    def signin(self, username=None, password=None, token=None, remember_me='0', admin_login='0', *args, **kwargs):
        ip_address = cherrypy.request.remote.ip
        rate_limit = check_rate_limit(ip_address)

        if rate_limit:
            logger.debug("Tautulli WebAuth :: Too many incorrect login attempts from '%s'." % ip_address)
            error_message = {'status': 'error', 'message': 'Too many login attempts.'}
            cherrypy.response.status = 429
            cherrypy.response.headers['Retry-After'] = rate_limit
            return error_message

        error_message = {'status': 'error', 'message': 'Invalid credentials.'}

        valid_login, user_details, user_group = check_credentials(username=username,
                                                                  password=password,
                                                                  token=token,
                                                                  admin_login=admin_login,
                                                                  headers=kwargs)

        if valid_login:
            payload, jwt_token = self.create_session(user_details, user_group,
                                                     remember_me=remember_me == '1',
                                                     oauth=bool(token))
            cherrypy.response.status = 200
            return {'status': 'success', 'token': jwt_token, 'uuid': hash_pms_uuid()}

        elif admin_login == '1' and username:
            self.on_login(username=username)
            logger.debug("Tautulli WebAuth :: Invalid admin login attempt from '%s'." % username)
            cherrypy.response.status = 401
            return error_message

        elif username:
            self.on_login(username=username)
            logger.debug("Tautulli WebAuth :: Invalid user login attempt from '%s'." % username)
            cherrypy.response.status = 401
            return error_message

        elif token:
            self.on_login(username='Plex OAuth', oauth=True)
            logger.debug("Tautulli WebAuth :: Invalid Plex OAuth login attempt.")
            cherrypy.response.status = 401
            return error_message

    def check_oidc_enabled(self):
        """Redirects away from the OIDC pages unless form login and OIDC are both enabled."""
        self.check_auth_enabled()
        if not oidc.enabled():
            raise cherrypy.HTTPRedirect(plexpy.HTTP_ROOT + "auth/login")

    @cherrypy.expose
    def oidc_login(self, redirect_uri='', remember_me='1', *args, **kwargs):
        """Starts an OIDC login by redirecting to the identity provider."""
        self.check_oidc_enabled()

        ip_address = cherrypy.request.remote.ip
        if check_rate_limit(ip_address):
            logger.debug("Tautulli WebAuth :: Too many incorrect login attempts from '%s'." % ip_address)
            cherrypy.response.status = 429
            return self.get_loginform(redirect_uri=redirect_uri, error='Too many login attempts. Try again later.')

        try:
            url, state, login_request = oidc.new_login_request(redirect_uri=self.oidc_callback_url(),
                                                               next_uri=redirect_uri,
                                                               remember_me=remember_me == '1')
        except oidc.OIDCError as e:
            cherrypy.response.status = 503
            return self.get_loginform(redirect_uri=redirect_uri, error=str(e))
        except Exception as e:
            logger.exception("Tautulli WebAuth :: Unexpected error starting OIDC login: %s" % e)
            cherrypy.response.status = 503
            return self.get_loginform(redirect_uri=redirect_uri, error='OpenID Connect login failed.')

        if not cherrypy.session.locked:
            cherrypy.session.acquire_lock()
        cherrypy.session[OIDC_SESSION_KEY] = oidc.store_login_request(cherrypy.session.get(OIDC_SESSION_KEY),
                                                                      state, login_request)

        raise cherrypy.HTTPRedirect(url)

    @cherrypy.expose
    def oidc_callback(self, code=None, state=None, error=None, *args, **kwargs):
        """Completes an OIDC login when the identity provider redirects back to Tautulli."""
        self.check_oidc_enabled()

        if not cherrypy.session.locked:
            cherrypy.session.acquire_lock()
        login_request, pending = oidc.pop_login_request(cherrypy.session.get(OIDC_SESSION_KEY), state)
        cherrypy.session[OIDC_SESSION_KEY] = pending

        if not login_request:
            logger.warn("Tautulli WebAuth :: OIDC callback with an unknown or expired login request.")
            cherrypy.response.status = 400
            return self.get_loginform(error='The login request expired or is invalid. Please try again.')

        redirect_uri = login_request['next']

        if error or not code:
            logger.warn("Tautulli WebAuth :: OIDC provider returned an error: %s" % (error or 'missing code'))
            cherrypy.response.status = 401
            return self.get_loginform(redirect_uri=redirect_uri, error='The identity provider did not complete the login.')

        try:
            tokens = oidc.exchange_code(code, login_request['redirect_uri'], login_request['code_verifier'])
            claims = oidc.validate_id_token(tokens['id_token'], login_request['nonce'])
            claims = oidc.complete_claims(claims, tokens.get('access_token'))
            username = oidc.authorize(claims)
        except oidc.OIDCAccessDenied as e:
            self.on_login(username=e.username or 'OIDC')
            logger.warn("Tautulli WebAuth :: OIDC user '%s' is not allowed to log in." % e.username)
            cherrypy.response.status = 403
            return self.get_loginform(redirect_uri=redirect_uri, error=str(e))
        except oidc.OIDCError as e:
            self.on_login(username='OIDC')
            cherrypy.response.status = 401
            return self.get_loginform(redirect_uri=redirect_uri, error=str(e))
        except Exception as e:
            logger.exception("Tautulli WebAuth :: Unexpected error completing OIDC login: %s" % e)
            self.on_login(username='OIDC')
            cherrypy.response.status = 401
            return self.get_loginform(redirect_uri=redirect_uri, error='OpenID Connect login failed.')

        self.create_session({'user_id': None, 'username': username}, 'admin',
                            remember_me=login_request['remember_me'],
                            method=oidc.provider_name())

        raise cherrypy.HTTPRedirect(plexpy.HTTP_ROOT + "auth/redirect?redirect_uri=" + quote(redirect_uri or ''))

    @cherrypy.expose
    @requireAuth()
    def redirect(self, redirect_uri='', *args, **kwargs):
        root = plexpy.HTTP_ROOT.rstrip('/')
        if redirect_uri.startswith(root):
            redirect_uri = redirect_uri[len(root):]
        redirect_uri = redirect_uri.replace('\\', '/')
        raise cherrypy.HTTPRedirect(plexpy.HTTP_ROOT + redirect_uri.strip('/ \t\r\n'))
