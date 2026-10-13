
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

# OpenID Connect authorization code flow with PKCE.
# Every failure raises OIDCError. Callers must treat any exception as a failed login.

import base64
import hashlib
import ipaddress
import secrets
import threading
import time
from hmac import compare_digest
from urllib.parse import quote, urlencode, urlparse

import jwt

import plexpy
from plexpy import logger
from plexpy import request

# Symmetric (HS*) and 'none' algorithms are never accepted for ID tokens.
ALLOWED_ALGORITHMS = ('RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512',
                      'ES256', 'ES384', 'ES512', 'EdDSA')
_ALGORITHM_KEY_TYPES = {'RS': 'RSA', 'PS': 'RSA', 'ES': 'EC', 'Ed': 'OKP'}

DISCOVERY_TTL = 3600
JWKS_TTL = 3600
JWKS_MIN_REFRESH_INTERVAL = 60
HTTP_TIMEOUT = 10
CLOCK_LEEWAY = 60
LOGIN_REQUEST_TTL = 600
MAX_PENDING_LOGIN_REQUESTS = 5

_CACHE_LOCK = threading.Lock()
_CACHE = {}


class OIDCError(Exception):
    """A login failure. The message is safe to show to the user."""


class OIDCAccessDenied(OIDCError):
    """The identity provider authenticated the user, but Tautulli does not allow them."""

    def __init__(self, message, username=None):
        super().__init__(message)
        self.username = username


def enabled():
    """Returns True if OIDC login is turned on. This does not mean the config is valid."""
    return bool(plexpy.CONFIG.OIDC_ENABLED)


def provider_name():
    """Returns the provider name shown on the login page."""
    return plexpy.CONFIG.OIDC_PROVIDER_NAME.strip() or 'OpenID Connect'


def split_list(value):
    """Splits a comma separated setting into a list of values."""
    return [v.strip() for v in (value or '').split(',') if v.strip()]


def _is_secure_url(url):
    """Returns True for HTTPS URLs, and HTTP URLs on the local machine."""
    parsed = urlparse(url)
    if not parsed.hostname:
        return False
    if parsed.scheme == 'https':
        return True
    if parsed.scheme == 'http':
        if parsed.hostname == 'localhost':
            return True
        try:
            return ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:
            return False
    return False


def config_errors():
    """Returns a list of problems that prevent OIDC login. An empty list means the config is usable."""
    errors = []
    issuer = plexpy.CONFIG.OIDC_ISSUER.strip()

    if not issuer:
        errors.append("The OIDC issuer URL is not set.")
    elif not _is_secure_url(issuer):
        errors.append("The OIDC issuer URL must use HTTPS.")
    if not plexpy.CONFIG.OIDC_CLIENT_ID.strip():
        errors.append("The OIDC client ID is not set.")
    if not split_list(plexpy.CONFIG.OIDC_ALLOWED_USERS) and not split_list(plexpy.CONFIG.OIDC_ALLOWED_GROUPS):
        errors.append("No OIDC allowed users or allowed groups are set, so nobody can log in.")
    if not jwt.algorithms.has_crypto:
        errors.append("The Python cryptography library is required to verify OIDC tokens.")

    return errors


def _get_json(method, url, **kwargs):
    """Requests a JSON object from the identity provider. Raises OIDCError on any failure."""
    # Always verify the provider certificate, even when VERIFY_SSL_CERT is off for Plex.
    response, err_msg, req_msg = request.request_response2(url, method=method, verify=True,
                                                           timeout=HTTP_TIMEOUT, allow_redirects=False,
                                                           **kwargs)

    if response is None or response.status_code != 200:
        logger.error("Tautulli OIDC :: Request to %s failed: %s", url,
                     err_msg or "HTTP status %s" % response.status_code)
        if req_msg:
            logger.debug("Tautulli OIDC :: Response: %s", req_msg)
        if response is None:
            raise OIDCError("Unable to reach the identity provider.")
        raise OIDCError("The identity provider returned an error.")

    try:
        data = response.json()
    except ValueError:
        logger.error("Tautulli OIDC :: Request to %s did not return JSON.", url)
        raise OIDCError("The identity provider returned an invalid response.")

    if not isinstance(data, dict):
        logger.error("Tautulli OIDC :: Request to %s did not return a JSON object.", url)
        raise OIDCError("The identity provider returned an invalid response.")

    return data


def _cache_entry():
    """Returns the cached provider metadata for the configured issuer. Call with _CACHE_LOCK held."""
    # Settings can change without a restart. Never use metadata from a different issuer.
    issuer = plexpy.CONFIG.OIDC_ISSUER.strip()
    entry = _CACHE.get('entry')
    if not entry or entry['issuer'] != issuer:
        entry = {'issuer': issuer, 'discovery': None, 'discovery_time': 0, 'jwks': None, 'jwks_time': 0}
        _CACHE['entry'] = entry
    return entry


def clear_cache():
    """Forgets the cached discovery document and signing keys."""
    with _CACHE_LOCK:
        _CACHE.clear()


def get_discovery():
    """Returns the provider discovery document. Raises OIDCError if the config or document is not valid."""
    errors = config_errors()
    if errors:
        for error in errors:
            logger.error("Tautulli OIDC :: %s", error)
        raise OIDCError("OpenID Connect login is not configured correctly.")

    with _CACHE_LOCK:
        entry = _cache_entry()
        if entry['discovery'] and time.time() - entry['discovery_time'] < DISCOVERY_TTL:
            return entry['discovery']

        issuer = entry['issuer']
        discovery = _get_json('GET', issuer.rstrip('/') + '/.well-known/openid-configuration')

        if discovery.get('issuer', '').rstrip('/') != issuer.rstrip('/'):
            logger.error("Tautulli OIDC :: The discovery document issuer '%s' does not match the configured issuer '%s'.",
                         discovery.get('issuer'), issuer)
            raise OIDCError("OpenID Connect login is not configured correctly.")

        for endpoint in ('authorization_endpoint', 'token_endpoint', 'jwks_uri'):
            url = discovery.get(endpoint)
            if not isinstance(url, str) or not _is_secure_url(url):
                logger.error("Tautulli OIDC :: The discovery document '%s' is missing or does not use HTTPS.", endpoint)
                raise OIDCError("OpenID Connect login is not configured correctly.")

        userinfo = discovery.get('userinfo_endpoint')
        if userinfo and (not isinstance(userinfo, str) or not _is_secure_url(userinfo)):
            discovery.pop('userinfo_endpoint')

        entry['discovery'] = discovery
        entry['discovery_time'] = time.time()
        return discovery


def _get_jwks(force=False):
    """Returns the provider signing keys as JWK dicts. A forced refresh is rate limited."""
    discovery = get_discovery()

    with _CACHE_LOCK:
        entry = _cache_entry()
        age = time.time() - entry['jwks_time']
        if entry['jwks'] and (age < JWKS_TTL and not force or age < JWKS_MIN_REFRESH_INTERVAL):
            return entry['jwks']

        data = _get_json('GET', discovery['jwks_uri'])
        jwks = data.get('keys')
        if not isinstance(jwks, list):
            logger.error("Tautulli OIDC :: The identity provider signing keys are missing.")
            raise OIDCError("The identity provider returned invalid signing keys.")

        entry['jwks'] = [jwk for jwk in jwks if isinstance(jwk, dict)]
        entry['jwks_time'] = time.time()
        return entry['jwks']


def _find_signing_key(jwks, kid, alg):
    """Returns the one JWK that can verify a token with the kid and alg, or None."""
    key_type = _ALGORITHM_KEY_TYPES.get(alg[:2])
    candidates = [jwk for jwk in jwks
                  if jwk.get('use', 'sig') == 'sig'
                  and jwk.get('kty') == key_type
                  and jwk.get('alg', alg) == alg
                  and (kid is None or jwk.get('kid') == kid)]

    # Without a kid, the key is only unambiguous if there is exactly one.
    if len(candidates) == 1:
        return candidates[0]


def _signing_key(kid, alg):
    """Returns the public key that signed the ID token. Raises OIDCError if there is none."""
    jwk = _find_signing_key(_get_jwks(), kid, alg)
    if jwk is None:
        # The provider may have rotated its keys.
        jwk = _find_signing_key(_get_jwks(force=True), kid, alg)
    if jwk is None:
        logger.error("Tautulli OIDC :: No identity provider signing key matches the ID token (kid '%s', alg '%s').",
                     kid, alg)
        raise OIDCError("Unable to verify the identity provider response.")

    try:
        return jwt.PyJWK.from_dict(jwk, algorithm=alg).key
    except (jwt.PyJWTError, KeyError, TypeError, ValueError) as e:
        logger.error("Tautulli OIDC :: Unable to load the identity provider signing key: %s", e)
        raise OIDCError("Unable to verify the identity provider response.")


def new_login_request(redirect_uri, next_uri='', remember_me=False):
    """Returns the authorization URL and the request state to keep in the session."""
    discovery = get_discovery()

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    code_verifier = secrets.token_urlsafe(64)
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode('ascii')).digest()).rstrip(b'=')

    scopes = plexpy.CONFIG.OIDC_SCOPES.split()
    if 'openid' not in scopes:
        scopes.insert(0, 'openid')

    params = {
        'response_type': 'code',
        'client_id': plexpy.CONFIG.OIDC_CLIENT_ID.strip(),
        'redirect_uri': redirect_uri,
        'scope': ' '.join(scopes),
        'state': state,
        'nonce': nonce,
        'code_challenge': code_challenge.decode('ascii'),
        'code_challenge_method': 'S256',
    }

    endpoint = discovery['authorization_endpoint']
    url = endpoint + ('&' if '?' in endpoint else '?') + urlencode(params)

    login_request = {
        'nonce': nonce,
        'code_verifier': code_verifier,
        'redirect_uri': redirect_uri,
        'next': next_uri,
        'remember_me': remember_me,
        'created': time.time(),
    }
    return url, state, login_request


def store_login_request(session_requests, state, login_request):
    """Adds a login request to the pending requests in the session and drops expired or excess ones."""
    now = time.time()
    pending = {k: v for k, v in (session_requests or {}).items()
               if now - v.get('created', 0) < LOGIN_REQUEST_TTL}
    while len(pending) >= MAX_PENDING_LOGIN_REQUESTS:
        pending.pop(min(pending, key=lambda k: pending[k]['created']))
    pending[state] = login_request
    return pending


def pop_login_request(session_requests, state):
    """Removes and returns the login request for the state. Each state is only usable once."""
    pending = dict(session_requests or {})
    login_request = None
    if state:
        for key in list(pending):
            if compare_digest(key, state):
                login_request = pending.pop(key)
                break

    if login_request and time.time() - login_request.get('created', 0) >= LOGIN_REQUEST_TTL:
        login_request = None

    return login_request, pending


def exchange_code(code, redirect_uri, code_verifier):
    """Exchanges the authorization code at the token endpoint. Returns the token response."""
    discovery = get_discovery()
    client_id = plexpy.CONFIG.OIDC_CLIENT_ID.strip()
    client_secret = plexpy.CONFIG.OIDC_CLIENT_SECRET

    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirect_uri,
        'code_verifier': code_verifier,
    }
    headers = {'Accept': 'application/json'}

    auth_methods = discovery.get('token_endpoint_auth_methods_supported') or ['client_secret_basic']
    if not client_secret:
        data['client_id'] = client_id
    elif 'client_secret_basic' not in auth_methods and 'client_secret_post' in auth_methods:
        data['client_id'] = client_id
        data['client_secret'] = client_secret
    else:
        # RFC 6749 section 2.3.1: form-encode the credentials before Basic encoding.
        credentials = '%s:%s' % (quote(client_id, safe=''), quote(client_secret, safe=''))
        headers['Authorization'] = 'Basic ' + base64.b64encode(credentials.encode('utf-8')).decode('ascii')

    tokens = _get_json('POST', discovery['token_endpoint'], data=data, headers=headers)

    if not isinstance(tokens.get('id_token'), str):
        logger.error("Tautulli OIDC :: The token response did not include an ID token.")
        raise OIDCError("The identity provider returned an invalid response.")

    return tokens


def validate_id_token(id_token, nonce):
    """Verifies the ID token signature and claims. Returns the claims or raises OIDCError."""
    discovery = get_discovery()
    client_id = plexpy.CONFIG.OIDC_CLIENT_ID.strip()

    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as e:
        logger.error("Tautulli OIDC :: Unable to read the ID token: %s", e)
        raise OIDCError("Unable to verify the identity provider response.")

    alg = header.get('alg')
    supported = discovery.get('id_token_signing_alg_values_supported') or ['RS256']
    if alg not in ALLOWED_ALGORITHMS or alg not in supported:
        logger.error("Tautulli OIDC :: The ID token uses the unsupported signing algorithm '%s'.", alg)
        raise OIDCError("Unable to verify the identity provider response.")

    signing_key = _signing_key(header.get('kid'), alg)

    try:
        claims = jwt.decode(
            id_token,
            key=signing_key,
            algorithms=[alg],
            audience=client_id,
            issuer=discovery['issuer'],
            leeway=CLOCK_LEEWAY,
            options={'require': ['iss', 'sub', 'aud', 'exp', 'iat']}
        )
    except jwt.PyJWTError as e:
        logger.error("Tautulli OIDC :: The ID token is not valid: %s", e)
        raise OIDCError("Unable to verify the identity provider response.")

    if not isinstance(claims.get('nonce'), str) or not compare_digest(claims['nonce'], nonce):
        logger.error("Tautulli OIDC :: The ID token nonce does not match the login request.")
        raise OIDCError("Unable to verify the identity provider response.")

    audience = claims['aud']
    if isinstance(audience, list) and len(audience) > 1 and 'azp' not in claims:
        logger.error("Tautulli OIDC :: The ID token has multiple audiences and no authorized party.")
        raise OIDCError("Unable to verify the identity provider response.")
    if 'azp' in claims and claims['azp'] != client_id:
        logger.error("Tautulli OIDC :: The ID token authorized party '%s' is not this client.", claims['azp'])
        raise OIDCError("Unable to verify the identity provider response.")

    if not isinstance(claims['sub'], str) or not claims['sub']:
        logger.error("Tautulli OIDC :: The ID token subject is not valid.")
        raise OIDCError("Unable to verify the identity provider response.")

    return claims


def _needs_userinfo(claims):
    """Returns True if the ID token is missing a claim used to allow access or name the user."""
    if split_list(plexpy.CONFIG.OIDC_ALLOWED_GROUPS) and plexpy.CONFIG.OIDC_GROUPS_CLAIM not in claims:
        return True
    if split_list(plexpy.CONFIG.OIDC_ALLOWED_USERS) and ('email' not in claims or 'email_verified' not in claims):
        return True
    return plexpy.CONFIG.OIDC_USERNAME_CLAIM not in claims


def complete_claims(claims, access_token=None):
    """Adds UserInfo claims missing from the ID token. ID token claims always take precedence."""
    discovery = get_discovery()
    userinfo_endpoint = discovery.get('userinfo_endpoint')

    if not _needs_userinfo(claims) or not userinfo_endpoint or not access_token:
        return claims

    userinfo = _get_json('GET', userinfo_endpoint,
                         headers={'Authorization': 'Bearer ' + access_token, 'Accept': 'application/json'})

    # OIDC Core section 5.3.2: the UserInfo sub must match the ID token sub.
    if not isinstance(userinfo.get('sub'), str) or not compare_digest(userinfo['sub'], claims['sub']):
        logger.error("Tautulli OIDC :: The UserInfo subject does not match the ID token subject.")
        raise OIDCError("Unable to verify the identity provider response.")

    merged = dict(userinfo)
    merged.update(claims)
    return merged


def _claim_list(value):
    """Returns a claim that may be a string or a list as a list of strings."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple)):
        return [v for v in value if isinstance(v, str)]
    return []


def get_username(claims):
    """Returns the username shown in Tautulli. It is never used to allow access."""
    for claim in (plexpy.CONFIG.OIDC_USERNAME_CLAIM, 'preferred_username', 'email', 'sub'):
        value = claims.get(claim)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return claims['sub']


def authorize(claims):
    """Returns the username if the user is allowed to log in, otherwise raises OIDCAccessDenied."""
    username = get_username(claims)
    allowed_users = split_list(plexpy.CONFIG.OIDC_ALLOWED_USERS)
    allowed_groups = split_list(plexpy.CONFIG.OIDC_ALLOWED_GROUPS)

    if not allowed_users and not allowed_groups:
        raise OIDCAccessDenied("You are not allowed to log in to Tautulli.", username=username)

    if claims['sub'] in allowed_users:
        return username

    # Only trust an email address the provider has verified.
    email = claims.get('email')
    email_verified = claims.get('email_verified')
    if isinstance(email, str) and email and (email_verified is True or email_verified == 'true'):
        if email.lower() in (u.lower() for u in allowed_users):
            return username

    if allowed_groups:
        groups = _claim_list(claims.get(plexpy.CONFIG.OIDC_GROUPS_CLAIM))
        if set(groups).intersection(allowed_groups):
            return username

    raise OIDCAccessDenied("You are not allowed to log in to Tautulli.", username=username)
