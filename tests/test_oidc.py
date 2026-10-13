"""OpenID Connect login.

OIDC turns on web server authentication by itself, without an HTTP password.
A broken OIDC config, a provider outage, or a bad provider response must
fail the login and leave every protected page locked.

The fake identity provider below answers the discovery, JWKS, and token
requests that plexpy.oidc makes, and signs ID tokens with a real RSA key.
"""

import io
import os
import sys
import time
from http.cookies import SimpleCookie
from urllib.parse import parse_qs, urlencode, urlparse

import cherrypy
import jwt
import pytest
import requests
from cryptography.hazmat.primitives.asymmetric import rsa

import plexpy
from plexpy import oidc, request, webauth, webserve, webstart

ISSUER = "https://idp.example.com/realm"
CLIENT_ID = "tautulli"
CLIENT_SECRET = "s3cret-value-for-the-tautulli-client"


class FakeResponse:
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self.reason = "OK" if status_code == 200 else "Error"
        self._data = data

    def json(self):
        if self._data is None:
            raise ValueError("no json")
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(response=self)


class FakeProvider:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.kid = "key-1"
        self.down = False
        self.claims = {}
        self.calls = []
        self.token_requests = []
        self.discovery = {
            "issuer": ISSUER,
            "authorization_endpoint": ISSUER + "/authorize",
            "token_endpoint": ISSUER + "/token",
            "jwks_uri": ISSUER + "/jwks",
            "userinfo_endpoint": ISSUER + "/userinfo",
            "id_token_signing_alg_values_supported": ["RS256"],
        }
        self.userinfo = None

    def jwks(self):
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key(), as_dict=True)
        jwk.update({"kid": self.kid, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    def id_token(self, nonce, overrides=None):
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "user-123", "iat": now, "exp": now + 300,
                  "nonce": nonce, "preferred_username": "alice",
                  "email": "alice@example.com", "email_verified": True, "groups": ["tautulli-admins"]}
        claims.update(self.claims)
        claims.update(overrides or {})
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": self.kid})

    def get(self, url, **kwargs):
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        return self.request("POST", url, **kwargs)

    def request(self, method, url, **kwargs):
        assert kwargs["verify"] is True
        self.calls.append((method, url))
        if self.down:
            raise requests.ConnectionError("provider is down")
        if url == ISSUER + "/.well-known/openid-configuration":
            return FakeResponse(data=self.discovery)
        if url == ISSUER + "/jwks":
            return FakeResponse(data=self.jwks())
        if url == ISSUER + "/token":
            self.token_requests.append(kwargs)
            return FakeResponse(data={"id_token": self.id_token(self.nonce), "access_token": "at",
                                      "token_type": "Bearer"})
        if url == ISSUER + "/userinfo":
            return FakeResponse(data=self.userinfo)
        return FakeResponse(status_code=404)


@pytest.fixture
def provider(monkeypatch):
    fake = FakeProvider()
    fake.nonce = None
    # plexpy.request sends every request through its shared session
    monkeypatch.setattr(request, "_session", fake)
    oidc.clear_cache()
    yield fake
    oidc.clear_cache()


@pytest.fixture
def oidc_config(app_config):
    app_config.OIDC_ENABLED = 1
    app_config.OIDC_ISSUER = ISSUER
    app_config.OIDC_CLIENT_ID = CLIENT_ID
    app_config.OIDC_CLIENT_SECRET = CLIENT_SECRET
    app_config.OIDC_ALLOWED_GROUPS = "tautulli-admins"
    app_config.JWT_SECRET = "jwt-secret-for-the-tautulli-oidc-tests"
    return app_config


# ---------------------------------------------------------------------------
# Enablement: OIDC enables auth on its own and never disables it.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("password, basic, oidc_on, form, basic_on", [
    ("", 0, 0, False, False),
    ("hash", 0, 0, True, False),
    ("", 0, 1, True, False),
    ("hash", 0, 1, True, False),
    ("", 1, 1, True, False),
    ("hash", 1, 0, False, True),
    ("hash", 1, 1, False, True),
])
def test_auth_mode(password, basic, oidc_on, form, basic_on):
    assert webauth.use_form_auth(password, basic, oidc_on) is form
    assert webauth.use_basic_auth(password, basic) is basic_on


class Mounted(Exception):
    pass


def initialize(monkeypatch, **options):
    captured = {}

    def mount(root, script_name='', config=None):
        captured.update(config)
        raise Mounted

    monkeypatch.setattr(plexpy, "PROG_DIR", os.path.dirname(os.path.dirname(plexpy.__file__)))
    monkeypatch.setattr(plexpy, "HTTP_ROOT", plexpy.HTTP_ROOT)
    monkeypatch.setattr(plexpy, "AUTH_ENABLED", plexpy.AUTH_ENABLED)
    monkeypatch.setattr(cherrypy.tree, "mount", mount)
    monkeypatch.setattr(cherrypy.config, "update", lambda *args, **kwargs: None)

    web_options = {"enable_https": False, "https_cert": "", "https_cert_chain": "", "https_key": "",
                   "http_host": "127.0.0.1", "http_port": 0, "http_environment": "production",
                   "http_proxy": False, "http_root": "/", "http_username": "", "http_password": "",
                   "http_basic_auth": False}
    web_options.update(options)
    with pytest.raises(Mounted):
        webstart.initialize(web_options)
    return captured


@pytest.mark.parametrize("issuer", ["", "http://insecure.example.com", ISSUER])
def test_oidc_without_a_password_turns_auth_on_even_when_misconfigured(app_config, monkeypatch, issuer):
    app_config.OIDC_ENABLED = 1
    app_config.OIDC_ISSUER = issuer

    conf = initialize(monkeypatch, oidc_enabled=1)

    assert plexpy.AUTH_ENABLED is True
    assert conf["/"]["tools.auth.on"] is True
    assert conf["/"]["tools.auth_basic.on"] is False


def test_no_login_method_leaves_auth_off(app_config, monkeypatch):
    conf = initialize(monkeypatch, oidc_enabled=0)

    assert plexpy.AUTH_ENABLED is False
    assert conf["/"]["tools.auth.on"] is False


def test_config_errors(oidc_config, monkeypatch):
    assert oidc.config_errors() == []

    oidc_config.OIDC_ALLOWED_GROUPS = ""
    assert any("nobody can log in" in e for e in oidc.config_errors())

    oidc_config.OIDC_ALLOWED_GROUPS = "admins"
    oidc_config.OIDC_ISSUER = "http://idp.example.com"
    assert any("HTTPS" in e for e in oidc.config_errors())

    oidc_config.OIDC_ISSUER = "http://127.0.0.1:9000/realm"
    assert oidc.config_errors() == []

    monkeypatch.setattr(jwt.algorithms, "has_crypto", False)
    assert any("cryptography" in e for e in oidc.config_errors())


# ---------------------------------------------------------------------------
# ID token validation
# ---------------------------------------------------------------------------

def test_a_valid_id_token_is_accepted(oidc_config, provider):
    claims = oidc.validate_id_token(provider.id_token("n1"), "n1")
    assert claims["sub"] == "user-123"


@pytest.mark.parametrize("overrides", [
    {"iss": "https://evil.example.com"},
    {"aud": "another-client"},
    {"aud": [CLIENT_ID, "another-client"]},
    {"azp": "another-client"},
    {"exp": int(time.time()) - 3600},
    {"iat": int(time.time()) + 3600},
    {"sub": None},
    {"nonce": "wrong-nonce"},
    {"nonce": None},
])
def test_invalid_id_tokens_are_rejected(oidc_config, provider, overrides):
    with pytest.raises(oidc.OIDCError):
        oidc.validate_id_token(provider.id_token("n1", overrides), "n1")


def test_a_token_signed_by_another_key_is_rejected(oidc_config, provider):
    good_key = provider.key
    provider.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    forged = provider.id_token("n1")
    provider.key = good_key

    with pytest.raises(oidc.OIDCError):
        oidc.validate_id_token(forged, "n1")


@pytest.mark.parametrize("alg, key", [("HS256", CLIENT_SECRET), ("none", None)])
def test_symmetric_and_unsigned_tokens_are_rejected(oidc_config, provider, alg, key):
    provider.discovery["id_token_signing_alg_values_supported"] = ["RS256", "HS256", "none"]
    now = int(time.time())
    token = jwt.encode({"iss": ISSUER, "aud": CLIENT_ID, "sub": "x", "iat": now, "exp": now + 60, "nonce": "n1"},
                       key, algorithm=alg)

    with pytest.raises(oidc.OIDCError):
        oidc.validate_id_token(token, "n1")


def test_an_unknown_kid_refreshes_the_keys_once(oidc_config, provider):
    oidc.validate_id_token(provider.id_token("n1"), "n1")
    provider.kid = "rotated"
    oidc._CACHE["entry"]["jwks_time"] -= oidc.JWKS_MIN_REFRESH_INTERVAL

    claims = oidc.validate_id_token(provider.id_token("n2"), "n2")

    assert claims["sub"] == "user-123"
    assert [url for _, url in provider.calls].count(ISSUER + "/jwks") == 2


def test_a_discovery_document_for_another_issuer_is_rejected(oidc_config, provider):
    provider.discovery["issuer"] = "https://evil.example.com"

    with pytest.raises(oidc.OIDCError):
        oidc.get_discovery()


def test_insecure_endpoints_in_discovery_are_rejected(oidc_config, provider):
    provider.discovery["token_endpoint"] = "http://idp.example.com/token"

    with pytest.raises(oidc.OIDCError):
        oidc.get_discovery()


def test_userinfo_with_a_different_subject_is_rejected(oidc_config, provider):
    claims = {"sub": "user-123", "iss": ISSUER}
    provider.userinfo = {"sub": "someone-else", "groups": ["tautulli-admins"]}

    with pytest.raises(oidc.OIDCError):
        oidc.complete_claims(claims, "at")


def test_userinfo_fills_in_missing_groups_without_overriding_the_id_token(oidc_config, provider):
    claims = {"sub": "user-123", "preferred_username": "alice"}
    provider.userinfo = {"sub": "user-123", "groups": ["tautulli-admins"], "preferred_username": "mallory"}

    merged = oidc.complete_claims(claims, "at")

    assert merged["groups"] == ["tautulli-admins"]
    assert merged["preferred_username"] == "alice"


# ---------------------------------------------------------------------------
# Authorization
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("users, groups, claims, allowed", [
    ("", "", {"sub": "a", "groups": ["admins"]}, False),
    ("", "admins", {"sub": "a", "groups": ["admins"]}, True),
    ("", "admins", {"sub": "a", "groups": "admins"}, True),
    ("", "admins", {"sub": "a", "groups": ["users"]}, False),
    ("", "admins", {"sub": "a"}, False),
    ("a", "", {"sub": "a"}, True),
    ("A", "", {"sub": "a"}, False),
    ("Alice@Example.com", "", {"sub": "a", "email": "alice@example.com", "email_verified": True}, True),
    ("alice@example.com", "", {"sub": "a", "email": "alice@example.com", "email_verified": "true"}, True),
    ("alice@example.com", "", {"sub": "a", "email": "alice@example.com", "email_verified": False}, False),
    ("alice@example.com", "", {"sub": "a", "email": "alice@example.com"}, False),
    ("alice", "", {"sub": "a", "preferred_username": "alice"}, False),
])
def test_authorize(app_config, users, groups, claims, allowed):
    app_config.OIDC_ALLOWED_USERS = users
    app_config.OIDC_ALLOWED_GROUPS = groups

    if allowed:
        assert oidc.authorize(claims)
    else:
        with pytest.raises(oidc.OIDCAccessDenied):
            oidc.authorize(claims)


def test_login_requests_are_single_use_and_expire():
    pending = oidc.store_login_request({}, "state-1", {"created": time.time()})
    pending = oidc.store_login_request(pending, "state-2", {"created": time.time() - oidc.LOGIN_REQUEST_TTL})

    login_request, pending = oidc.pop_login_request(pending, "state-1")
    assert login_request is not None
    assert oidc.pop_login_request(pending, "state-1")[0] is None
    assert oidc.pop_login_request(pending, "state-2")[0] is None
    assert oidc.pop_login_request(pending, None)[0] is None


# ---------------------------------------------------------------------------
# End to end through the CherryPy app
# ---------------------------------------------------------------------------

class Client:
    def __init__(self, app):
        self.app = app
        self.cookies = {}

    def get(self, path, query=None, headers=None):
        environ = {"REQUEST_METHOD": "GET", "PATH_INFO": path, "SCRIPT_NAME": "",
                   "QUERY_STRING": urlencode(query or {}),
                   "SERVER_NAME": "localhost", "SERVER_PORT": "8181", "SERVER_PROTOCOL": "HTTP/1.1",
                   "HTTP_HOST": "localhost:8181", "REMOTE_ADDR": "127.0.0.1",
                   "wsgi.url_scheme": "http", "wsgi.input": io.BytesIO(), "wsgi.errors": sys.stderr,
                   "wsgi.version": (1, 0), "wsgi.multithread": False, "wsgi.multiprocess": False,
                   "wsgi.run_once": False}
        if self.cookies:
            environ["HTTP_COOKIE"] = "; ".join("%s=%s" % kv for kv in self.cookies.items())
        for name, value in (headers or {}).items():
            environ["HTTP_" + name.upper().replace("-", "_")] = value

        result = {}

        def start_response(status, response_headers, exc_info=None):
            result["status"] = int(status.split()[0])
            result["headers"] = response_headers

        body = b"".join(self.app(environ, start_response))
        for name, value in result["headers"]:
            if name.lower() == "set-cookie":
                for morsel in SimpleCookie(value).values():
                    if morsel["max-age"] == "0" or not morsel.value or morsel.value == '""':
                        self.cookies.pop(morsel.key, None)
                    else:
                        self.cookies[morsel.key] = morsel.value
        headers = dict(result["headers"])
        return result["status"], headers, body.decode("utf-8", "replace")


@pytest.fixture
def client(app_db, oidc_config, provider, monkeypatch):
    conf = initialize(monkeypatch, oidc_enabled=1)
    app = cherrypy.Application(webserve.WebInterface(), "", config=conf)
    return Client(app)


def start_login(client, provider, **query):
    status, headers, _ = client.get("/auth/oidc_login", query)
    assert status in (302, 303)
    location = urlparse(headers["Location"])
    params = {k: v[0] for k, v in parse_qs(location.query).items()}
    provider.nonce = params["nonce"]
    return params


def jwt_cookie(client):
    return client.cookies.get(webauth.jwt_cookie_name())


def test_protected_pages_redirect_to_login_when_oidc_is_the_only_method(client):
    status, headers, _ = client.get("/home")
    assert status in (302, 303)
    assert "/auth/logout" in headers["Location"]

    status, _, _ = client.get("/home", headers={"X-Requested-With": "XMLHttpRequest"})
    assert status == 401


def test_login_page_shows_oidc_and_hides_the_password_form(client):
    status, _, body = client.get("/auth/login")

    assert status == 200
    assert 'id="sign-in-oidc"' in body
    assert 'id="login-form"' not in body


def test_authorization_request_uses_pkce_state_and_nonce(client, provider):
    params = start_login(client, provider)

    assert params["response_type"] == "code"
    assert params["client_id"] == CLIENT_ID
    assert params["redirect_uri"] == "http://localhost:8181/auth/oidc_callback"
    assert params["code_challenge_method"] == "S256"
    assert params["state"] and params["nonce"] and params["code_challenge"]
    assert "openid" in params["scope"].split()


def test_a_successful_login_issues_a_session_and_opens_protected_pages(client, provider):
    params = start_login(client, provider, redirect_uri="/history")

    status, headers, _ = client.get("/auth/oidc_callback", {"code": "abc", "state": params["state"]})

    assert status in (302, 303)
    assert headers["Location"].endswith("/auth/redirect?redirect_uri=/history")
    token = jwt_cookie(client)
    payload = jwt.decode(token, plexpy.CONFIG.JWT_SECRET, algorithms=["HS256"])
    assert payload["user"] == "alice"
    assert payload["user_group"] == "admin"

    request = provider.token_requests[0]
    assert request["data"]["code"] == "abc"
    assert request["data"]["code_verifier"]
    assert request["headers"]["Authorization"].startswith("Basic ")

    status, headers, _ = client.get("/auth/redirect", {"redirect_uri": "/history"})
    assert status in (302, 303)
    assert headers["Location"].endswith("/history")


def test_a_state_can_only_be_used_once(client, provider):
    params = start_login(client, provider)
    client.get("/auth/oidc_callback", {"code": "abc", "state": params["state"]})
    client.cookies.pop(webauth.jwt_cookie_name())

    status, _, _ = client.get("/auth/oidc_callback", {"code": "abc", "state": params["state"]})

    assert status == 400
    assert jwt_cookie(client) is None


def test_a_forged_state_is_rejected(client, provider):
    start_login(client, provider)

    status, _, _ = client.get("/auth/oidc_callback", {"code": "abc", "state": "forged"})

    assert status == 400
    assert jwt_cookie(client) is None
    assert provider.token_requests == []


def test_a_callback_from_another_browser_session_is_rejected(client, provider):
    params = start_login(client, provider)
    client.cookies.clear()

    status, _, _ = client.get("/auth/oidc_callback", {"code": "abc", "state": params["state"]})

    assert status == 400
    assert jwt_cookie(client) is None


def test_a_user_outside_the_allowed_groups_is_denied(client, provider):
    provider.claims = {"groups": ["users"]}
    params = start_login(client, provider)

    status, _, body = client.get("/auth/oidc_callback", {"code": "abc", "state": params["state"]})

    assert status == 403
    assert "not allowed" in body
    assert jwt_cookie(client) is None
    status, _, _ = client.get("/home")
    assert status in (302, 303)


def test_a_provider_error_is_a_failed_login(client, provider):
    params = start_login(client, provider)

    status, _, _ = client.get("/auth/oidc_callback", {"error": "access_denied", "state": params["state"]})

    assert status == 401
    assert jwt_cookie(client) is None


def test_a_bad_id_token_is_a_failed_login(client, provider):
    provider.claims = {"aud": "another-client"}
    params = start_login(client, provider)

    status, _, _ = client.get("/auth/oidc_callback", {"code": "abc", "state": params["state"]})

    assert status == 401
    assert jwt_cookie(client) is None


def test_a_provider_outage_fails_closed(client, provider):
    provider.down = True

    status, _, body = client.get("/auth/oidc_login")
    assert status == 503
    assert "Unable to reach the identity provider" in body
    assert jwt_cookie(client) is None

    status, headers, _ = client.get("/home")
    assert status in (302, 303)
    assert "/auth/logout" in headers["Location"]


def test_a_provider_outage_during_the_callback_fails_closed(client, provider):
    params = start_login(client, provider)
    oidc.clear_cache()
    provider.down = True

    status, _, _ = client.get("/auth/oidc_callback", {"code": "abc", "state": params["state"]})

    assert status == 401
    assert jwt_cookie(client) is None


def test_a_misconfigured_provider_fails_closed(client, provider):
    plexpy.CONFIG.OIDC_ISSUER = ""

    status, _, _ = client.get("/auth/oidc_login")
    assert status == 503
    assert provider.calls == []

    status, _, _ = client.get("/home")
    assert status in (302, 303)


def test_disabling_oidc_after_startup_keeps_pages_locked(client, provider):
    plexpy.CONFIG.OIDC_ENABLED = 0

    status, headers, _ = client.get("/auth/oidc_login")
    assert status in (302, 303)
    assert headers["Location"].endswith("/auth/login")

    status, _, _ = client.get("/home")
    assert status in (302, 303)
    status, _, _ = client.get("/auth/login")
    assert status == 200


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@pytest.fixture
def web(app_config, monkeypatch):
    from plexpy import libraries, logger, plextv, users

    monkeypatch.setattr(logger, "initLogger", lambda **kwargs: None)
    # configUpdate also reschedules tasks and refreshes the server data.
    monkeypatch.setattr(plexpy, "initialize_scheduler", lambda: None)
    monkeypatch.setattr(plextv, "get_server_resources", lambda: None)
    monkeypatch.setattr(libraries, "refresh_libraries", lambda: None)
    monkeypatch.setattr(users, "refresh_users", lambda: None)
    # Keep the startup options unchanged so the save leaves the OS alone.
    plexpy.CONFIG.LAUNCH_STARTUP = 0
    plexpy.CONFIG.LAUNCH_BROWSER = 0
    return webserve.WebInterface()


def save(web, app_config, **form):
    form.setdefault("http_password", "    " if app_config.HTTP_PASSWORD else "")
    form.setdefault("oidc_client_secret", "    " if app_config.OIDC_CLIENT_SECRET else "")
    for key in ("oidc_issuer", "oidc_client_id", "oidc_allowed_users", "oidc_allowed_groups",
                "oidc_username_claim", "oidc_groups_claim"):
        form.setdefault(key, getattr(app_config, key.upper()))
    # An unchecked checkbox is not posted
    form.setdefault("oidc_enabled", "1" if app_config.OIDC_ENABLED else None)
    if form["oidc_enabled"] is None:
        del form["oidc_enabled"]
    web.configUpdate(**form)


def test_the_masked_client_secret_is_kept(web, oidc_config):
    save(web, oidc_config)
    assert oidc_config.OIDC_CLIENT_SECRET == CLIENT_SECRET

    save(web, oidc_config, oidc_client_secret="new-secret")
    assert oidc_config.OIDC_CLIENT_SECRET == "new-secret"


def test_an_unchanged_save_keeps_existing_sessions(web, oidc_config):
    save(web, oidc_config)
    assert not oidc_config.JWT_UPDATE_SECRET


@pytest.mark.parametrize("form", [
    {"oidc_allowed_groups": "other-group"},
    {"oidc_issuer": "https://other.example.com"},
    {"oidc_enabled": None},
])
def test_changing_who_can_log_in_logs_out_existing_sessions(web, oidc_config, form):
    save(web, oidc_config, **form)

    assert oidc_config.JWT_UPDATE_SECRET


def test_settings_page_renders_oidc_options_without_the_secret(client, provider):
    params = start_login(client, provider)
    client.get("/auth/oidc_callback", {"code": "abc", "state": params["state"]})

    status, _, body = client.get("/settings")

    assert status == 200
    assert 'id="oidc_issuer"' in body
    assert ISSUER in body
    assert "http://localhost:8181/auth/oidc_callback" in body
    assert CLIENT_SECRET not in body


def test_the_client_secret_is_redacted_from_the_logs_but_the_client_id_is_not(tmp_path, monkeypatch):
    # Client IDs are often just "tautulli", which would redact every log line that names it.
    from plexpy import logger

    monkeypatch.setattr(logger, "_BLACKLIST_WORDS", set())
    ini_path = tmp_path / "config.ini"
    ini_path.write_text("[OIDC]\noidc_client_id = tautulli\noidc_client_secret = %s\n" % CLIENT_SECRET)

    plexpy.config.Config(str(ini_path))

    assert CLIENT_SECRET in logger._BLACKLIST_WORDS
    assert "tautulli" not in logger._BLACKLIST_WORDS


def test_oidc_settings_are_not_imported_or_downloaded():
    from plexpy import config

    for key in config._CONFIG_DEFINITIONS:
        if key.startswith("OIDC_"):
            assert key in config._DO_NOT_IMPORT_KEYS
    assert "OIDC_CLIENT_SECRET" in config._DO_NOT_DOWNLOAD_KEYS
