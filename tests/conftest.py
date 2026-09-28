"""Test fixtures."""

import pytest
import requests

from radicale import config
from radicale.auth import dovecot

import radicale_modoboa_auth_oauth2

INTROSPECTION_ENDPOINT = "https://modoboa.test/api/o/introspect/"
# Former configuration style, with the client credentials in the URL
INTROSPECTION_ENDPOINT_WITH_CREDENTIALS = (
    "https://radicale:secret@modoboa.test/api/o/introspect/"
)
RIGHTS_ENDPOINT = "https://modoboa.test/api/v2/calendar-rights/"
TOKEN_ENDPOINT = "https://modoboa.test/api/o/token/"

CLIENT_CREDENTIALS = {
    "modoboa_client_id": "radicale",
    "modoboa_client_secret": "secret",
}

SHARE_LINK_OPTIONS = {"modoboa_rights_endpoint": RIGHTS_ENDPOINT, **CLIENT_CREDENTIALS}


class FakeResponse:
    def __init__(self, status_code=200, data=None):
        self.status_code = status_code
        self._data = data

    def json(self):
        if isinstance(self._data, Exception):
            raise self._data
        return self._data


class FakeApi:
    """Stand-in for the Modoboa introspection, token and rights endpoints."""

    def __init__(self):
        # OAuth2 access tokens of users: token -> username
        self.user_tokens = {}
        # Rights endpoint answers: user -> data
        self.rights = {}
        self.rights_calls = []
        self.rights_error = None
        self.token_calls = []
        self.introspection_calls = []
        self.valid_tokens = set()

    def post(self, url, json=None, data=None, headers=None, auth=None, **kwargs):
        if url in (INTROSPECTION_ENDPOINT, INTROSPECTION_ENDPOINT_WITH_CREDENTIALS):
            self.introspection_calls.append({"url": url, "auth": auth})
            username = self.user_tokens.get(data["token"])
            return FakeResponse(data={"active": bool(username), "username": username})
        if url == TOKEN_ENDPOINT:
            self.token_calls.append({"data": data, "auth": auth})
            token = f"token-{len(self.token_calls)}"
            self.valid_tokens.add(token)
            return FakeResponse(
                data={"access_token": token, "token_type": "Bearer", "expires_in": 3600}
            )
        assert url == RIGHTS_ENDPOINT
        authorization = (headers or {}).get("Authorization")
        self.rights_calls.append({"json": json, "authorization": authorization})
        if self.rights_error is not None:
            if isinstance(self.rights_error, Exception):
                raise self.rights_error
            return self.rights_error
        if authorization not in {f"Bearer {token}" for token in self.valid_tokens}:
            return FakeResponse(status_code=401)
        return FakeResponse(data=self.rights.get(json["user"], {}))

    def revoke_tokens(self):
        self.valid_tokens.clear()


@pytest.fixture
def api(monkeypatch):
    fake = FakeApi()
    monkeypatch.setattr(
        requests.Session,
        "post",
        lambda session, url, **kwargs: fake.post(url, **kwargs),
    )
    return fake


class FakeDovecot:
    """Stand-in for Dovecot authentication."""

    def __init__(self):
        # login -> password
        self.passwords = {}
        self.calls = []

    def login(self, login, password):
        self.calls.append(login)
        return login if self.passwords.get(login) == password else ""


@pytest.fixture
def dovecot_server(monkeypatch):
    fake = FakeDovecot()
    monkeypatch.setattr(
        dovecot.Auth,
        "_login_ext",
        lambda auth, login, password, context: fake.login(login, password),
    )
    return fake


def load_configuration(auth_options=None, extra=None):
    configuration = config.load()
    values = {
        "auth": {
            "type": "radicale_modoboa_auth_oauth2",
            "oauth2_introspection_endpoint": INTROSPECTION_ENDPOINT_WITH_CREDENTIALS,
            **(auth_options or {}),
        }
    }
    for section, options in (extra or {}).items():
        values.setdefault(section, {}).update(options)
    configuration.update(values, "test", privileged=True)
    return configuration


@pytest.fixture
def make_auth():
    def _make_auth(**options):
        return radicale_modoboa_auth_oauth2.Auth(load_configuration(options))

    return _make_auth
