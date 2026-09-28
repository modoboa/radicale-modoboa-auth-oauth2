"""Unit tests of the authentication plugin."""

import pytest
import requests

from conftest import SHARE_LINK_OPTIONS, TOKEN_ENDPOINT, FakeResponse

from radicale_modoboa_auth_oauth2 import TOKEN_IDENTITY_PREFIX, get_token_identity

ALICE = "alice@example.com"
SHARE_TOKEN = "0123456789abcdef0123456789abcdef"
IDENTITY = get_token_identity(SHARE_TOKEN)


def share_link_environ(query):
    return {"QUERY_STRING": query, "PATH_INFO": "/alice@example.com/Work/"}


def test_introspection_login(make_auth, api, dovecot_server):
    api.user_tokens["oauth-token"] = ALICE
    auth = make_auth()
    assert auth._login_ext(ALICE, "oauth-token", None) == ALICE
    assert not dovecot_server.calls


def test_introspection_checks_username(make_auth, api, dovecot_server):
    api.user_tokens["oauth-token"] = "bob@example.com"
    auth = make_auth()
    assert auth._login_ext(ALICE, "oauth-token", None) == ""


def test_dovecot_fallback(make_auth, api, dovecot_server):
    dovecot_server.passwords[ALICE] = "password"
    auth = make_auth()
    assert auth._login_ext(ALICE, "password", None) == ALICE
    assert api.introspection_calls
    assert dovecot_server.calls == [ALICE]


def test_share_links_disabled_by_default(make_auth, api):
    auth = make_auth()
    assert auth.get_external_login(share_link_environ(f"token={SHARE_TOKEN}")) == ()


def test_share_link_login(make_auth, api):
    auth = make_auth(**SHARE_LINK_OPTIONS)
    login, password = auth.get_external_login(
        share_link_environ(f"token={SHARE_TOKEN}")
    )
    assert login == IDENTITY
    assert password == SHARE_TOKEN


def test_token_identity_hides_token():
    assert IDENTITY.startswith(TOKEN_IDENTITY_PREFIX)
    assert SHARE_TOKEN not in IDENTITY


@pytest.mark.parametrize(
    "query",
    ["", "token=", "other=1", "token=abc", f"token={SHARE_TOKEN.upper()}"],
)
def test_requests_without_valid_token_use_http_auth(make_auth, api, query):
    auth = make_auth(**SHARE_LINK_OPTIONS)
    assert auth.get_external_login(share_link_environ(query)) == ()


def test_valid_share_token(make_auth, api, dovecot_server):
    api.rights[IDENTITY] = {"shares": {"alice@example.com/Work": "r"}}
    auth = make_auth(**SHARE_LINK_OPTIONS)
    assert auth._login_ext(IDENTITY, SHARE_TOKEN, None) == IDENTITY
    # Only the identity is sent to Modoboa, never the token
    assert [call["json"] for call in api.rights_calls] == [{"user": IDENTITY}]
    assert not api.introspection_calls
    assert not dovecot_server.calls


def test_unknown_share_token(make_auth, api, dovecot_server):
    auth = make_auth(**SHARE_LINK_OPTIONS)
    assert auth._login_ext(IDENTITY, SHARE_TOKEN, None) == ""
    assert not api.introspection_calls
    assert not dovecot_server.calls


@pytest.mark.parametrize("password", ["", "wrong", SHARE_TOKEN[:-1] + "0"])
def test_token_identity_requires_the_token(make_auth, api, dovecot_server, password):
    """The identity appears in logs: it must not be enough to log in."""
    api.rights[IDENTITY] = {"shares": {"alice@example.com/Work": "r"}}
    auth = make_auth(**SHARE_LINK_OPTIONS)
    assert auth._login_ext(IDENTITY, password, None) == ""
    assert not api.rights_calls
    assert not dovecot_server.calls


def test_token_identity_refused_when_share_links_disabled(
    make_auth, api, dovecot_server
):
    auth = make_auth()
    assert auth._login_ext(IDENTITY, SHARE_TOKEN, None) == ""
    assert not api.introspection_calls
    assert not dovecot_server.calls


@pytest.mark.parametrize(
    "error",
    [
        requests.ConnectionError("down"),
        FakeResponse(status_code=500),
        FakeResponse(status_code=404),
        FakeResponse(status_code=403),
        FakeResponse(data=ValueError("not JSON")),
        FakeResponse(data=["not", "an", "object"]),
        FakeResponse(data={"shares": ["alice@example.com/Work"]}),
    ],
)
def test_api_failure_refuses_share_token(make_auth, api, error):
    api.rights_error = error
    auth = make_auth(**SHARE_LINK_OPTIONS)
    assert auth._login_ext(IDENTITY, SHARE_TOKEN, None) == ""


@pytest.mark.parametrize("option", ["modoboa_client_id", "modoboa_client_secret"])
def test_credentials_required_with_share_links(make_auth, option):
    options = {**SHARE_LINK_OPTIONS, option: ""}
    with pytest.raises(RuntimeError, match=option):
        make_auth(**options)


def test_client_credentials_are_form_encoded(make_auth, api):
    api.rights[IDENTITY] = {"shares": {"alice@example.com/Work": "r"}}
    auth = make_auth(**{**SHARE_LINK_OPTIONS, "modoboa_client_secret": "a b+c"})
    auth._login_ext(IDENTITY, SHARE_TOKEN, None)
    assert api.token_calls == [
        {"data": {"grant_type": "client_credentials"}, "auth": ("radicale", "a+b%2Bc")}
    ]
    assert api.rights_calls[0]["authorization"] == "Bearer token-1"


def test_access_token_is_reused(make_auth, api):
    api.rights[IDENTITY] = {"shares": {"alice@example.com/Work": "r"}}
    auth = make_auth(**SHARE_LINK_OPTIONS)
    auth._login_ext(IDENTITY, SHARE_TOKEN, None)
    auth._login_ext(IDENTITY, SHARE_TOKEN, None)
    assert len(api.token_calls) == 1
    assert len(api.rights_calls) == 2


def test_refused_access_token_is_renewed(make_auth, api):
    api.rights[IDENTITY] = {"shares": {"alice@example.com/Work": "r"}}
    auth = make_auth(**SHARE_LINK_OPTIONS)
    auth._login_ext(IDENTITY, SHARE_TOKEN, None)
    api.revoke_tokens()
    assert auth._login_ext(IDENTITY, SHARE_TOKEN, None) == IDENTITY
    assert len(api.token_calls) == 2


def test_token_endpoint_defaults_to_rights_endpoint_host(make_auth, api):
    auth = make_auth(**SHARE_LINK_OPTIONS)
    assert auth._rights_client.token_endpoint == TOKEN_ENDPOINT


def test_token_endpoint_option(make_auth, api):
    other = "https://other.test/api/o/token/"
    auth = make_auth(**SHARE_LINK_OPTIONS, modoboa_token_endpoint=other)
    assert auth._rights_client.token_endpoint == other
