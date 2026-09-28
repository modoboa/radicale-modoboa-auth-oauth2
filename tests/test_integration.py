"""Integration tests: the plugin loaded by a real Radicale application."""

import base64
import logging
import sys
import wsgiref.util

import pytest

from radicale import app, config

from conftest import SHARE_LINK_OPTIONS, load_configuration

from radicale_modoboa_auth_oauth2 import get_token_identity

ALICE = "alice@example.com"
CALENDAR = "/alice@example.com/Work/"
SHARE_TOKEN = "0123456789abcdef0123456789abcdef"

# Same rights as radicale-modoboa-rights, which is tested in its own
# package: token identities only get the calendars shared with them, and
# no principal (Radicale can't store a collection named after them).
RIGHTS = r"""
[root]
user: .+
collection:
permissions: R

[owner]
user: [^.].*
collection: {user}
permissions: RW

[owner-calendars]
user: [^.].*
collection: {user}/[^/]+
permissions: rw

[share-link]
user: \.modoboa-token-.+
collection: alice@example\.com/Work
permissions: r
"""


@pytest.fixture
def application(api, tmp_path):
    api.user_tokens["oauth-token"] = ALICE
    rights_file = tmp_path / "rights"
    rights_file.write_text(RIGHTS)
    server_options = {}
    if "validate_user_value" in config.DEFAULT_CONFIG_SCHEMA["server"]:
        # Token identities must pass the strictest user name validation
        # (Radicale 3.8 or later)
        server_options["validate_user_value"] = "strict"
    configuration = load_configuration(
        SHARE_LINK_OPTIONS,
        extra={
            # Short delay on failed logins to keep tests fast
            "auth": {"delay": "0.001"},
            "server": server_options,
            "rights": {"type": "from_file", "file": str(rights_file)},
            "storage": {
                "filesystem_folder": str(tmp_path),
                "_filesystem_fsync": "False",
            },
        },
    )
    application = app.Application(configuration)
    assert request(application, "MKCALENDAR", CALENDAR, ALICE, "oauth-token") == 201
    return application


def request(application, method, path, login=None, password=None, query=""):
    """Send a request and return the status code."""
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query,
        "wsgi.errors": sys.stderr,
    }
    if login is not None:
        credentials = base64.b64encode(f"{login}:{password}".encode()).decode()
        environ["HTTP_AUTHORIZATION"] = f"Basic {credentials}"
    wsgiref.util.setup_testing_defaults(environ)
    status = None

    def start_response(status_, headers):
        nonlocal status
        status = int(status_.split()[0])

    list(application(environ, start_response))
    return status


def test_share_link(application, api, caplog):
    api.rights[get_token_identity(SHARE_TOKEN)] = {
        "shares": {"alice@example.com/Work": "r"}
    }
    with caplog.at_level(logging.DEBUG):
        status = request(application, "GET", CALENDAR, query=f"token={SHARE_TOKEN}")
    assert status == 200
    assert SHARE_TOKEN not in caplog.text


def test_unknown_share_link(application, api):
    status = request(application, "GET", CALENDAR, query=f"token={SHARE_TOKEN}")
    assert status in (401, 403)


def test_token_identity_without_token(application, api):
    identity = get_token_identity(SHARE_TOKEN)
    api.rights[identity] = {"shares": {"alice@example.com/Work": "r"}}
    assert request(application, "GET", CALENDAR, identity, "") in (401, 403)


def test_user_login_still_works(application, api):
    assert request(application, "GET", CALENDAR, ALICE, "oauth-token") == 200
