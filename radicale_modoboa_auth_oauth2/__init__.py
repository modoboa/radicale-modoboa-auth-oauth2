"""Authentication plugin for Radicale."""

import time

import requests

from radicale.auth.dovecot import Auth as DovecotAuth
from radicale.log import logger

#: Timeout (in seconds) of introspection requests
INTROSPECTION_TIMEOUT = 10


class Auth(DovecotAuth):
    """
    Custom authentication plugin using oAuth2 introspection mode.

    If the authentication fails with given credentials, it falls back to Dovecot
    authentication.

    Configuration:

    [auth]
    type = radicale_modoboa_auth_oauth2
    oauth2_introspection_endpoint = <URL HERE>
    # Recommended: avoid one introspection call per CalDAV request
    cache_logins = True
    """

    def __init__(self, configuration):
        super().__init__(configuration)
        try:
            self._endpoint = configuration.get("auth", "oauth2_introspection_endpoint")
        except KeyError:
            raise RuntimeError("oauth2_introspection_endpoint must be set")
        logger.warning("Using oauth2 introspection endpoint: %s" % (self._endpoint))
        # Keep the connection to the introspection endpoint alive
        self._session = requests.Session()
        self._enable_login_cache(configuration)

    def _enable_login_cache(self, configuration):
        """Enable Radicale's login cache for this plugin.

        Radicale only honors cache_logins for its builtin auth types, so it is
        always disabled for external plugins. Without it, every CalDAV request
        triggers an introspection call.
        """
        try:
            enabled = configuration.get("auth", "cache_logins")
        except KeyError:
            # Radicale version without login cache support
            return
        if not enabled or getattr(self, "_cache_logins", True) is True:
            return
        self._cache_logins = True
        self._cache_successful_logins_expiry = configuration.get(
            "auth", "cache_successful_logins_expiry"
        )
        self._cache_failed_logins_expiry = configuration.get(
            "auth", "cache_failed_logins_expiry"
        )
        self._cache_successful = dict()
        self._cache_failed = dict()
        self._cache_failed_logins_salt_ns = time.time_ns()
        logger.info(
            "auth.cache_logins enabled for oauth2 plugin (successful: %s sec, failed: %s sec)",
            self._cache_successful_logins_expiry,
            self._cache_failed_logins_expiry,
        )

    def _introspect(self, login, password):
        """Check if password is a valid access token for login."""
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "token": password
        }
        try:
            response = self._session.post(
                self._endpoint, data=data, headers=headers,
                timeout=INTROSPECTION_TIMEOUT
            )
        except requests.RequestException as exc:
            logger.error("OAuth2 introspection request failed: %s", exc)
            return False
        if response.status_code != 200:
            logger.warning(
                "OAuth2 introspection endpoint returned status %d",
                response.status_code
            )
            return False
        try:
            content = response.json()
        except ValueError:
            logger.error("OAuth2 introspection endpoint returned invalid JSON")
            return False
        return bool(content.get("active")) and content.get("username") == login

    def _login_ext(self, login, password, context):
        if self._introspect(login, password):
            return login
        return super()._login_ext(login, password, context)
