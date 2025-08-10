"""Authentication plugin for Radicale."""

import requests
import urllib3.util  # requests dependency

from radicale.auth.dovecot import Auth as DovecotAuth
from radicale.log import logger


class Auth(DovecotAuth):
    """
    Custom authentication plugin using oAuth2 introspection mode.

    If the authentication fails with given credentials, it falls back to Dovecot
    authentication.

    Configuration:

    [auth]
    type = radicale_modoboa_auth_oauth2
    oauth2_introspection_endpoint = <URL HERE>
    """

    def __init__(self, configuration):
        super().__init__(configuration)
        try:
            self._endpoint = configuration.get("auth", "oauth2_introspection_endpoint")
        except KeyError:
            raise RuntimeError("oauth2_introspection_endpoint must be set")

        # Log OAuth2 introspection URL without secret
        clean_endpoint_url = self._endpoint
        clean_url_dict = urllib3.util.parse_url(clean_endpoint_url)._asdict()
        auth_parts = clean_url_dict["auth"].split(":", 1)
        if len(auth_parts) == 2:
            clean_url_dict["auth"] = f"{auth_parts[0]}:********"
            clean_endpoint_url = urllib3.util.Url(**clean_url_dict).url
        logger.warning(f"Using OAuth2 introspection endpoint: {clean_endpoint_url}")

    def _login_ext(self, login, password, context):
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "token": password
        }
        response = requests.post(self._endpoint, data=data, headers=headers)
        content = response.json()
        if response.status_code == 200 and content.get("active") and content.get("username") == login:
            return login
        return super()._login_ext(login, password, context)
