"""Authentication plugin for Radicale."""

import requests_unixsocket
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
    oauth2_introspection_endpoint_secret = <FILEPATH>  # OPTIONAL: File containing the client secret (if not part of the URL)
    """

    def __init__(self, configuration):
        super().__init__(configuration)
        try:
            endpoint_url = configuration.get("auth", "oauth2_introspection_endpoint")
        except KeyError:
        	raise RuntimeError("oauth2_introspection_endpoint must be set") from None

        # Optionally read client secret from separate file if not present in URL
        endpoint_url_dict = urllib3.util.parse_url(endpoint_url)._asdict()
        auth_parts = endpoint_url_dict["auth"].split(":", 1)
        if len(auth_parts) == 1:
            try:
                secret_path = configuration.get("auth", "oauth2_introspection_endpoint_secret")
                with open(secret_path) as f:
                    secret = f.read().rstrip("\r\n")
            except KeyError:
                raise RuntimeError(
                    "oauth2_introspection_endpoint has no client secret and "
                    "oauth2_introspection_endpoint_secret is not set"
                ) from None
            except IOError as exc:
                raise RuntimeError(
                    f"Path oauth2_introspection_endpoint_secret ({secret_path}) "
                    f"could not be read: {type(exc).__name__}: {exc}"
                ) from exc
            else:
                auth_parts.append(secret)
        del endpoint_url_dict["auth"]
        self._endpoint = urllib3.util.Url(**endpoint_url_dict).url
        self._endpoint_auth = tuple(auth_parts)

        # Log OAuth2 introspection URL without secret
        clean_endpoint_url = urllib3.util.Url(**endpoint_url_dict, auth=f"{auth_parts[0]}:********").url
        logger.warning(f"Using OAuth2 introspection endpoint: {clean_endpoint_url}")

    def _login_ext(self, login, password, context):
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "token": password
        }
        with requests_unixsocket.Session() as session:
            response = session.post(self._endpoint, data=data, headers=headers, auth=self._endpoint_auth)
            content = response.json()
            if response.status_code == 200 and content.get("active") and content.get("username") == login:
                return login
            return super()._login_ext(login, password, context)
