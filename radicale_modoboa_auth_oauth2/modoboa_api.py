"""Client of the Modoboa calendar rights API.

Same protocol as the radicale-modoboa-rights plugin, which is not a
dependency so both plugins can be installed independently.
"""

import threading
import time
from urllib.parse import quote_plus, urljoin

import requests

from radicale.log import logger

#: Path of Modoboa's OAuth2 token endpoint
TOKEN_ENDPOINT_PATH = "/api/o/token/"

#: Access tokens are renewed this many seconds before they expire
TOKEN_EXPIRY_MARGIN = 30

#: Lifetime assumed for access tokens returned without expires_in
DEFAULT_TOKEN_LIFETIME = 300


class RightsClient:
    """Send requests to the Modoboa rights endpoint.

    Requests are authenticated with an access token obtained with the
    OAuth2 client credentials grant, and renewed when needed.
    """

    def __init__(
        self, endpoint, client_id, client_secret, token_endpoint=None, timeout=5
    ):
        self._endpoint = endpoint
        self._token_endpoint = token_endpoint or urljoin(endpoint, TOKEN_ENDPOINT_PATH)
        # Client credentials are form-encoded before HTTP Basic (RFC 6749, 2.3.1)
        self._client_credentials = (quote_plus(client_id), quote_plus(client_secret))
        self._timeout = timeout
        # Keep the connection to the API alive
        self._session = requests.Session()
        self._access_token = None
        self._access_token_expires_at = 0.0
        self._token_lock = threading.Lock()

    @property
    def endpoint(self):
        return self._endpoint

    @property
    def token_endpoint(self):
        return self._token_endpoint

    def _request_access_token(self):
        """Get a new access token with the client credentials grant."""
        try:
            response = self._session.post(
                self._token_endpoint,
                data={"grant_type": "client_credentials"},
                auth=self._client_credentials,
                timeout=self._timeout,
            )
        except requests.RequestException as exc:
            logger.error("Modoboa token request failed: %s", exc)
            return None
        if response.status_code != 200:
            logger.error(
                "Modoboa token endpoint returned status %d: check %s, "
                "modoboa_client_id and modoboa_client_secret",
                response.status_code,
                self._token_endpoint,
            )
            return None
        try:
            data = response.json()
            token = data["access_token"]
            expires_in = data.get("expires_in")
            expires_in = (
                DEFAULT_TOKEN_LIFETIME if expires_in is None else float(expires_in)
            )
        except (ValueError, KeyError, TypeError, AttributeError):
            logger.error("Modoboa token endpoint returned invalid data")
            return None
        if not isinstance(token, str) or not token:
            logger.error("Modoboa token endpoint returned invalid data")
            return None
        self._access_token = token
        self._access_token_expires_at = time.monotonic() + max(
            expires_in - TOKEN_EXPIRY_MARGIN, 0
        )
        return token

    def _get_access_token(self):
        """Return a valid access token, None on failure."""
        with self._token_lock:
            if self._access_token and time.monotonic() < self._access_token_expires_at:
                return self._access_token
            return self._request_access_token()

    def _discard_access_token(self, token):
        """Forget token, refused by the API."""
        with self._token_lock:
            if self._access_token == token:
                self._access_token = None

    def _post(self, user):
        """Send the rights request, with a new token if the current one is refused."""
        response = None
        for attempt in range(2):
            token = self._get_access_token()
            if token is None:
                return None
            response = self._session.post(
                self._endpoint,
                json={"user": user},
                headers={"Authorization": f"Bearer {token}"},
                timeout=self._timeout,
            )
            if response.status_code != 401 or attempt:
                return response
            # Token expired or revoked before its expected expiration
            self._discard_access_token(token)
        return response

    def get_rights(self, user):
        """Return the rights Modoboa grants to user as a dict, None on failure."""
        try:
            response = self._post(user)
        except requests.RequestException as exc:
            logger.error("Modoboa rights request failed: %s", exc)
            return None
        if response is None:
            return None
        if response.status_code == 404:
            logger.error(
                "Modoboa rights endpoint not found: check %s "
                "(Modoboa 2.11 or later is required)",
                self._endpoint,
            )
            return None
        if response.status_code == 403:
            logger.error(
                "Modoboa rights endpoint refused access: modoboa_client_id must "
                "be the client id of the OAuth2 application named Radicale"
            )
            return None
        if response.status_code != 200:
            logger.error(
                "Modoboa rights endpoint returned status %d", response.status_code
            )
            return None
        try:
            data = response.json()
        except ValueError:
            logger.error("Modoboa rights endpoint returned invalid JSON")
            return None
        if not isinstance(data, dict):
            logger.error("Modoboa rights endpoint returned invalid data")
            return None
        return data
