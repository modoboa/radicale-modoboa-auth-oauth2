radicale-modoboa-auth-oauth2
============================

An authentication plugin for Radicale provided by Modoboa.

Users log in with an OAuth2 access token issued by Modoboa, checked with
the introspection endpoint. If it fails, the plugin falls back to Dovecot
authentication.

The plugin can also authenticate share links: calendar URLs with a
``?token=`` query parameter, which give read access without an account.

Requirements:

* Radicale 3.5.6 or later
* Share links: Modoboa 2.11 or later and the ``radicale-modoboa-rights``
  plugin

Installation
------------

You can install this package from PyPi using the following command::

   pip install radicale-modoboa-auth-oauth2

Configuration
-------------

Here is a configuration example::

   [auth]
   type = radicale_modoboa_auth_oauth2

   oauth2_introspection_endpoint = <introspection url>
   # Recommended: avoid one introspection call per CalDAV request
   cache_logins = True

Dovecot settings (``dovecot_socket`` and others) are those of Radicale's
``dovecot`` authentication.

Share links
-----------

Share links are enabled by the following settings::

   [auth]
   modoboa_rights_endpoint = https://<modoboa>/api/v2/calendar-rights/
   # Credentials of Radicale's OAuth2 application in Modoboa
   modoboa_client_id = <client id>
   modoboa_client_secret = <client secret>

``modoboa_token_endpoint`` (default: ``/api/o/token/`` on the host of
``modoboa_rights_endpoint``) is Modoboa's OAuth2 token endpoint.

These are the settings of ``radicale-modoboa-rights``, which reads them
from its own ``[rights]`` section.

When a request has a ``token`` query parameter, the plugin logs it in as
``.modoboa-token-<SHA-256 of the token>``, with the token as password.
The hash keeps the token out of Radicale's logs, and the password check
makes the hash useless to log in. The plugin then asks the Modoboa rights
endpoint, like ``radicale-modoboa-rights``, whether this identity gets any
calendar, and refuses the login otherwise.

The ``radicale-modoboa-rights`` plugin is required: it only gives such
identities the calendars shared with them. Radicale can't store a
collection named after them, so other rights backends that grant them a
principal collection make every share link request fail.

With ``cache_logins``, a revoked token keeps working until the cached
login expires (``cache_successful_logins_expiry``).

Tests
-----

::

   pip install -e ".[test]"
   python -m pytest
