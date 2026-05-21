radicale-modoboa-token-auth
===========================

An OAuth2 introspection based authentication plugin for Radicale provided by
Modoboa.

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

Alternatively, if you wish to keep the OAuth2 client secret in a seperate file::

   [auth]
   type = radicale_modoboa_auth_oauth2

   oauth2_introspection_endpoint = <introspection url with no secret/password>
   oauth2_introspection_endpoint_secret = <path to file containing secret>

Introspection URL may also contain the path to a Unix domain socket for local
deployments: ``http+unix://radicale@%2Frun%2F<service>%2Fgunicorn.sock/<path>``
