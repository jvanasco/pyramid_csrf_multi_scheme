pyramid_csrf_multi_scheme
=========================

.. image:: https://github.com/jvanasco/pyramid_csrf_multi_scheme/workflows/Python%20package/badge.svg
        :alt: Build Status

Pyramid's default session implementation provides for a single abstract session object,
that is not related to the scheme.

This package enables two separate cookie tokens on each request, bound to the scheme:

* a SECURE HTTPS only cookie, `csrf_https`
* a mixed-use insecure http token (which is also available on https), `csrf_http`

If the current scheme is `HTTPS`:

* only the SECURE HTTPS token will be considered
* HOWEVER calls to generate a new token will reset both the SECURE HTTPS and the
  insecure http tokens.

If the current scheme is `insecure http`:

* the SECURE HTTPS tokens are ignored as they are not even available, and only the
  insecure http token is considered.


Python Versions
---------------

This package is currently tested under Python2.7 and Python 3.6-3.15;
other 3.x versions may work.

This package should work on Pyramid1.x and 2.x


Why?
----

If an application supports both `HTTP` and `HTTPS` endpoints,
this package simplifies sandboxing the CSRF data for each one.

If an application only supports `HTTPS`, this library is irrelevant.

Most modern applications should only support HTTPS.


Is this necessary?
------------------

I'm not sure, but have decided to err on the side of caution.

The best solution is to only use HTTPS tokens and forms - but that is not always an
option. Some applications must still support plain HTTP in certain contexts; if you must
support plain HTTP, this package was designed to establish a security boundary between the
two protocols at the CSRF validation layer.


debugtoolbar support!
---------------------

just add to your `ENVIRONMENT.ini` file, or similar application configuration.

.. code-block:: python

    debugtoolbar.includes = pyramid_csrf_multi_scheme.debugtoolbar

Tthe debugtoolbar will now have a `CSRFMultiScheme` panel that has the following info:

* configuration info on the cookie names
* incoming request csrf values
* outgoing response csrf values


License
-------

Most of this is just code lightly edited from Pyramid, and
therefore available under Pyramid's licensing terms.

