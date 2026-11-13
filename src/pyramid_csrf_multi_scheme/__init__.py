# stdlib
import sys
import uuid

# pypi
from pyramid.interfaces import ICSRFStoragePolicy
from pyramid.request import Request
from pyramid.util import strings_differ
from pyramid.util import SimpleSerializer
from webob.cookies import CookieProfile
from webob.response import Response
from zope.interface import implementer


# ==============================================================================


__VERSION__ = "1.0.0"


# ------------------------------------------------------------------------------


"""
The following functions are taken from Pyramid directly.

* `pyramid.compat.bytes_`
* `pyramid.compat.text_`
"""

text_type = unicode if (sys.version_info[0] == 2) else str
binary_type = str if (sys.version_info[0] == 2) else bytes


def text_(s, encoding="latin-1", errors="strict"):
    """If ``s`` is an instance of ``binary_type``, return
    ``s.decode(encoding, errors)``, otherwise return ``s``"""
    if isinstance(s, binary_type):
        return s.decode(encoding, errors)
    return s


def bytes_(s, encoding="latin-1", errors="strict"):
    """If ``s`` is an instance of ``text_type``, return
    ``s.encode(encoding, errors)``, otherwise return ``s``"""
    if isinstance(s, text_type):
        return s.encode(encoding, errors)
    return s


# ==============================================================================


@implementer(ICSRFStoragePolicy)
class DualCookieCSRFStoragePolicy(object):
    """
    A re-implementation of ``pyramid.csrf.CookieCSRFStoragePolicy``.
    This policy runs separate csrf tokens on http and https connections.

    If the connection is https:
        expiring the csrf will expire the http and https
        only the https csrf will be consulted

    If the connection is http:
        expiring the csrf will expire the http
        only the http csrf will be consulted

    last synced to pyramid: 1.10.4

    NOTE: this does not support a ``secure`` argument
    """

    _token_factory = staticmethod(lambda: text_(uuid.uuid4().hex))

    def __init__(
        self,
        cookie_name_secure="csrf_https",
        cookie_name_http="csrf_http",
        secure=None,
        httponly=False,
        domain=None,
        max_age=None,
        path="/",
        samesite="Lax",
    ):
        if secure is not None:
            raise ValueError(
                "`DualCookieCSRFStoragePolicy` does not support "
                "the `secure` argument."
            )
        serializer = SimpleSerializer()
        self.cookie_name_secure = cookie_name_secure
        self.cookie_name_http = cookie_name_http
        self.cookie_profile_secure = CookieProfile(
            cookie_name=cookie_name_secure,
            secure=True,
            max_age=max_age,
            httponly=httponly,
            path=path,
            domains=[domain],
            serializer=serializer,
            samesite=samesite,
        )
        self.cookie_profile_http = CookieProfile(
            cookie_name=cookie_name_http,
            secure=False,
            max_age=max_age,
            httponly=httponly,
            path=path,
            domains=[domain],
            serializer=serializer,
            samesite=samesite,
        )

    @property
    def cookie_profile(self):
        """
        Returns the active cookie profile for the request's scheme.
        """
        raise ValueError(
            "`DualCookieCSRFStoragePolicy` supports access "
            "via the attributes `.cookie_profile_secure` and "
            "via the attributes `.cookie_profile_http`. The "
            "attribute `.cookie_profile` is not supported."
        )

    def new_csrf_token(self, request):
        # type: (Request) -> str
        """Rotate the HTTP token and also the HTTPS token on secure requests."""

        def _issue_token(cookie_name, profile):
            # type: (str, CookieProfile) -> str
            """Store a fresh token and schedule its response cookie."""
            token = self._token_factory()
            request.cookies[cookie_name] = token

            def _set_cookie(request, response):
                # type: (Request, Response) -> None
                profile.set_cookies(response, token)

            request.add_response_callback(_set_cookie)
            return token

        token_http = _issue_token(self.cookie_name_http, self.cookie_profile_http)
        if request.scheme == "https":
            return _issue_token(self.cookie_name_secure, self.cookie_profile_secure)
        return token_http

    def get_csrf_token(self, request):
        """
        Returns the currently active CSRF token by checking the cookies
        sent with the current request.
        """
        if request.scheme == "https":
            # only consult the secure cookie
            bound_cookies = self.cookie_profile_secure.bind(request)
        else:
            # the only accessible cookie is http insecure
            bound_cookies = self.cookie_profile_http.bind(request)
        token = bound_cookies.get_value()
        if not token:
            token = self.new_csrf_token(request)
        return token

    def check_csrf_token(self, request, supplied_token):
        # type: (Request, object) -> bool
        """Check a text or byte token using Pyramid's timing-safe comparison."""
        if not isinstance(supplied_token, (text_type, binary_type)):
            return False
        try:
            supplied_bytes = bytes_(supplied_token)
        except UnicodeEncodeError:
            return False
        expected_token = self.get_csrf_token(request)
        return not strings_differ(bytes_(expected_token), supplied_bytes)

    def get_csrf_token_scheme(self, request, scheme):
        """this is a utility for testing"""
        if scheme not in ("https", "http"):
            raise ValueError("unknown scheme")
        if scheme == "https":
            if request.scheme != "https":
                return None
            bound_cookies = self.cookie_profile_secure.bind(request)
            token = bound_cookies.get_value()
            return token
        bound_cookies = self.cookie_profile_http.bind(request)
        token = bound_cookies.get_value()
        return token
