# stdlib
import unittest

# pypi
from pyramid.config import Configurator
from pyramid.interfaces import ICSRFStoragePolicy

# our local tested package
from pyramid_csrf_multi_scheme import DualCookieCSRFStoragePolicy


# ==============================================================================


class DummyRequest(object):
    registry = None
    session = None
    response_callbacks = None
    scheme = None

    def __init__(self, registry=None, session=None, scheme="http"):
        self.registry = registry
        self.session = session
        self.cookies = {}
        self.scheme = scheme
        self.response_callbacks = []

    def add_response_callback(self, callback):
        self.response_callbacks.append(callback)

    def response_callback(self, request, response):
        while len(self.response_callbacks):
            callback = self.response_callbacks.pop()
            callback(request, response)


class MockResponse(object):
    def __init__(self):
        self.headerlist = []


class TestCookieCSRFStoragePolicy_InsecureHttp(unittest.TestCase):
    """tests on the insecure channel"""

    def _makeOne(self, **kw):
        return DualCookieCSRFStoragePolicy(**kw)

    def test_register_cookie_csrf_policy(self):
        config = Configurator()
        config.set_csrf_storage_policy(self._makeOne())
        config.commit()
        policy = config.registry.queryUtility(ICSRFStoragePolicy)
        self.assertTrue(isinstance(policy, DualCookieCSRFStoragePolicy))

    def test_get_cookie_csrf_with_no_existing_cookie_sets_cookies(self):
        response = MockResponse()
        request = DummyRequest()

        policy = self._makeOne()
        token = policy.get_csrf_token(request)
        request.response_callback(request, response)
        self.assertEqual(
            response.headerlist,
            [("Set-Cookie", "csrf_http={}; Path=/; SameSite=Lax".format(token))],
        )

    def test_get_cookie_csrf_nondefault_samesite(self):
        response = MockResponse()
        request = DummyRequest()

        policy = self._makeOne(samesite=None)
        token = policy.get_csrf_token(request)
        request.response_callback(request, response)
        self.assertEqual(
            response.headerlist, [("Set-Cookie", "csrf_http={}; Path=/".format(token))]
        )

    def test_existing_cookie_csrf_does_not_set_cookie(self):
        request = DummyRequest()
        request.cookies = {"csrf_http": "e6f325fee5974f3da4315a8ccf4513d2"}

        policy = self._makeOne()
        token = policy.get_csrf_token(request)

        self.assertEqual(token, "e6f325fee5974f3da4315a8ccf4513d2")
        self.assertEqual(len(request.response_callbacks), 0)

    def test_new_cookie_csrf_with_existing_cookie_sets_cookies(self):
        request = DummyRequest()
        request.cookies = {"csrf_http": "e6f325fee5974f3da4315a8ccf4513d2"}

        policy = self._makeOne()
        token = policy.new_csrf_token(request)

        response = MockResponse()
        request.response_callback(request, response)
        self.assertEqual(
            response.headerlist,
            [("Set-Cookie", "csrf_http={}; Path=/; SameSite=Lax".format(token))],
        )

    def test_get_csrf_token_returns_the_new_token(self):
        request = DummyRequest()
        request.cookies = {"csrf_http": "foo"}

        policy = self._makeOne()
        self.assertEqual(policy.get_csrf_token(request), "foo")

        token = policy.new_csrf_token(request)
        self.assertNotEqual(token, "foo")
        self.assertEqual(token, policy.get_csrf_token(request))

    def test_check_csrf_token(self):
        request = DummyRequest()

        policy = self._makeOne()
        self.assertFalse(policy.check_csrf_token(request, "foo"))

        request.cookies = {"csrf_http": "foo"}
        self.assertTrue(policy.check_csrf_token(request, "foo"))
        self.assertTrue(policy.check_csrf_token(request, b"foo"))
        self.assertFalse(policy.check_csrf_token(request, "bar"))

    def test_check_csrf_token_rejects_malformed_input(self):
        # type: () -> None
        """Malformed inputs fail even when there is no cookie to compare."""
        request = DummyRequest()
        policy = self._makeOne()

        for supplied_token in (None, 42, [b"foo"], u"\u2603"):
            self.assertFalse(policy.check_csrf_token(request, supplied_token))

        self.assertEqual(request.cookies, {})
        self.assertEqual(request.response_callbacks, [])


class TestCookieCSRFStoragePolicy_SecureHTTPS(unittest.TestCase):
    """tests on the SECURE HTTPS"""

    def _makeOne(self, **kw):
        return DualCookieCSRFStoragePolicy(**kw)

    def test_register_cookie_csrf_policy(self):
        config = Configurator()
        config.set_csrf_storage_policy(self._makeOne())
        config.commit()
        policy = config.registry.queryUtility(ICSRFStoragePolicy)
        self.assertTrue(isinstance(policy, DualCookieCSRFStoragePolicy))

    def test_get_cookie_csrf_with_no_existing_cookie_sets_cookies(self):
        response = MockResponse()
        request = DummyRequest(scheme="https")

        policy = self._makeOne()
        token_secure = policy.get_csrf_token(request)
        token_http = policy.get_csrf_token_scheme(request, "http")
        request.response_callback(request, response)

        self.assertEqual(
            response.headerlist,
            [
                (
                    "Set-Cookie",
                    "csrf_https={}; Path=/; secure; SameSite=Lax".format(token_secure),
                ),
                ("Set-Cookie", "csrf_http={}; Path=/; SameSite=Lax".format(token_http)),
            ],
        )

    def test_get_cookie_csrf_nondefault_samesite(self):
        response = MockResponse()
        request = DummyRequest(scheme="https")

        policy = self._makeOne(samesite=None)
        token_secure = policy.get_csrf_token(request)
        token_http = policy.get_csrf_token_scheme(request, "http")
        request.response_callback(request, response)
        self.assertEqual(
            response.headerlist,
            [
                ("Set-Cookie", "csrf_https={}; Path=/; secure".format(token_secure)),
                ("Set-Cookie", "csrf_http={}; Path=/".format(token_http)),
            ],
        )

    def test_existing_cookie_csrf_does_not_set_cookie(self):
        request = DummyRequest(scheme="https")
        request.cookies = {"csrf_https": "e6f325fee5974f3da4315a8ccf4513d2"}

        policy = self._makeOne()
        token_secure = policy.get_csrf_token(request)

        self.assertEqual(token_secure, "e6f325fee5974f3da4315a8ccf4513d2")
        self.assertEqual(len(request.response_callbacks), 0)

    def test_new_cookie_csrf_with_existing_cookie_sets_cookies(self):
        request = DummyRequest(scheme="https")
        request.cookies = {"csrf_https": "e6f325fee5974f3da4315a8ccf4513d2"}

        policy = self._makeOne()
        token_secure = policy.new_csrf_token(request)
        token_http = policy.get_csrf_token_scheme(request, "http")

        response = MockResponse()
        request.response_callback(request, response)
        self.assertEqual(
            response.headerlist,
            [
                (
                    "Set-Cookie",
                    "csrf_https={}; Path=/; secure; SameSite=Lax".format(token_secure),
                ),
                ("Set-Cookie", "csrf_http={}; Path=/; SameSite=Lax".format(token_http)),
            ],
        )

    def test_get_csrf_token_returns_the_new_token(self):
        request = DummyRequest(scheme="https")
        request.cookies = {"csrf_https": "foo"}

        policy = self._makeOne()
        self.assertEqual(policy.get_csrf_token(request), "foo")

        token_secure = policy.new_csrf_token(request)
        self.assertNotEqual(token_secure, "foo")
        self.assertEqual(token_secure, policy.get_csrf_token(request))

    def test_check_csrf_token(self):
        request = DummyRequest(scheme="https")

        policy = self._makeOne()
        self.assertFalse(policy.check_csrf_token(request, "foo"))

        request.cookies = {"csrf_https": "foo"}
        self.assertTrue(policy.check_csrf_token(request, "foo"))
        self.assertFalse(policy.check_csrf_token(request, "bar"))
