from tests.example_server import BaseHMACTestCase

from tornado.testing import gen_test

from hmacauth.client import authenticated_request


class TestAuthenticatedRequest(BaseHMACTestCase):
    @gen_test
    def test_signs_post_with_bytestring_body(self):
        response = yield self.http_client.fetch(authenticated_request(
            self.get_url("/authorized/argument"),
            method="POST",
            body=b"Some Body",
            hmac_key="correct-key",
            hmac_secret="secret"))

        self.assertEqual(200, response.code)

    @gen_test
    def test_signs_post_with_unicode_body(self):
        response = yield self.http_client.fetch(authenticated_request(
            self.get_url("/authorized/argument"),
            method="POST",
            body="Some Body",
            hmac_key="correct-key",
            hmac_secret="secret"))

        self.assertEqual(200, response.code)

    @gen_test
    def test_signs_explicit_get(self):
        response = yield self.http_client.fetch(authenticated_request(
            self.get_url("/authorized/argument"),
            method="GET",
            hmac_key="correct-key",
            hmac_secret="secret"))

        self.assertEqual(200, response.code)

    @gen_test
    def test_signs_implicit_get(self):
        response = yield self.http_client.fetch(authenticated_request(
            self.get_url("/authorized/argument"),
            hmac_key="correct-key",
            hmac_secret="secret"))

        self.assertEqual(200, response.code)

    @gen_test
    def test_handles_path_only_url(self):
        request = authenticated_request(
            "/authorized/argument",
            hmac_key="correct-key",
            hmac_secret="secret")

        request.url = self.get_url(request.url)

        response = yield self.http_client.fetch(request)

        self.assertEqual(200, response.code)

    @gen_test
    def test_includes_existing_headers_in_request(self):
        response = yield self.http_client.fetch(authenticated_request(
            self.get_url("/authorized/argument"),
            headers={
                "X-Ping": "Pong"
            },
            hmac_key="correct-key",
            hmac_secret="secret"))

        self.assertEqual(200, response.code)
        self.assertEqual("Pong", response.body.decode("utf8"))

    @gen_test
    def test_signs_url_as_keyword_argument(self):
        response = yield self.http_client.fetch(authenticated_request(
            url=self.get_url("/authorized/argument"),
            hmac_key="correct-key",
            hmac_secret="secret"))

        self.assertEqual(200, response.code)

    @gen_test
    def test_raises_exception_without_url_argument(self):
        with self.assertRaises(TypeError):
            yield self.http_client.fetch(authenticated_request(
                hmac_key="correct-key",
                hmac_secret="secret"))

    @gen_test
    def test_normalizes_and_signs_query_arguments(self):
        response = yield self.http_client.fetch(authenticated_request(
            url=self.get_url("/authorized/argument?bar=value%202&Foo=value%3f1&blank"),
            hmac_key="correct-key",
            hmac_secret="secret"))

        self.assertEqual(200, response.code)
