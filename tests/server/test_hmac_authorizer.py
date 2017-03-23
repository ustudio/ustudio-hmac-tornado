import hmac
import hashlib

from tests.example_server import BaseHMACTestCase


class TestHMACAuthorizer(BaseHMACTestCase):
    def generate_digest(self, secret, method, path, body):
        if isinstance(body, str):
            body = body.encode("utf-8")

        return hmac.new(
            secret.encode("utf-8"),
            "\n".join((method, path, "", "")).encode("utf-8") + body,
            hashlib.sha256).hexdigest()

    def test_request_raises_if_request_does_not_have_authorization_header(self):
        response = self.fetch(
            "/authorized/argument",
            method="GET")

        self.assertEqual(401, response.code)

    def test_request_raises_if_algorithm_is_invalid(self):
        digest = self.generate_digest("secret", "GET", "/authorized/argument", "")
        response = self.fetch(
            "/authorized/argument",
            headers={
                "Authorization": "WRONG-ALGORITHM correct-key {}".format(digest)
            })

        self.assertEqual(401, response.code)

    def test_request_raises_if_key_is_invalid(self):
        digest = self.generate_digest("secret", "GET", "/authorized/argument", "")
        response = self.fetch(
            "/authorized/argument",
            headers={
                "Authorization": "USTUDIO-HMAC-V2 wrong-key {}".format(digest)
            })

        self.assertEqual(401, response.code)

    def test_request_raises_if_secret_is_invalid(self):
        digest = self.generate_digest("wrongsecret", "GET", "/authorized/argument", "")
        response = self.fetch(
            "/authorized/argument",
            headers={
                "Authorization": "USTUDIO-HMAC-V2 correct-key {}".format(digest)
            })

        self.assertEqual(401, response.code)

    def test_request_raises_if_methods_differ(self):
        digest = self.generate_digest("secret", "POST", "/authorized/argument", "")
        response = self.fetch(
            "/authorized/argument",
            headers={
                "Authorization": "USTUDIO-HMAC-V2 correct-key {}".format(digest)
            })

        self.assertEqual(401, response.code)

    def test_request_raises_if_paths_differ(self):
        digest = self.generate_digest("secret", "GET", "/authorized/other", "")
        response = self.fetch(
            "/authorized/argument",
            headers={
                "Authorization": "USTUDIO-HMAC-V2 correct-key {}".format(digest)
            })

        self.assertEqual(401, response.code)

    def test_request_raises_if_bodies_differ(self):
        digest = self.generate_digest("secret", "POST", "/authorized/argument", "Different Body")
        response = self.fetch(
            "/authorized/argument",
            method="POST",
            headers={
                "Authorization": "USTUDIO-HMAC-V2 correct-key {}".format(digest)
            },
            body="Some Body")

        self.assertEqual(401, response.code)

    def test_get_succeeds_with_valid_hmac(self):
        digest = self.generate_digest("secret", "GET", "/authorized/argument", "")
        response = self.fetch(
            "/authorized/argument",
            headers={
                "Authorization": "USTUDIO-HMAC-V2 correct-key {}".format(digest)
            })

        self.assertEqual(200, response.code)

    def test_post_succeeds_with_valid_hmac(self):
        digest = self.generate_digest("secret", "POST", "/authorized/argument", "Some Body")
        response = self.fetch(
            "/authorized/argument",
            method="POST",
            headers={
                "Authorization": "USTUDIO-HMAC-V2 correct-key {}".format(digest)
            },
            body="Some Body")

        self.assertEqual(200, response.code)
