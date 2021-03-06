from tornado.testing import AsyncHTTPTestCase
from tornado.web import RequestHandler, Application
from tornado import gen

from hmacauth.server import hmac_authorized


class AuthorizedRoute(RequestHandler):
    @hmac_authorized
    @gen.coroutine
    def get(self, arg):
        yield gen.moment
        self.finish(self.request.headers.get("X-Ping", ""))

    @hmac_authorized
    def post(self, arg):
        pass

    def get_hmac_secret(self, key):
        if key == "correct-key":
            return "secret"
        return None


class BaseHMACTestCase(AsyncHTTPTestCase):
    def get_app(self):
        return Application([(r"/authorized/(.*)", AuthorizedRoute)])
