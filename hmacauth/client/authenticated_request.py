from tornado.httpclient import HTTPRequest

from urllib.parse import urlparse

from hmacauth.digest import generate_digest


def authenticated_request(*args, **kwargs):
    hmac_key = kwargs.pop("hmac_key")
    hmac_secret = kwargs.pop("hmac_secret")

    path = urlparse(args[0]).path

    body = kwargs.get("body", "")
    if isinstance(body, str):
        body = body.encode("utf-8")

    digest = generate_digest(hmac_secret, kwargs.get("method", "GET"), path, body)

    headers = kwargs.get("headers", {})
    headers["Authorization"] = "USTUDIO-HMAC-V2 {} {}".format(hmac_key, digest)
    kwargs["headers"] = headers

    return HTTPRequest(*args, **kwargs)
