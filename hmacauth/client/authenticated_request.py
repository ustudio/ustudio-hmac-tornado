import hmac
import hashlib

from tornado.httpclient import HTTPRequest

from urllib.parse import urlparse


def authenticated_request(*args, **kwargs):
    hmac_key = kwargs.pop("hmac_key")
    hmac_secret = kwargs.pop("hmac_secret")

    path = urlparse(args[0]).path

    body = kwargs.get("body", "")
    if isinstance(body, str):
        body = body.encode("utf-8")

    digest = hmac.new(
        hmac_secret.encode("utf-8"),
        "".join((kwargs.get("method", "GET"), path)).encode("utf-8") +
        body,
        hashlib.sha256).hexdigest()

    headers = kwargs.get("headers", {})
    headers["Authorization"] = "USTUDIO-HMAC-V2 {} {}".format(hmac_key, digest)
    kwargs["headers"] = headers

    return HTTPRequest(*args, **kwargs)
