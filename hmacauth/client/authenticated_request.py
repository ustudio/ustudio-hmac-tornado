from tornado.httpclient import HTTPRequest

from urllib.parse import urlparse

from hmacauth.digest import generate_digest


def authenticated_request(*args, **kwargs):
    hmac_key = kwargs.pop("hmac_key")
    hmac_secret = kwargs.pop("hmac_secret")

    if len(args) > 0:
        url = args[0]
    elif "url" in kwargs:
        url = kwargs["url"]
    else:
        raise TypeError("Missing argument: 'url'")

    parsed_url = urlparse(url)
    if len(parsed_url.query) > 0:
        raise NotImplementedError("HMAC Authorized requests with query strings not yet supported")

    path = parsed_url.path

    body = kwargs.get("body", "")
    if isinstance(body, str):
        body = body.encode("utf-8")

    digest = generate_digest(hmac_secret, kwargs.get("method", "GET"), path, body)

    headers = kwargs.get("headers", {})
    headers["Authorization"] = "USTUDIO-HMAC-V2 {} {}".format(hmac_key, digest)
    kwargs["headers"] = headers

    return HTTPRequest(*args, **kwargs)
