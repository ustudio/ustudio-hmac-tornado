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

    path = parsed_url.path
    query = parsed_url.query

    body = kwargs.get("body", "")
    if isinstance(body, str):
        body = body.encode("utf-8")

    digest = generate_digest(hmac_secret, kwargs.get("method", "GET"), path, query, body)

    headers = kwargs.get("headers", {})
    headers["Authorization"] = "USTUDIO-HMAC-V2 {} {}".format(hmac_key, digest)
    kwargs["headers"] = headers

    return HTTPRequest(*args, **kwargs)
