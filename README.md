# ustudio-hmac-tornado
Client, Server and Testing utilities for HMAC authentication between
services using Tornado

## How it Works ##

Clients and servers communicate using a shared secret, which is not
transmitted as part of the protocol.

When a client makes an HTTP request, it generates a SHA-256 HMAC
digest of the concatenated path, HTTP method and request body, and
includes an `Authorization` HTTP header of the form:

```
USTUDIO-HMAC-V2 [KEY] [DIGEST]
```

On the server side, the server uses the provided key to look up a
pre-shared secret; it then reproduces the digest signing algorithm
against the request, and compares that the digest it generated matches
that provided by the client.

If the key does not correspond to a known secret, if the secrets do
not match between client and server, or if any of the signed
parameters have been changed in the request, the digests will not
match and the server will reject the request.

## Installation ##

```
pip install ustudio-hmac-tornado
```

## Usage ##

This library implements both client-side signing of requests, and
server-side validating of signed requests.

## Client Side Usage ##

The `hmacauth.client.authenticated_request` function can be used to
generate `tornado.httpclient.HTTPRequest` objects which are
authenticated against a key and secret.

It requires three arguments:

* `url` - May be the first positional or a keyword argument
* `hmac_key` - Must be a keyword argument
* `hmac_secret` - Must be a keyword argument

`hmac_key` and `hmac_secret` will be removed from the arguments, and
all other arguments will be passed to the `HTTPRequest`
constructor. The headers will be modified to include the
`Authorization` header with the provided `hmac_key` and generated
digest.

```python
from hmacauth.client import authenticated_request

response = await http_client.fetch(authenticated_request(
    "https://some.service/api/v1/resource",
    method="POST",
    body=json.dumps({
        "request": "body"
    }).encode("utf8")))
```

## Server Side Usage ##

On the server side, the library provides a decorator
`hmacauth.server.hmac_authorized`, which works similarly to
`tornado.web.authorized`, but validates requests using HMAC
authorization, rather than checking the `current_user` property.

When a request is made to a decorated method, the `Authorization`
header is parsed, and the `key` is looked up by calling
`handler.get_hmac_secret(key)` on the handler with the wrapped method.

`handler.get_hmac_secret` should return the correct secret for that
key, or `None` if the key is invalid. The decorator will then use that
key to validate the request and raise an `HTTPError(401)` if it is
invalid, or invoke the method if it is valid.


```python
from tornado.web import RequestHandler
from hmacauth.server import hmac_authorized


class SecureRoute(RequestHandler):
    @hmac_authorized
    def post(self, some, args):
        # Only called if the request is valid
        self.finish("You're OK!")

    def get_hmac_secret(self, key):
        return self.settings["database"].get_secret(key)
```
