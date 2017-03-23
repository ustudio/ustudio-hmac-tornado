import hmac
import hashlib
import logging

import functools
from tornado.web import HTTPError


def hmac_authorized(method):
    @functools.wraps(method)
    def hmac_authorized_wrapper(handler, *args, **kwargs):
        authorization = handler.request.headers.get("Authorization", "").split(" ")
        if len(authorization) != 3:
            logging.info("Invalid Authorization header {}".format(authorization))
            raise HTTPError(401)

        algorithm, key, provided_digest = authorization
        if algorithm != "USTUDIO-HMAC-V2":
            logging.info("Invalid algorithm {}".format(algorithm))
            raise HTTPError(401)

        secret = handler.get_hmac_secret(key)
        if secret is None:
            logging.info("Invalid HMAC key {}".format(key))
            raise HTTPError(401)

        expected_digest = hmac.new(
            secret.encode("utf-8"),
            "".join((handler.request.method, handler.request.path)).encode("utf-8") +
            handler.request.body,
            hashlib.sha256).hexdigest()

        if not hmac.compare_digest(expected_digest, provided_digest):
            logging.info("Invalid HMAC digest {}".format(provided_digest))
            raise HTTPError(401)

        method(handler, *args, **kwargs)

    return hmac_authorized_wrapper
