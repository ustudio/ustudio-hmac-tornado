import hmac
import hashlib


def generate_digest(secret, method, path, body):
    return hmac.new(
        secret.encode("utf-8"),
        "\n".join((method, path, "", "")).encode("utf-8") +
        body,
        hashlib.sha256).hexdigest()
