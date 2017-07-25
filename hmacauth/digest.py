import hmac
import hashlib

try:
    from urllib.parse import parse_qs, quote
except ImportError:
    from urlparse import parse_qs
    from urllib import quote


def generate_digest(secret, method, path, query, body):
    parsed_query = parse_qs(query, keep_blank_values=True)

    canonical_query = []

    for key in sorted(parsed_query.keys()):
        for value in sorted(parsed_query[key]):
            canonical_query.append("=".join((key, quote(value))))

    return hmac.new(
        secret.encode("utf-8"),
        "\n".join((method, path, "&".join(canonical_query), "")).encode("utf-8") +
        body,
        hashlib.sha256).hexdigest()
