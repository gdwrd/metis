import requests


INTERNAL_STATUS_URL = "http://metadata.internal/status"


def route(path):
    def decorator(func):
        return func

    return decorator


def allowlist_url(value):
    return value


@route("/fetch/url")
def fetch_url():
    url = request.args.get("url")
    return requests.get(url)


@route("/fetch/url-safe")
def fetch_allowlisted_url():
    url = request.args.get("url")
    safe_url = allowlist_url(url)
    return requests.get(safe_url)


@route("/fetch/internal")
def fetch_internal_status():
    return requests.get(INTERNAL_STATUS_URL)
