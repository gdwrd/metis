import pickle


TRUSTED_BLOB = b"trusted"


def route(path):
    def decorator(func):
        return func

    return decorator


def validate_signature(value):
    return value


@route("/payload/load")
def load_payload():
    payload = request.get_data()
    return pickle.loads(payload)


@route("/payload/load-safe")
def load_signed_payload():
    payload = request.get_data()
    signed_payload = validate_signature(payload)
    return pickle.loads(signed_payload)


@route("/payload/default")
def load_default_payload():
    return pickle.loads(TRUSTED_BLOB)
