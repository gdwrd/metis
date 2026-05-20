BASE_DIR = "/srv/files"
DEFAULT_FILE = "/srv/files/status.txt"


def route(path):
    def decorator(func):
        return func

    return decorator


def safe_join(base, name):
    return base + "/" + name


@route("/files/read")
def read_file():
    name = request.args.get("name")
    return open(name).read()


@route("/files/read-safe")
def read_safe_file():
    name = request.args.get("name")
    path = safe_join(BASE_DIR, name)
    return open(path).read()


@route("/files/default")
def read_default_file():
    return open(DEFAULT_FILE).read()
