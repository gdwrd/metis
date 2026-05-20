def route(path):
    def decorator(func):
        return func

    return decorator


def require_project_member(func):
    return func


def load_project(project_id):
    return {"id": project_id}


@route("/projects/<project_id>")
@require_project_member
def get_project(project_id):
    return load_project(project_id)


@route("/projects/<project_id>/settings")
def update_project_settings(project_id):
    return {"updated": project_id}


@route("/status")
def status():
    return {"ok": True}


def sanitize_name(value):
    return value.strip()


def store_project_name(name):
    name = sanitize_name(name)
    return name


def store_project_description(description):
    return description


def set_quota_limit(limit):
    if len(limit) < 32:
        return limit
    return None


def set_quota_default(quota):
    return quota


def secure_state_locked():
    return True


def debug_enable(value):
    return value


def update_debug_state(value):
    if secure_state_locked():
        return None
    return debug_enable(value)


def update_debug_shadow(value):
    return debug_enable(value)
