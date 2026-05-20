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
