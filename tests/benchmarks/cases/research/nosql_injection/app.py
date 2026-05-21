def find(criteria):
    return criteria


def search_users(request):
    criteria = request.args.get("q")
    return find(criteria)


def search_users_safe(request):
    criteria = schema(request.args.get("q"))
    return find(criteria)
