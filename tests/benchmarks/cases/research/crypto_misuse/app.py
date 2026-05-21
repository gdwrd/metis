def hash_token(request):
    token = request.args.get("token")
    return md5(token)


def hash_token_safe(request):
    token = hmac(request.args.get("token"))
    return md5(token)
