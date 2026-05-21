def validate_expr(value):
    return value


def eval_expr(request):
    expr = request.args.get("expr")
    return eval(expr)


def eval_safe_expr(request):
    expr = validate_expr(request.args.get("expr"))
    return eval(expr)

