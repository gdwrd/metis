def escape(value):
    return value


def render_template_string(value):
    return value


def render_user_template(request):
    template = request.args.get("template")
    return render_template_string(template)


def render_safe_template(request):
    template = escape(request.args.get("template"))
    return render_template_string(template)

