import os


def route(path):
    def decorator(func):
        return func

    return decorator


def validate_command(value):
    return value


def sanitize_constant(value):
    return value


@route("/commands/run")
def run_command():
    command = request.args.get("command")
    ignored = validate_command("constant")
    return os.system(command)


@route("/commands/run-extra-source")
def run_command_with_extra_source():
    ignored = os.environ.get("IGNORED_COMMAND")
    command = request.args.get("command")
    return os.system(command)


@route("/commands/run-constant")
def run_constant_after_source():
    command = request.args.get("command")
    return os.system("constant")


@route("/commands/run-safe")
def run_validated_command():
    command = request.args.get("command")
    safe_command = validate_command(command)
    return os.system(safe_command)


@route("/commands/run-safe-after-unrelated-sanitizer")
def run_validated_after_unrelated_sanitizer():
    command = request.args.get("command")
    ignored = sanitize_constant("constant")
    safe_command = validate_command(command)
    return os.system(safe_command)


@route("/commands/run-conditionally-safe")
def run_conditionally_validated_command(flag):
    command = request.args.get("command")
    if flag:
        command = validate_command(command)
    return os.system(command)


@route("/commands/run-safe-overwritten")
def run_validated_command_overwritten():
    command = request.args.get("command")
    safe_command = validate_command(command)
    safe_command = command
    return os.system(safe_command)


@route("/commands/run-helper")
def run_helper_command():
    command = request.args.get("command")
    return command_sink(command)


@route("/commands/run-helper-safe")
def run_helper_sanitized():
    command = request.args.get("command")
    safe_command = validate_command(command)
    return command_sink(safe_command)


@route("/commands/run-helper-internal-safe")
def run_helper_with_internal_sanitizer():
    command = request.args.get("command")
    return sanitizing_command_sink(command)


@route("/commands/run-helper-constant")
def run_helper_with_constant():
    command = request.args.get("command")
    return command_sink("constant")


@route("/commands/run-helper-overwritten")
def run_helper_after_overwrite():
    command = request.args.get("command")
    command = "constant"
    return command_sink(command)


def command_sink(command):
    return os.system(command)


def sanitizing_command_sink(command):
    safe_command = validate_command(command)
    return os.system(safe_command)


@route("/commands/default")
def run_default_command():
    return os.system(DEFAULT_COMMAND)
