import subprocess


def validate_command(value):
    return value


def run_command(request):
    cmd = request.args.get("cmd")
    return subprocess.run(cmd, shell=True)


def run_safe_command(request):
    cmd = validate_command(request.args.get("cmd"))
    return subprocess.run(cmd, shell=True)

