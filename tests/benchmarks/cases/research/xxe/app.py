def parsexml(value):
    return value


def parse_user_xml(request):
    xml = request.args.get("xml")
    return parsexml(xml)


def parse_safe_xml(request):
    xml = defusedxml(request.args.get("xml"))
    return parsexml(xml)
