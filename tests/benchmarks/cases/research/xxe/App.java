class App {
    void parseUserXml(HttpServletRequest request) {
        String xml = request.getParameter("xml");
        parsexml(xml);
    }

    void parseSafeXml(HttpServletRequest request) {
        String xml = defusedxml(request.getParameter("xml"));
        parsexml(xml);
    }
}
