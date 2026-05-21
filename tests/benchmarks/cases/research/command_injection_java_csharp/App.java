class App {
    void runCommand(HttpServletRequest request) throws Exception {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }

    void runSafeCommand(HttpServletRequest request) throws Exception {
        String cmd = validate(request.getParameter("cmd"));
        Runtime.getRuntime().exec(cmd);
    }
}
