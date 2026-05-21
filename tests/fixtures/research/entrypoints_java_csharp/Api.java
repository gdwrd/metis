class Api extends HttpServlet {
  @GetMapping("/items/{id}")
  public String getItem(Request request) {
    return request.getParameter("q");
  }

  public void doGet(HttpServletRequest request, HttpServletResponse response) {
    request.getParameter("debug");
  }

  public String helper(Request request) {
    return request.getParameter("debug");
  }
}
