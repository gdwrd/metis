class App {
    void search(HttpServletRequest request, Statement statement) throws Exception {
        String id = request.getParameter("id");
        statement.executeQuery("SELECT * FROM users WHERE id=" + id);
    }

    void searchSafe(HttpServletRequest request, Connection connection) throws Exception {
        String id = request.getParameter("id");
        PreparedStatement statement = connection.prepareStatement("SELECT * FROM users WHERE id=?");
        statement.setString(1, id);
        statement.executeQuery();
    }
}
