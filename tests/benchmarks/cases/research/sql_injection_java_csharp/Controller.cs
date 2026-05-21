class Controller {
  void Search(Request request, SqlConnection connection) {
    var id = request.Query["id"];
    var command = new SqlCommand("SELECT * FROM users WHERE id=" + id, connection);
    command.ExecuteReader();
  }

  void SearchSafe(Request request, SqlConnection connection) {
    var id = prepare(request.Query["id"]);
    var command = new SqlCommand("SELECT * FROM users WHERE id=@id", connection);
    command.Parameters.AddWithValue("@id", id);
    command.ExecuteReader();
  }
}
