class Controller {
  [HttpPost("/upload")]
  public IActionResult Upload(HttpRequest request) {
    return Ok(request.Query["name"]);
  }

  public void Minimal(WebApplication app) {
    app.MapGet("/minimal", MinimalHandler);
  }

  public string MinimalHandler(HttpRequest request) {
    return request.Query["id"];
  }
}
