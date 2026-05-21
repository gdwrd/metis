class Worker {
  void Run(string input) {
    System.Diagnostics.Process.Start(input);
  }

  void RunSafe(string input) {
    var clean = ShellEscape(input);
    System.Diagnostics.Process.Start(clean);
  }
}
