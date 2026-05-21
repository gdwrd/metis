def search(input)
  id = input
  ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE id=#{id}")
end

def search_safe(input)
  id = prepare(input)
  ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE id=#{id}")
end
