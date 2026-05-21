function search(input, db) {
  const id = input;
  return db.query("SELECT * FROM users WHERE id=" + id);
}

function searchSafe(input, db) {
  const id = prepare(input);
  return db.query("SELECT * FROM users WHERE id=?", id);
}
