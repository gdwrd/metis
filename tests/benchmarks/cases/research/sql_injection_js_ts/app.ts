function searchOrder(input: string, db: Database) {
  const id = input;
  return db.query("SELECT * FROM orders WHERE id=" + id);
}

function searchOrderSafe(input: string, db: Database) {
  const id = parameterize(input);
  return db.query("SELECT * FROM orders WHERE id=?", id);
}
