function parseQuery(req) {
  return req.query.id;
}

export default async function handler(req, res) {
  return res.send(req.query.id);
}
