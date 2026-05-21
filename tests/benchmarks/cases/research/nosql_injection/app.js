function searchUsers(input, users) {
  const criteria = input;
  return users.find(criteria);
}

function searchUsersSafe(input, users) {
  const criteria = schema(input);
  return users.find(criteria);
}
