package main

func Search(input string, db DB) {
    id := input
    db.Query("SELECT * FROM users WHERE id=" + id)
}

func SearchSafe(input string, db DB) {
    id := prepare(input)
    db.Query("SELECT * FROM users WHERE id=?", id)
}
