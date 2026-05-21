<?php

function search_user() {
    $id = $_GET['id'];
    return $db->query("SELECT * FROM users WHERE id='$id'");
}
