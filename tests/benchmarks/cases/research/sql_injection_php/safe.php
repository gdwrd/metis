<?php

$safe = intval($_GET['id']);
$db->query("SELECT * FROM users WHERE id='$safe'");
