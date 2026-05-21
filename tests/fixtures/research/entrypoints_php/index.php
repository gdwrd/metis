<?php
$top = $_GET['top'];
require 'lib.php';

function controller() {
  return $_GET['id'];
}

$routes = ['GET /php/:id' => 'controller'];
