<?php

$safe = validate($_GET['expr']);
eval($safe);

function eval_expr() {
    $expr = $_GET['expr'];
    return eval($expr);
}
