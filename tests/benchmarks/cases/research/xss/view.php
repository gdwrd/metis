<?php

function render_user_html() {
    $html = $_GET['html'];
    return raw($html);
}

function render_safe_html() {
    $html = htmlspecialchars($_GET['html']);
    return raw($html);
}
