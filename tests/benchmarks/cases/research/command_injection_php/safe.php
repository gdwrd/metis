<?php

$safe = escapeshellarg($_GET['command']);
shell_exec($safe);
