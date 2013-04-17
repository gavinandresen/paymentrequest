<?php
/*
 * Fetch and serve up a payment request from memcache
 */

if (empty($_REQUEST['h'])) {
    header("HTTP/1.0 404 Not Found");
    exit(0);
}

$memcache = new Memcache;
if (! $memcache->connect('localhost', 11211)) {
    header("HTTP/1.0 503 Service Unavailable");
    exit(0);
}

$data = $memcache->get($_REQUEST['h']);
if ($data === FALSE) {
    header("HTTP/1.0 404 Not Found");
    exit(0);
}

header('Content-Type: application/x-bitcoinpaymentrequest');
$filename = "r".(string)time().".bitcoinpaymentrequest";
header('Content-Disposition: inline; filename='.$filename);
header('Content-Transfer-Encoding: binary');
header('Expires: 0');
header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
header('Pragma: public');
header('Content-Length: ' . (string)strlen($data));

echo $data;

exit(0);

?>
