<?php
/*
 * Receive a Payment message, return a PaymentACK from memcache
 */

// Protocol buffer stuff:
require_once 'DrSlump/Protobuf.php';
\DrSlump\Protobuf::autoload();
require_once 'include/paymentrequest.php';

$memcache = new Memcache;
if (! $memcache->connect('localhost', 11211)) {
    header("HTTP/1.0 503 Service Unavailable");
    exit(0);
}

$data = file_get_contents("php://input");

$payment = new \payments\Payment();
$payment->parse($data);
$id = $payment->getMerchantData();
$message = $memcache->get($id);

if ($message === FALSE) {
    header("HTTP/1.0 404 Not Found");
    exit(0);
}

// For debugging Tor connections: replace $CLIENT_IP
// in ACK_message with client's IP address:
$message = str_replace('$CLIENT_IP', $_SERVER['REMOTE_ADDR'], $message);

$paymentACK = new \payments\PaymentACK();
$paymentACK->setPayment($payment);
$paymentACK->setMemo($message);

/*
 * NOTE: A real application might submit transactions
 * to a running bitcoind to broadcast them, make sure
 * they were valid payments, etc.
 * For this demo, we just echo back the message.
 */

header('Content-Type: application/x-bitcoinpaymentACK');
$filename = "r".(string)time().".bitcoinpaymentACK";
header('Content-Disposition: inline; filename='.$filename);
header('Content-Transfer-Encoding: binary');
header('Expires: 0');
header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
header('Pragma: public');
header('Content-Length: ' . (string)strlen($data));

$codec = new \DrSlump\Protobuf\Codec\Binary();
echo $paymentACK->serialize($codec);

exit(0);

?>
