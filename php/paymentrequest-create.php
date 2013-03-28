#!/usr/bin/env php
<?php

// Command-line utility to create a payment request and
// send it to standard output, to demonstrate how you'd use
// the code in paymentrequest.php / certificates.php in web server
// code
//

$usage = <<<USAGE
Required arguments:
 paytoaddress= : one of your bitcoin addresses (ideally, a unique-per-customer address)
 certificate=  : PEM-encoded file containing certificate
 privatekey=   : PEM file containing private key for certificate

Optional:
 amount= : amount (in BTC) that needs to be paid
 memo= : message to user
 expires= : unix timestamp (integer) when this Request expires
 receipt_url= : URL where a Payment message should be sent
 out= : file to write to (default: standard output)
 single_use= : 1 is single-use, 0 is multi-use 

USAGE;

// Protocol buffer stuff:
require_once 'DrSlump/Protobuf.php';
\DrSlump\Protobuf::autoload();
require_once 'paymentrequest.php';

// Certificate handling stuff:
require_once 'certificates.php';

// Bitcoin address stuff:
require_once 'base58.php';

$details = new \payments\PaymentDetails();
$details->setTime(time());

$paymentRequest = new \payments\PaymentRequest();

$payto = NULL;
$amount = NULL;
$certificate = NULL;
$privatekey = NULL;
$outfile = NULL;

for ($i = 1; $i < $argc; $i++) {
    $keyval = explode("=", $argv[$i]);    
    if (count($keyval) != 2) {
        echo "Unrecognized argument: ".$argv[$i]."\n";
        echo $usage;
        exit(1);
    }
    $key = trim($keyval[0], "-");
    $val = $keyval[1];
    switch ($key) {
    case "paytoaddress":
        $payto = $val;
        break;
    case "certificate":
        $certificate = $val;
        break;
    case "privatekey":
        $privatekey = $val;
        break;
    case "amount":
        $amount = $val;
        break;
    case "memo":
        $details->setMemo($val);
        break;
    case "expires":
        $details->setExpires($val);
        break;
    case "receipt_url":
        $details->setReceiptUrl($val);
        break;
    case "out":
        $outfile = $val;
        break;
    case "single_use":
        $details->setSingleUse($val ? true : false);
        break;
    default:
        echo "Unrecognized argument: ".$argv[$i]."\n";
        echo $usage;
        exit(1);
    }
}

if ($payto === NULL || $certificate === NULL || $privatekey === NULL) {
    echo "You must specify paytoaddress= certificate= and privatekey=\n";
    exit(1);
}

$paymentRequest->setSerializedPaymentDetails($details->serialize());

$certChain = new \payments\X509Certificates();
$leafCert = file_get_contents($certificate);

// http-fetch parent certificates. In a real web application, you should avoid
// constantly re-fetching the certificate chain, and should, instead, fetch it once
// and then store it in your database or in a file on disk and only re-fetch it when
// your certificate expires or one of the intermediate certificates is revoked/replaced.
$certs = fetch_chain($leafCert);
foreach ($certs as $cert) {
    $certChain->addCertificate($cert);
}

//
// Create signature
//
$paymentRequest->setPkiType("x509+sha1");
$paymentRequest->setPkiData($certChain->serialize());

$priv_key = file_get_contents($privatekey);
$pkeyid = openssl_get_privatekey($priv_key);

$paymentRequest->setSignature("");
$dataToSign = $paymentRequest->serialize();

$signature = "";
$result = openssl_sign($dataToSign, $signature, $pkeyid, OPENSSL_ALGO_SHA1);
if ($signature === FALSE) {
    echo "ERROR: signing failed.\n";
    exit(1);
}
$paymentRequest->setSignature($signature);

$data = $paymentRequest->serialize();

//
// Done; output:
//

if ($outfile) {
    file_put_contents($outfile, $data);
}
else {
    echo $data;
}

exit(0);

// A web application serving up a payment request would do something like this:

header('Content-Type: application/x-bitcoin-payment-request');
$filename = "r".(string)time().".bitcoinpaymentrequest"; // ... or any unique filename
header('Content-Disposition: inline; filename='.$filename);
header('Content-Transfer-Encoding: binary');
header('Expires: 0');
header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
header('Content-Length: ' . (string)strlen($data));
echo $data;

exit(0);

?>
