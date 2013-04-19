<?php
//
// Create-a-payment-request test form.
//
// Requires: 
//  PHP5.3 or later
//  openssl
//  bcmath
//  memcached
//  http://drslump.github.com/Protobuf-PHP/
//

// Protocol buffer stuff:
require_once 'DrSlump/Protobuf.php';
\DrSlump\Protobuf::autoload();
require_once 'include/paymentrequest.php';

// Certificate handling stuff:
require_once 'include/certificates.php';

// Form-handling stuff:
require_once 'include/fillInFormValues.php';
require_once 'include/validateForm.php';
require_once 'include/urls.php';

// Bitcoin address stuff:
require_once 'include/base58.php';

function setField($params, $name, $callable)
{
    if (isset($params[$name]))
        call_user_func($callable, $params[$name]);
}

function mySecret($memcache)
{
    $secret = $memcache->get('secret');
    if ($secret === FALSE) {
        $secret = openssl_random_pseudo_bytes(16);
	$memcache->set('secret', $secret);
    }
    return $secret;
}

function createPaymentRequest($params)
{
    $memcache = new Memcache;
    $memcache->connect('localhost', 11211) or die ("Could not connect to memcache");

    // $params contains:
    // merchant / address123 / amount123 / time / expires / memo
    // payment_url / ACK_message
    $codec = new \DrSlump\Protobuf\Codec\Binary();

    $details = new \payments\PaymentDetails();
    $details->setTime(time() + (int)$params['time']);
    if ($params['expires'] != "never") {
        $details->setExpires(time() + (int)$params['expires']);
    }
    setField($params, 'memo', array($details, 'setMemo'));

    $testnet = false;
    $totalAmount = 0;
    for ($i = 1; $i <= 3; $i++) {
        $field = "address".$i;
        if (!empty($params[$field])) {
            $output = new \payments\Output();
            $r = address_to_script($params["address".$i]);
            $testnet = $r[0];
            $output->setScript($r[1]);
	    $output->setAmount($params["amount".$i]*1.0e8);
	    $totalAmount += $params["amount".$i];

            $details->addOutputs($output);
        }
    }
    if ($testnet) {
        $details->setNetwork("test");
    }
    if (isset($params['payment_url'])) {
        /* Generate a unique id for this request: */
        $id = uniqid(mySecret($memcache));
	/* ... store it in merchant data: */
	$details->setMerchantData($id);

        $ackURL = AbsoluteURL('')."payACK.php";
        $details->setPaymentUrl($ackURL);

        if (isset($params['ACK_message'])) {
	  $memcache->set($id, $params['ACK_message'], 0, 60*60*24);
	}
	else {
	  $memcache->set($id, '', 0, 60*60*24);
	}
    }
    
    $paymentRequest = new \payments\PaymentRequest();
    $serialized = $details->serialize($codec);
    $paymentRequest->setSerializedPaymentDetails($serialized);

    // Signed?
    if ($params['merchant'] != "None") {
        $certK = $params['merchant'] . "certificate";
        $keyK = $params['merchant'] . "key";

	$certChain = new \payments\X509Certificates();
	$cachedCertChain = $memcache->get($certK);
	if ($cachedCertChain === FALSE) {
            $leafCert = file_get_contents("/home/gavin/.certs/".$params['merchant'].".crt");
            $certs = fetch_chain($leafCert);
            foreach ($certs as $cert) {
                $certChain->addCertificate($cert);
            }
	    $cachedCertChain = $certChain->serialize($codec);
	    $memcache->set($certK, $cachedCertChain);
        }
	else {
	    $certChain->parse($cachedCertChain);
        }

        $paymentRequest->setPkiType("x509+sha1");
        $paymentRequest->setPkiData($certChain->serialize($codec));

        $priv_key = file_get_contents("/home/gavin/.certs/".$params['merchant'].".key");
        $pkeyid = openssl_get_privatekey($priv_key);

        $paymentRequest->setSignature("");
        $dataToSign = $paymentRequest->serialize($codec);

        $signature = "";
        $result = openssl_sign($dataToSign, $signature, $pkeyid, OPENSSL_ALGO_SHA1);
        if ($signature === FALSE) return "ERROR: signing failed.\n";
        $paymentRequest->setSignature($signature);

    }

    $data = $paymentRequest->serialize($codec);

    if (isset($params['produce_uri']))
    {
        $urlParams = array();

	if ($totalAmount > 0)
	  $urlParams['amount'] = $totalAmount;

	$hash = hash('ripemd128', $data);
	$memcache->set($hash, $data, FALSE, 60*60*24); /* cache for 24 hours */

	// f.php is fetch payment request from memcache:
	$urlParams['request'] = AbsoluteURL('')."f.php?h=".$hash;

        $url = AddArgsToURL("bitcoin:".$params["address1"], $urlParams);
	
        return MakeAnchor("CLICK TO PAY", $url);
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
}

ob_start();
include "form.html.inc";
$html = ob_get_contents();
ob_end_clean();

$request = (get_magic_quotes_gpc() ? array_map('stripslashes', $_REQUEST) : $_REQUEST);

$validationData['address1'] = array('isRequired', 'type' => 'btcaddress');
$validationData['amount1'] = array('isRequired', 'type' => 'btcamount');
$validationData['address2'] = array('type' => 'btcaddress');
$validationData['amount2'] = array('type' => 'btcamount');
$validationData['address3'] = array('type' => 'btcaddress');
$validationData['amount3'] = array('type' => 'btcamount');

if (isset($request['submit'])) {
    // For debugging Tor connections: replace $CLIENT_IP
    // in memo/ACK_message with client's IP address:
    $request['memo'] = str_replace('$CLIENT_IP', $_SERVER['REMOTE_ADDR'], $request['memo']);
    $request['ACK_message'] = str_replace('$CLIENT_IP', $_SERVER['REMOTE_ADDR'], $request['ACK_message']);

    $formErrors = validateForm($request, $validationData);

    if (count($formErrors) == 0) {
        $info = createPaymentRequest($request);
        $html = preg_replace('/<span class="result">[^<]*/', '<span class="result">'.$info, $html);

        // Normally there would be code here to process the form
        // and redirect to a thank you page...
        // ... but for this example, we just always re-display the form.
//    $info = "No errors; got these values:".
//      nl2br(htmlspecialchars(print_r($request, 1)));
//    $html = preg_replace('/<body>/', "<body><p>$info</p>", $html);
    }
}
else {
    $formErrors = array();
}

echo fillInFormValues($html, $request, $formErrors);

?>
