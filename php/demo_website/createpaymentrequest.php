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

function validate_pubkey($hex)
{
    $d = pack("H*", $hex);
    if (strlen($d) < 33) {
        return false;
    }
    if ($d[0] == "\x04") {
        // Uncompressed pubkey, must be 1+64 bytes:
        if (strlen($d) != 1+64) return false;
        return d;
    }
    else if ($d[0] == "\x02" || $d[0] == "\x03") {
        // Compressed pubkey, must be 1+32 bytes:
        if (strlen($d) != 1+32) return false;
        return $d;
    }
    return false;
}

function pubkeys_to_script($hex)
{
    $keys = explode(",", $hex);

    $script = false;

    switch(count($keys)) {
        case 1:
            $k = validate_pubkey($keys[0]);
            if ($k === false) return false;

            // <push-pubkey-len-bytes><pubkey> OP_CHECKSIG
            $script = chr(strlen($k)) . $k . "\xac"; 
            break;
        case 2:
            $k1 = validate_pubkey($keys[0]);
            $k2 = validate_pubkey($keys[1]);
            if ($k1 === false || $k2 === false) return false;

            // OP_2 <k1> <k2> OP_2 OP_CHECKMULTISIG
            $script = "\x52";
            $script .= chr(strlen($k1)) . $k1;
            $script .= chr(strlen($k2)) . $k2;
            $script .= "\x52";
            $script .= "\xae";
            break;
        case 3:
            $k1 = validate_pubkey($keys[0]);
            $k2 = validate_pubkey($keys[1]);
            $k3 = validate_pubkey($keys[2]);
            if ($k1 === false || $k2 === false || $k3 === false) return false;

            // OP_3 <k1> <k2> <k3> OP_3 OP_CHECKMULTISIG
            $script = "\x53";
            $script .= chr(strlen($k1)) . $k1;
            $script .= chr(strlen($k2)) . $k2;
            $script .= chr(strlen($k3)) . $k3;
            $script .= "\x53";
            $script .= "\xae";
            break;
    }
    return $script;
}

function createPaymentRequest($params, &$formErrors)
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
    $nAddresses = 0;
    for ($i = 1; $i <= 3; $i++) {
        $field = "address".$i;
        if (!empty($params[$field])) {
            $output = new \payments\Output();
            $r = address_to_script($params[$field]);
            if ($r === false) {
                $script = pubkeys_to_script($params[$field]);
                if ($script === false) {
                    $formErrors[$field] = "Invalid address/pubkey";
                    continue;
                }
                $r = array(true, $script);
            }
            $testnet = $r[0];
            $output->setScript($r[1]);
	    $output->setAmount($params["amount".$i]*1.0e8);
	    $totalAmount += $params["amount".$i];
            $nAddresses += 1;

            $details->addOutputs($output);

            // Testnet only, we don't want anybody to be able to create 
            // real-money payment requests
            // from bitcoincore.org/gavinandresen@gmail.com:
            if (!$testnet && $params['merchant'] != "None") {
                $formErrors[$field] = "Testnet-only addresses, please";
                return NULL;
            }
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

    if (isset($params['produce_uri'])) {
        $urlParams = array();

	$hash = hash('ripemd128', $data);
	$memcache->set($hash, $data, FALSE, 60*60*24); /* cache for 24 hours */

	// f.php is fetch payment request from memcache:
	$urlParams['r'] = AbsoluteURL('')."f.php?h=".$hash;

	if ($nAddresses == 1 && $totalAmount > 0) {
	    $urlParams['amount'] = $totalAmount;
        }
        if ($nAddresses == 1) {
            $url = AddArgsToURL("bitcoin:".$params["address1"], $urlParams);
        }
        else {
            $url = AddArgsToURL("bitcoin:", $urlParams);
	}
        return MakeAnchor("CLICK TO PAY", $url);
    }

    header('Content-Type: application/bitcoin-paymentrequest');
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

$validationData['address1'] = array('isRequired', 'type' => 'btcdestination');
$validationData['amount1'] = array('isRequired', 'type' => 'btcamount');
$validationData['address2'] = array('type' => 'btcdestination');
$validationData['amount2'] = array('type' => 'btcamount');
$validationData['address3'] = array('type' => 'btcdestination');
$validationData['amount3'] = array('type' => 'btcamount');

if (isset($request['submit'])) {
    $formErrors = validateForm($request, $validationData);

    if (count($formErrors) == 0) {
        $info = createPaymentRequest($request, $formErrors);
    }
    if (count($formErrors) == 0) {
        $html = preg_replace('/<span class="result">[^<]*/', '<span class="result">'.$info, $html);

        // Normally there would be code here to process the form
        // and redirect to a thank you page...
        // ... but for this example, we just always re-display the form.
    }
}
else {
    $formErrors = array();
}

echo fillInFormValues($html, $request, $formErrors);

?>
