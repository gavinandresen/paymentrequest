Source code for PHP website that generates PaymentRequests and
handles the whole PaymentRequest->Payment->PaymentACK payment
flow.

Requirements:

 Recent version of PHP 5 that includes:
  + memcache
  + openssl
 DrSlump's ProtoBuf support for PHP
  https://github.com/drslump/Protobuf-PHP

What is here:

createpaymentrequest.php : Main page: logic for creating a PaymentRequest
form.html.inc : HTML for createpaymentrequest.php

If a bitcoin: URI is produced, then the r= parameter will point to:
f.php : just serves up a generated PaymentRequest from memcache

If a payment_url is part of the payment request, then it is set to:
payACK.php : receives a Payment message and responds with PayACK

include/
Supporting PHP code.
