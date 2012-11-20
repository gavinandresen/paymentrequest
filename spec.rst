Bitcoin Payment Messages
========================

This document proposes protocol buffer-based formats for a simple payment protocol between a customer's bitcoin client software and a merchant.

Separate documents will propose an extension to the Bitcoin URI syntax and new MIME types to support them.

Motivation
==========

The idea of a "payment protocol" to improve on Bitcoin addresses has been around for over a year. Users have been asking for some features in this proposal (like the ability to provide a refund address so overpayments or refunds can be returned to customers without the need to ask them for their address) for two or three years, and have started to work around shortcomings in the Bitcoin payment process with creative (but inefficient) uses of transactions.

The key features of this proposal are:

+ Requests for payment (SignedPaymentRequests) are tied to authenticated identities using the only widely-deployed identity authentication system we have right now (X.509 certificates signed by root certificate authorities)
+ PaymentRequests include a user-friendly description of what the payment is for
+ Payments include information on where refunds should be sent
+ At the end of the payment process, the customer has a SignedPaymentRequest and bitcoin transaction that can be used as proof-of-payment if there is any dispute with the merchant.


Specification
=============

PaymentRequest/SignedPaymentRequest
---------------------

An Output specifies where payment (or part of a payment) should be sent:

::

    message Output {
	optional uint64 amount = 1 [default = 0];
        required bytes script = 2;
    }

amount: Number of satoshis (0.00000001 BTC) to be paid.

script: a "TxOut" script where payment should be sent. This will normally be one of the standard Bitcoin transaction scripts (e.g. pubkey OP_CHECKSIG).

A PaymentRequest is a request for payment from a merchant to a customer:

::

    message PaymentRequest {
        optional string network = 1 [default = "main"];
        repeated Output outputs = 2;
        required uint64 time = 3;
        optional uint64 expires = 4;
        optional bool single_use = 5 [default = true];
        optional string memo = 6;
        optional string receipt_url = 7;
        optional bytes merchant_data = 8;
    }        

network: either "main" for payments on the production Bitcoin network, or "test" for payments on test network. If a client receives a PaymentRequest for a network it does not support it must reject the request.

outputs: one or more outputs where Bitcoins are to be sent. If the sum of outputs.amount is zero, the customer will be asked how much to pay, and the bitcoin client may choose any or all of the Outputs (if there are more than one) for payment. If the sum of outputs.amount is non-zero, then the customer will be asked to pay the sum, and the payment shall be split among the Outputs with non-zero amounts (if there are more than one; Outputs with zero amounts shall be ignored). 

time: Unix timestamp (seconds since 1-Jan-1970) when the PaymentRequest was created.

expires: Unix timestamp after which the PaymentRequest should be considered invalid.

single_use: If true, this PaymentRequest should be used for only one payment. If false, it may be added to the user's address book and used repeatedly until it expires (e.g. for donations or a recurring payment).

memo: UTF-8 encoded, plain-text (no formatting) note that should be displayed to the customer, explaining what this PaymentRequest is for.

receipt_url: Secure (usually https) location where a Payment message (see below) may be sent to obtain a PaymentACK.

merchant_data : Arbitrary data that may be used by the merchant to identify the PaymentRequest. May be omitted if the merchant does not need to associate Payments with PaymentRequest or if they associate each PaymentRequest with a separate payment address.

When a Bitcoin client receives a (unsigned) PaymentRequest, it must authorize payment by doing the following:

1. Validate that the time on the customer's system is before PaymentRequest.expires
2. Display the proposed Outputs in as human-friendly a form as possible and ask the customer to approve payment.

**TODO**: develop best practices for warning the customer of the dangers of accepting unsigned PaymentRequests:  potential man-in-the-middle attacks if the request came over an insecure connection, and possibility that their trading partner will repudiate that they generated the request.

A SignedPaymentRequest is a PaymentRequest cryptographically tied to a merchant's identity:

::

    message SignedPaymentRequest {
        required bytes pki_data = 1;
        optional string pki_type = 2 [default = "x509"];
        required bytes serialized_payment_request = 3;
        optional uint32 paymentrequest_version = 4 [default = 1];
        required bytes signature = 5;
    }

pki_data: PKI-system data that identifies the merchant and can be used to create a digital signature. In the case of X.509 certificates, pki_data one or more X.509 certificates (see Certificates section below).

pki_type : public-key infrastructure (PKI) system being used to identify the merchant. X.509 certificates are the default that all implementations should support.

serialized_payment_request: A protocol-buffer serialized PaymentRequest message.

paymentrequest_version: in case there are multiple versions of PaymentRequest messages in the future, specify what version is encoded in serialized_payment_request. Clients must reject SignedPaymentRequest if given an paymentrequest_version that they do not understand.

signature: digital signature over a protocol buffer serialized variation of the SignedPaymentRequest message where signature is a zero-byte array and fields are serialized in numerical order (all current protocol buffer implementations serialize fields in numerical order), using the public key in pki_data.

When a Bitcoin client receives a SignedPaymentRequest, it must authorize payment by doing the following:

1. Validate the merchant's identity and signature using the PKI system (e.g. validate the X.509 certificates in pki_data up to a list of root certificate authorities, extract the public key from the first certificate, and validate the signature).
2. Validate that the time on the customer's system is before PaymentRequest.expires
3. Display the merchant's identity and ask the customer if they would like to submit payment (e.g. display the "Common Name" in the first X.509 certificate).

Payment
-------

::

    message Payment {
        optional bytes merchant_data = 1;
        repeated bytes transactions = 2;
        repeated Output refund_to = 3;
        optional string memo = 4;
    }

merchant_data : copied from PaymentRequest.merchant_data. Merchants may use invoice numbers or any other data they require to match Payments to PaymentRequests.

transactions : One or more valid, signed Bitcoin transactions that fully pay the PaymentRequest

refund_to : One or more outputs where the merchant may return funds, if necessary.

memo : UTF-8 encoded, plain-text note from the customer to the merchant.

If the customer authorizes payment, then the Bitcoin client:

1. Creates and signs a transaction with one output sending the PaymentRequest.script
2. If there is no PaymentRequest.receipt_url, then the transaction should be broadcast on the Bitcoin p2p network.
3. Else send (POST if http/https) a Payment message to PaymentRequest.receipt_url and expect a PaymentACK in response.

Clients may handle errors communicating with the receipt_url server however they like, but should assume that if they cannot communicate at all with the server then the Payment should either be retried later or immediately rejected.

PaymentRequest.receipt_url must be secure against man-in-the-middle attacks that might alter Payment.refund_to (if using HTTP, it must be TLS-protected).

A merchant receiving a Payment will determine whether or not the transactions satisfy conditions of payment, and, if and only if they do, broadcast the transactions on the Bitcoin p2p network. It must return a PaymentACK message to let the customer know whether payment was accepted or rejected.

PaymentACK
---------------------

::

    message PaymentACK {
        required Payment payment = 1;
        required bool accepted = 2;
        optional string memo = 3;
    }

accepted : true if the Payment is accepted and will be broadcast on the Bitcoin p2p network.

memo : UTF-8 encoded note that should be displayed to the customer indicating that the transaction is complete.

::

Upon receiving a PaymentACK, a Bitcoin client should display the PaymentACK.memo to the customer.

The Bitcoin client must be prepared to handle the case of an evil merchant that returns accepted=false but broadcasts the transactions anyway.

Once broadcast on the Bitcon p2p network, payments are like any other Bitcoin transaction and may be confirmed or not.

Certificates
============

The default PKI system is X.509 certificates (the same system used to authenticate web servers). The format of pki_data when pki_type is "x509" is a protocol-buffer-encoded certificate chain [RFC5280]:

::

    message X509Certificates {
        repeated bytes certificate = 1;
    }

Each certificate is a DER [ITU.X690.1994] PKIX certificate value. The certificate containing the public key of the entity that digitally signed the PaymentRequest MUST be the first certificate. This MAY be followed by additional certificates, with each subsequent certificate being the one used to certify the previous one. The recipient MUST verify the certificate chain according to [RFC5280] and reject the PaymentRequest if any validation failure occurs.

*Issue:* What should we say about root certificates and certificate management in general? Any requirements, or leave it up to each Bitcoin client to determine which root CA's are trustworthy, as happens with web browsers? Gavin suggests trusting only (say) ten of the Extended Validation authorities: http://en.wikipedia.org/wiki/Extended_Validation_Certificate#Extended_Validation_certificate_identification

*Issue:* X.509 is widely criticised for doing too much. However, it is the PKI system we're stuck with. Do web browsers / certificate authorities support the full X.509 spec, or only a subset? Should Bitcoin clients only support some well-defined subset of X.509 ? More research needed here... 

*Issue:* Specify a maximum certificate chain length, to avoid DoS or other potential attacks? What is the maximum chain length that reputable certificate issuing authorities use?

Extensions
==========

Implementations that need to extend these messages shall use tags starting at 1000, and shall update the wiki page at **TODO** to avoid conflicts with other extensions.

Use Cases
=========

Merchant Payment Service
------------------------

A merchant payment service (like Paysius or bit-pay.com) would use PaymentRequests and PaymentACKs as follows:

1. Merchant pays for a certificate from a certificate authority, and then gives the payment service the certificate and their private key. This could be the same certificate and private key as is used for the merchant's web site, but best security practice would be to purchase a separate certificate for authenticating PaymentRequests. Very successful merchant payment services might act as intermediate certificate authorities, issuing certificates for their merchants.
2. Customer goes through the checkout process on either the merchant's or payment service's web site.
3. At the end of the checkout process, a SignedPaymentRequest is generated and sent to the customer's Bitcoin client.
4. Customer's Bitcoin client displays the PaymentRequest, showing that the payment is for the merchant.
5. On customer approval, a Payment is sent to the payment service's paymentURI. The merchant is notified of the payment, and the customer receives a PaymentACK.
6. The payment service broadcasts the Payment.transactions, and the customer's Bitcoin client show the transaction as it is confirmed. The merchant ships product to the customer when the transaction has N confirmations.

Immediate-feedback Transactions
-------------------------------

SatoshiDice (www.satoshidice.com) and similar very popular games use tiny transactions for customer/service communication. In particular, customers can add an extra output to their transactions to indicate where winnings should be sent. And they create tiny transactions as a way of telling customers that their bet was received, but lost.

Assuming Bitcoin clients upgrade to support this proposal, a bet on SatoshiDice would proceed as follows:

1. Customer clicks on a link on SatoshiDice.com and their Bitcoin client receives a SignedPaymentRequest.
2. Customer authorizes payment, and their Bitcoin client creates a Payment message and submits it directly to https://satoshidice.com/something
3. The SatoshiDice web server checks to make sure the transaction is valid, broadcasts it, and determines whether the customer wins or loses. It returns a PaymentACK with either a "You win" or "You lost" memo.
4. If the customer won, it broadcasts a transaction to pay them using Payment.refund_to
5. Customer's Bitcoin client displays the win/lose memo, and if they won the winnings appear in their wallet when received over the p2p network.

Using a Payment message to specify where winning should be sent instead of an extra send-to-self output makes the customer-to-merchant transactions about 30% smaller on average.  And using a PaymentACK message to let the customer know that they did not win avoids a blockchain transaction entirely.

Multiperson Wallet
------------------

This use case starts with a multi-signature Bitcoin address or wallet, with keys held by two different people (Alice and Bob). Payments from that address/wallet must be authorized by both Alice and Bob, and both are running multi-signature-capable Bitcoin clients.

Alice begins the payment process by getting a SignedPaymentRequest from a merchant that needs to be paid. She authorizes payment and her Bitcoin client creates a Payment message with a partially-signed transaction, which is then sent to Bob any way that is convenient (email attachment, smoke signals...).

Bob's Bitcoin client validates the SignedPaymentRequest and asks Bob to authorize the transaction. He says OK, his Bitcoin client completes the transaction by providing his signature, submits the payment to the merchant, and then sends a message to Alice with the PaymentACK he received from the merchant, completing the payment process.


Design Notes
============

Why X.509 Certificates?
-----------------------

This proposal uses X.509 certificates as the identity system for merchants because most of them will have already purchased a certificate to secure their website and will be familiar with the process of proving their identity to a certificate issuing authority.

Implementing a better global PKI infrastructure is outside the scope of this proposal. If a better PKI infrastructure is adopted, the only change to this proposal would be to add a new pki_type and new formats for pki_data and signature with whatever that better infrastructure uses to identify entities.


Why not JSON?
-------------

PaymentRequest, Payment and PaymentACK messages could all be JSON-encoded. The Javascript Object Signing and Encryption (JOSE) working group at the IETF has a draft specification for signing JSON data that we could adopt and use.

But the spec is non-trivial. Signing JSON data is troublesome, so JSON that needs to be signed must be base64-encoded into a string. And the standards committee identified one security-related issue that will require special JSON parsers for handling JSON-Web-Signed (JWS) data (duplicate keys must be rejected by the parser, which is more strict than the JSON spec requires). It is very likely some implementors would just use whatever JSON library was most convenient, either because they weren't aware of the potential problem or because they were lazy and couldn't see how an attacker might take advantage of the problem.


Why not an existing electronic invoice standard?
------------------------------------------------

There are several existing standards for electronic invoices (EDIFACT, OAGIS, UBL, ISDOC). They are all over-designed for Bitcoin's purposes.

However, it would be trivial to extend the PaymentRequest message to include more extensive invoice details encoded as specified by one of those standards (e.g. add a ubl_invoice string that is an XML-encoded UBL invoice).

What about a merchant-pays-fee feature?
---------------------------------------

It is desireable to allow a merchant to pay the cost of any Bitcoin network transaction processing fees, so if a customer is paying for a 1 BTC item they pay exactly 1 BTC.

The consensus is to change the transaction selection code used by Bitcoin miners so that dependent transactions are considered as a group. Merchants or payment services with one or more unconfirmed zero-fee transaction from customers will periodically create a pay-to-self transaction with a large enough fee to get the transactions into a block.

Checking for revoked certificates
---------------------------------

The Online Certificate Checking Protocol (OCSP) is supposed to be a quick and easy way for applications to check for revoked certificates.

In practice, it doesn't work very well. Certificate Authorities have no financial incentive to support a robust infrastructure that can handle millions of OCSP validation requests quickly.

Ideally, Bitcoin clients would use OCSP to check certificate statuses every time they received or re-used a PaymentRequest. But if that results in long pauses or lots of false-positive rejections (because an OCSP endpoint is offline or overwhelmed, perhaps) then merchants and customers might revert to just using "never fails" Bitcoin addresses.

Test Vectors
============

TODO: give base64-encoded data for PaymentRequest, SignedPaymentRequest, root certificate(s), etc.


References
==========

Public-Key Infrastructure (X.509) working group : http://datatracker.ietf.org/wg/pkix/charter/

RFC 2560, X.509 Internet Public Key Infrastructure Online Certificate Status Protocol - OCSP : http://tools.ietf.org/html/rfc2560

Protocol Buffers : https://developers.google.com/protocol-buffers/

See Also
========

Javascript Object Signing and Encryption working group : http://datatracker.ietf.org/wg/jose/

Wikipedia's page on Invoices: http://en.wikipedia.org/wiki/Invoice  especially the list of Electronic Invoice standards

sipa's payment protocol proposal: https://gist.github.com/1237788

ThomasV's "Signed Aliases" proposal : http://ecdsa.org/bitcoin_URIs.html
