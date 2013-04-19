Code implementing a simple payment protocol for Bitcoin (PaymentRequest/etc).

See https://en.bitcoin.it/wiki/BIP_0070

Files here:

paymentrequest.proto : Google protocol buffer definition of messages

Subdirectories here:

c++ : command-line utilities for creating/validating PaymentRequests

php : php code and a demo website for creating/validating PaymentRequests

ca_in_a_box : "certificate authority in a box", used to generate
  certificates and certificate chains for testing.
