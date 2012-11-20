Code implementing a simple payment protocol for Bitcoin (PaymentRequest/etc).

See https://gist.github.com/4120476

Dependencies:
  OpenSSL
  Google Protocol Buffers

To compile:
  make

The Makefile will create a "certificate authority in a box" in ca_in_a_box/ and
compile command-line tools:

paymentrequest-create  # Prototype code: create a SignedPaymentRequest message
paymentrequest-verify  # Prototype code: verify a SignedPaymentRequest message

