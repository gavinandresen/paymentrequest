#!/usr/bin/env bash
#
# Starting with an empty directory containing only certificate-authority-specific
# openssl.cnf, create a root signing certificate and a demo merchant
# certificate.
#
# All the private keys are created non-password-protected, so use this
# ONLY FOR TESTING, NOT FOR PRODUCTION!
#

# openssl uses these to keep track of certificates issued:
if [ ! -f serial ]; then echo '01' > serial; fi
touch index.txt
touch index.txt.attr

mkdir -p private && chmod go-rw private
mkdir -p certs

echo "CA: Creating self-signed root certificate authority (CA) certificate:"
openssl req -config openssl.cnf -x509 -newkey rsa -nodes -days 3650 -out private/cacert.pem -outform PEM
mv private/cacert.pem certs/

echo "MERCHANT: Creating merchant private key and certificate signing request (CSR):"
openssl genpkey -pass pass: -algorithm RSA -out private/demomerchantkey.pem -outform PEM
openssl req -new -batch -subj "/CN=testmerchant.org/O=Payment Request Test Merchant/" -days 3600 -key private/demomerchantkey.pem -out /tmp/demomerchant.csr -outform PEM

echo "CA: Issuing new merchant certificate"
openssl ca -config openssl.cnf -batch -in /tmp/demomerchant.csr -cert certs/cacert.pem -keyfile private/cakey.pem -notext -out certs/demomerchant.pem
rm /tmp/demomerchant.csr

echo "Done."
echo " Root CA certificate is certs/cacert.pem"
echo " Merchant certificate is certs/demomerchant.pem , private (signing) key is private/demomerchantkey.pem"

#
# At the end of all of this, the following useful stuff is created:
#
# Certificate Authority private key (private/cacert.pem)
# Certificate Authority certificate (certs/cacert.pem); use this as a testing root certificate
#   openssl x509 -in certs/cacert.pem -text -noout  # To see cert details
#
# Merchant private key (private/demomerchantkey.pem)
# Merchant certificate
#   openssl x509 -in certs/demomerchant.pem -text -noout  # To see cert details

#
# To clean up everything and start over:
# rm -rf index.txt* serial private/ certs/ /tmp/*.csr
#
