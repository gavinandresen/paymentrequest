#!/usr/bin/env bash
#
# Create 8 intermediate certificate authorities, each dependent on the previous
#
# Run create_ca.sh first to generate the root certificate authority.
#

set -x

parent=$(pwd)

for i in {1..8}; do
  mkdir -p intermediate_${i}
  pushd intermediate_${i}
  child=$(pwd)
  sed "s/Test CA/Intermediate CA ${i}/" < ../openssl.cnf > openssl.cnf

  if [ ! -f serial ]; then echo '01' > serial; fi
  touch index.txt
  touch index.txt.attr

  mkdir -p private && chmod go-rw private
  mkdir -p certs

  openssl genpkey -pass pass: -algorithm RSA -out private/cakey.pem -outform PEM
  openssl req -new -batch -subj "/CN=testca${i}.org/O=Payment Request Intermediate ${i}/" -sha1 -key private/cakey.pem -out ${parent}/ca${i}.csr
  popd

  # Get parent to sign:
  pushd ${parent}
  openssl ca -config openssl.cnf -batch -in ca${i}.csr -cert certs/cacert.pem -keyfile private/cakey.pem -notext -out certs/cacert${i}.pem
  cp certs/cacert${i}.pem ${child}/certs/cacert.pem
  popd

  # Create a merchant cert:
  pushd intermediate_${i}
  openssl genpkey -pass pass: -algorithm RSA -out private/demomerchantkey.pem -outform PEM
  openssl req -new -batch -subj "/CN=testmerchant${i}.org/O=Test Merchant ${i}/" -days 3600 -key private/demomerchantkey.pem -out /tmp/demomerchant.csr -outform PEM
  openssl ca -config openssl.cnf -batch -in /tmp/demomerchant.csr -cert certs/cacert.pem -keyfile private/cakey.pem -notext -out certs/demomerchant.pem
  rm /tmp/demomerchant.csr
  popd

  parent=$(pwd)/intermediate_${i}
done

