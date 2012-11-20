To compile and run, do something like this:

$ g++ -g -o invoice-create -lssl -lcrypto -I/opt/local/include -L/opt/local/lib -lprotobuf invoice-create.cpp invoices.pb.cc && ./invoice-create
File written successfully, see demo.bitcoin-invoice
You can check it by running invoice-verify

$ g++ -o invoice-verify -lssl -lcrypto -I/opt/local/include -L/opt/local/lib -lprotobuf invoice-verify.cpp invoices.pb.cc && ./invoice-verify 
Invoice is valid! Signed by www.plan99.net
Label: Bobs Widget Emporium

Files:
- ca-bundle-startcom.pem:   A bunch of trusted root authorities provided by StartCom Ltd.
- pubcert.pem:   An expired certificate issued to me for plan99.net
- privkey.pem:   The private key, this originally came appended to pubcert.pem and I split them.
- sub.class1.server.ca.pem:    Intermediate cert for StartCom certificates

The intermediate cert is not an unusual requirement for SSL authorities. You are expected
to provide it to your web server software along with your regular certificate so the chain
can be formed back to the root CA.