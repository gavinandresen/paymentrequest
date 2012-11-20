// Writing out a demo invoice file. Loads certs from PEM files
// converts them to binary DER form and writes them out to a
// protocol buffer.

// Apple has deprecated OpenSSL in latest MacOS, shut up compiler warnings about it.
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <assert.h>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <time.h>
#include <utility>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>

#include "paymentrequest.pb.h";
#include "util.h"

using std::string;
using std::map;

// Returns the files contents as a byte array.
string load_file(const char *path) {
    string result;
    std::ifstream cert_file(path);
    result.assign(std::istreambuf_iterator<char>(cert_file),  std::istreambuf_iterator<char>());    
    return result;
}

// Must be freed with BIO_free.
BIO *string_to_bio(const string &str) {
    return BIO_new_mem_buf((void*)str.data(), str.size());
}

// Take textual PEM data (concatenated base64 encoded x509 data with separator markers)
// and return an X509 object suitable for verification or use.
X509 *parse_pem_cert(string cert_data) {
    // Parse it into an X509 structure.
    BIO *bio = string_to_bio(cert_data);
    X509 *cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    assert(cert);
    BIO_free(bio);  
    return cert;
}

string x509_to_der(X509 *cert) {
    unsigned char *buf = NULL;
    int buflen = i2d_X509(cert, &buf);
    string data((char*)buf, buflen);
    return data;
}

int main(int argc, char **argv) {
    std::list<string> expected = split("paytoaddress,amount,certificates,privatekey,memo,"
                                       "expires,receipt_url,single_use,out", ",");

    map<string,string> params;
    if (!parse_command_line(argc, argv, expected, params)) {
        usage(expected);
        exit(1);
    }

    // BTC to satoshis:
    ::google::protobuf::uint64 amount; 
    amount = static_cast< ::google::protobuf::uint64 >(1.0e8 * atof(params["amount"].c_str()));

    SSL_library_init();
    ERR_load_BIO_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    // Verify that the version of the library that we linked against is
    // compatible with the version of the headers we compiled against.
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    // Load demo merchant certificate:
    X509 *my_cert = parse_pem_cert(load_file("ca_in_a_box/certs/demomerchant.pem"));

    // Load StartComs intermediate cert. A real tool would let you specify all intermediate
    // certs you need to reach a root CA, or load from a config file or whatever.
    // X509 *intermediate_cert = parse_pem_cert(load_file("sub.class1.server.ca.pem"));

    // PaymentRequest:
    PaymentRequest paymentRequest;
    paymentRequest.set_memo(params["memo"]);
    paymentRequest.set_time(time(0));
    paymentRequest.set_expires(time(0)+60*60*24);
    paymentRequest.set_single_use(true);

    // Output to Bitcoin Foundation donation address, using standard pay-to-pubkey-hash script:
    // Foundation address is 1BTCorgHwCg6u2YSAWKgS17qUad6kHmtQW which is
    // pay-to-public-key-whos-hash-is 72a5edf78b64c21e6ca2436f113c6426547b1491
    // TODO: include a BTCAddressToScript() routine?
    // BEWARE! Test your code on the test-network, and make sure you can redeem your
    // outputs; it is easy to lose bitcoins by creating un-spendable outputs.
    Output* out = paymentRequest.add_outputs();
    if (amount > 0) out->set_amount(amount);
    out->set_script("\x76\xa9" // DUP HASH160
                    "\x14" // Push 20-byte (160-bit) hash
                    "\x72\xa5\xed\xf7\x8b\x64\xc2\x1e\x6c\xa2\x43\x6f\x11\x3c\x64\x26\x54\x7b\x14\x91"
                    "\x88\xac"); // EQUALVERIFY CHECKSIG

    // SignedPaymentRequest:
    SignedPaymentRequest signedPaymentRequest;
    string paymentRequestBytes;
    paymentRequest.SerializeToString(&paymentRequestBytes);
    signedPaymentRequest.set_serialized_payment_request(paymentRequestBytes);

    // Certificate chain:
    X509Certificates certChain;
    certChain.add_certificate(x509_to_der(my_cert));
//    certChain.add_certificate(x509_to_der(intermediate_cert));
    string certChainBytes;
    certChain.SerializeToString(&certChainBytes);
    signedPaymentRequest.set_pki_data(certChainBytes);

    // Serialize the signedpaymentRequest in preparation for signing.
    signedPaymentRequest.set_signature(string(""));
    string data_to_sign;
    signedPaymentRequest.SerializeToString(&data_to_sign);

    // Now we want to sign the paymentRequest using the privkey that matches the cert.
    // There are many key formats and some keys can be password protected. We gloss
    // over all of that here and just assume unpassworded PEM.
    BIO *pkey = string_to_bio(load_file("ca_in_a_box/private/demomerchantkey.pem"));
    EVP_PKEY *privkey = PEM_read_bio_PrivateKey(pkey, NULL, NULL, NULL);
    assert(privkey);

    EVP_MD_CTX ctx;
    EVP_MD_CTX_init(&ctx);
    assert(EVP_SignInit_ex(&ctx, EVP_sha256(), NULL));
    assert(EVP_SignUpdate(&ctx, data_to_sign.data(), data_to_sign.size()));
    unsigned char *signature = new unsigned char[EVP_PKEY_size(privkey)];
    unsigned int actual_signature_len;
    assert(EVP_SignFinal(&ctx, signature, &actual_signature_len, privkey));

    // Now we have our signature, let's check it actually verifies.
    EVP_PKEY *pubkey = X509_get_pubkey(my_cert);
    EVP_MD_CTX_init(&ctx);
    assert(EVP_VerifyInit_ex(&ctx, EVP_sha256(), NULL));
    assert(EVP_VerifyUpdate(&ctx, data_to_sign.data(), data_to_sign.size()));
    assert(EVP_VerifyFinal(&ctx, signature, actual_signature_len, pubkey));

    // We got here, so the signature is self-consistent.
    signedPaymentRequest.set_signature(signature, actual_signature_len);

    std::fstream outfile("demo.bitcoin-paymentrequest", std::ios::out | std::ios::trunc | std::ios::binary);
    assert(signedPaymentRequest.SerializeToOstream(&outfile));
    printf("File written successfully, see demo.bitcoin-paymentrequest\n");
    printf("You can check it by running paymentrequest-verify\n");

    delete[] signature;

    google::protobuf::ShutdownProtobufLibrary();
}
