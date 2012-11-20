// Writing out a demo invoice file. Loads certs from PEM files
// converts them to binary DER form and writes them out to a
// protocol buffer.

// Apple has deprecated OpenSSL in latest MacOS, shut up compiler warnings about it.
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <string>
#include <iostream>
#include <fstream>
#include <assert.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>

#include "invoices.pb.h";

using std::string;

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
    SSL_library_init();
    ERR_load_BIO_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    // Verify that the version of the library that we linked against is
    // compatible with the version of the headers we compiled against.
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    // Load my expired demo cert.
    X509 *my_cert = parse_pem_cert(load_file("pubcert.pem"));
    // Load StartComs intermediate cert. A real tool would let you specify all intermediate
    // certs you need to reach a root CA, or load from a config file or whatever.
    X509 *intermediate_cert = parse_pem_cert(load_file("sub.class1.server.ca.pem"));

    // Build the invoice and add the certs to it.
    Invoice invoice;
    invoice.set_label("Bobs Widget Emporium");
    IdentityData *id_data = invoice.mutable_identity_data();
    id_data->add_cert_chain(x509_to_der(intermediate_cert));
    id_data->add_cert_chain(x509_to_der(my_cert));
    Output *output = invoice.add_outputs();
    output->set_value(1000);  // 1000 satoshis
    output->set_script("this should obviously be binary data");

    // Serialize the invoice in preparation for signing.
    string data_to_sign;
    invoice.SerializeToString(&data_to_sign);

    // Now we want to sign the invoice using the privkey that matches the cert.
    // There are many key formats and some keys can be password protected. We gloss
    // over all of that here and just assume unpassworded PEM.
    BIO *pkey = string_to_bio(load_file("privkey.pem"));
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

    // We got here, so the signature is self-consistent. Put it into the protobuf.
    string sigstr((char*)signature, actual_signature_len);
    id_data->set_signature(sigstr);

    std::fstream outfile("demo.bitcoin-invoice", std::ios::out | std::ios::trunc | std::ios::binary);
    assert(invoice.SerializeToOstream(&outfile));
    printf("File written successfully, see demo.bitcoin-invoice\n");
    printf("You can check it by running invoice-verify\n");

    google::protobuf::ShutdownProtobufLibrary();
}