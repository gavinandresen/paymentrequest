// Writing out a demo invoice file. Loads certs from PEM files
// converts them to binary DER form and writes them out to a
// protocol buffer.

// Apple has deprecated OpenSSL in latest MacOS, shut up compiler warnings about it.
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <algorithm>
#include <assert.h>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <time.h>
#include <utility>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
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

static const char base58_chars[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

//
// Decode a "base58check" address into its parts: one-byte version, 20-byte hash, 4-byte checksum.
//
bool decode_base58(const string& btcaddress, unsigned char& version, string& hash, string& checksum)
{
    unsigned char decoded[25];

    size_t nBytes = 0;
    BIGNUM bn58, bn, bnChar;
    BN_CTX *ctx;

    ctx = BN_CTX_new();
    BN_init(&bn58);
    BN_init(&bn);
    BN_init(&bnChar);

    BN_set_word(&bn58, 58);
    BN_set_word(&bn, 0);

    for (unsigned int i = 0; i < btcaddress.length(); i++) {
        const char *p1 = strchr(base58_chars, btcaddress[i]);
        if (!p1) {
            goto out;
        }

        BN_set_word(&bnChar, p1 - base58_chars);

        if (!BN_mul(&bn, &bn, &bn58, ctx))
            goto out;

        if (!BN_add(&bn, &bn, &bnChar))
            goto out;
    }

    nBytes = BN_num_bytes(&bn);
    if (nBytes == 0 || nBytes > 25)
        return false;

    std::fill(decoded, decoded+25, (unsigned char)0);
    BN_bn2bin(&bn, &decoded[25-nBytes]);

out:
    BN_clear_free(&bn58);
    BN_clear_free(&bn);
    BN_clear_free(&bnChar);
    BN_CTX_free(ctx);

    version = decoded[0];
    hash.clear(); hash.resize(20);
    std::copy(decoded+1, decoded+21, hash.begin());
    checksum.clear(); checksum.resize(4);
    std::copy(decoded+21, decoded+25, checksum.begin());

    // Make sure checksum is correct: (first four bytes of double-sha256)
    unsigned char h1[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_1;
    SHA256_Init(&sha256_1);
    SHA256_Update(&sha256_1, &decoded[0], 21);
    SHA256_Final(h1, &sha256_1);
    unsigned char h2[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256_2;
    SHA256_Init(&sha256_2);
    SHA256_Update(&sha256_2, &h1[0], SHA256_DIGEST_LENGTH);
    SHA256_Final(h2, &sha256_2);
    string ck(&h2[0], &h2[4]);
    if (checksum != ck) {
        return false;
    }
    return true;
}

//
// Convert Address into a Script
//
bool address_to_script(const std::string& btcaddress, string& script, bool& fTestNet)
{
    unsigned char version;
    string hash, checksum;
    if (!decode_base58(btcaddress, version, hash, checksum)) return false;

    fTestNet = false;
    script.clear();
    switch (version) {
    case 111:
        fTestNet = true; // Fall through to set script
    case 0:
        script.append(
            "\x76\xa9" // DUP HASH160
            "\x14" // Push 20-byte (160-bit) hash
            );
        script.append(hash);
        script.append("\x88\xac"); // EQUALVERIFY CHECKSIG
        break;

    case 196:
        fTestNet = true; // Fall through to set script
    case 5:
        script.append(
            "\xa9" // HASH160
            "\x14" // Push 20-byte (160-bit) hash
            );
        script.append(hash);
        script.append("\x87"); // EQUAL
        break;

    default:
        return false;
    }

    return true;
}

int main(int argc, char **argv) {
    std::list<string> expected = split("paytoaddress,amount,certificates,privatekey,memo,"
                                       "expires,receipt_url,single_use,out", ",");

    map<string,string> params;
    if (!parse_command_line(argc, argv, expected, params)) {
        usage(expected);
        exit(1);
    }
    if (params.count("paytoaddress") == 0) {
        std::cerr << "You must specify paytoaddress=<address>\n";
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

    Output* out = paymentRequest.add_outputs();
    if (amount > 0) out->set_amount(amount);
    string script;
    bool fTestNet = false;
    if (!address_to_script(params["paytoaddress"], script, fTestNet)) {
        std::cerr << "Invalid bitcoin address: " << params["paytoaddress"] << "\n";
        exit(1);
    }
    out->set_script(script);
    if (fTestNet)
        paymentRequest.set_network("testnet3");

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

    if (params.count("out")) {
        std::fstream outfile(params["out"].c_str(), std::ios::out | std::ios::trunc | std::ios::binary);
        assert(signedPaymentRequest.SerializeToOstream(&outfile));
    }
    else {
        assert(signedPaymentRequest.SerializeToOstream(&std::cout));
    }

    delete[] signature;

    google::protobuf::ShutdownProtobufLibrary();
}
