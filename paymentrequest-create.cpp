//
// Create a PaymentRequest object, given:
// REQUIRED:
//  paytoaddress= : one of your bitcoin addresses (ideally, a unique-per-customer address)
//  certificates= : one or more .pem files containing certificate chain signed by trusted root CA
//  privatekey= : .pem file containing private key for first certificate in certificates
//
// OPTIONAL:
//  amount= : amount (in BTC) that needs to be paid
//  memo= : message to user
//  expires= : unix timestamp (integer) when this Request expires
//  receipt_url= : URL where a Payment message should be sent
//  out= : file to write to (default: standard output)
//  single_use : if specified, this will be a single-use Request
//

// Apple has deprecated OpenSSL in latest MacOS, shut up compiler warnings about it.
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#include <algorithm>
#include <assert.h>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <time.h>
#include <utility>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/evp.h>

#include "paymentrequest.pb.h";
#include <google/protobuf/io/tokenizer.h>  // For string-to-uint64 conversion
#include "util.h"

using std::string;
using std::map;

using namespace payments;

// Returns the files contents as a byte array.
string load_file(string path) {
    string result;
    std::ifstream cert_file(path.c_str());
    result.assign(std::istreambuf_iterator<char>(cert_file),  std::istreambuf_iterator<char>());    
    return result;
}

// Result must be freed with BIO_free.
BIO *string_to_bio(const string &str) {
    return BIO_new_mem_buf((void*)str.data(), str.size());
}

// Take textual PEM data (concatenated base64 encoded x509 data with separator markers)
// and return an X509 object suitable for verification or use.
// Result must be freed with X509_free()
X509 *parse_pem_cert(string cert_data) {
    // Parse it into an X509 structure.
    BIO *bio = string_to_bio(cert_data);
    X509 *cert = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    BIO_free(bio);
    return cert;
}
X509 *parse_der_cert(string cert_data) {
    BIO *bio = string_to_bio(cert_data);
    X509 *cert = d2i_X509_bio(bio, NULL);
    BIO_free(bio);
    return cert;
}

string x509_to_der(X509 *cert) {
    unsigned char *buf = NULL;
    int buflen = i2d_X509(cert, &buf);
    string data((char*)buf, buflen);
    OPENSSL_free(buf);
    return data;
}

X509* fetchCert(const char* uri)
{
    // TODO: use libcurl or something nicer instead of shelling
    // out to curl

    std::string command("curl -m 60 --silent ");
    command.append(uri);
    FILE* fp = popen(command.c_str(), "r");
    if (!fp)
    {
        fprintf(stderr, "Error opening %s\n", command.c_str());
        return NULL;
    }
    string data;
    char buf[1024];
    size_t n;
    do
    {
        n = fread(buf, 1, 1024, fp);
        data.append(buf, n);
    } while(n > 0);
    pclose(fp);

    if (data.empty())
    {
        fprintf(stderr, "Error reading %s\n", uri);
        return NULL;
    }

    // If I was doing this right I'd look at the Content-Type
    // http header... but the chances a DER-encoded certificate
    // happens to contain the PEM header is pretty darn small, so
    // this should work.
    if (data.find("-----BEGIN CERTIFICATE-----") != string::npos)
        return parse_pem_cert(data);

    return parse_der_cert(data);
}

bool isRootCert(X509* cert)
{
    X509_NAME* issuer = X509_get_issuer_name(cert);
    X509_NAME* subject = X509_get_subject_name(cert);
    if (X509_NAME_cmp(issuer, subject) == 0)
        return true;
    return false;
}

void fetchParentCerts(X509Certificates& certChain, X509* cert)
{
    // If cert is self-signed, then it is a root certificate
    // and there's nothing to do
    if (isRootCert(cert)) return;

    // The Authority Info Access extension can contain
    // info about where to fetch parent/root certs.
    AUTHORITY_INFO_ACCESS* ads = (AUTHORITY_INFO_ACCESS*)X509_get_ext_d2i(cert, NID_info_access, 0, 0);
    for (int i = 0; i < sk_ACCESS_DESCRIPTION_num(ads); i++)
    {
        ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(ads, i);
        if (OBJ_obj2nid(ad->method) == NID_ad_ca_issuers && ad->location->type == GEN_URI)
        {
            char* uri = (char*)ASN1_STRING_data(ad->location->d.uniformResourceIdentifier);

            X509* parent = fetchCert(uri);
            if (parent && !isRootCert(parent))
            {
                // Successful: add to end of certChain, then recurse
                // fprintf(stderr, "Adding %s to end of chain\n", uri);

                certChain.add_certificate(x509_to_der(parent));

                fetchParentCerts(certChain, parent);

                X509_free(parent);
                break;
            }
            //else fprintf(stderr, "Skipped %s\n", uri);
        }
    }
}

static const char base58_chars[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

//
// Decode a "base58check" address into its parts: one-byte version, 20-byte hash, 4-byte checksum.
// Based on code from Jeff Garzik's picocoin project.
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

        assert(BN_mul(&bn, &bn, &bn58, ctx));
        assert(BN_add(&bn, &bn, &bnChar));
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

google::protobuf::uint64 BTC_to_satoshis(double btc)
{
    return static_cast< google::protobuf::uint64 >(1.0e8 * btc + 0.5);
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
    if (params.count("certificates") == 0) { // Default to ca_in_a_box test merchant:
        params["certificates"] = "ca_in_a_box/certs/demomerchant.pem";
        if (params.count("privatekey") == 0)
            params["privatekey"] = "ca_in_a_box/private/demomerchantkey.pem";
    }
    if (params.count("privatekey") == 0) {
        std::cerr << "You must specify privatekey=path/to/privatekey.pem\n";
        usage(expected);
        exit(1);
    }

    SSL_library_init();
    ERR_load_BIO_strings();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    // Verify that the version of the library that we linked against is
    // compatible with the version of the headers we compiled against.
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    // PaymentDetails:
    PaymentDetails details;
    details.set_memo(params["memo"]);
    details.set_time(time(0));
    if (params.count("expires") > 0) {
        google::protobuf::uint64 expires;
        if (google::protobuf::io::Tokenizer::ParseInteger(params["expires"], -1, &expires)) 
            details.set_expires(expires);
        else
            std::cerr << "Invalid expires, ignoring: " << params["expires"] << "\n";
    }
    if (params.count("single_use"))
        details.set_single_use(true);
    if (params.count("receipt_url"))
        details.set_receipt_url(params["receipt_url"]);

    Output* out = details.add_outputs();
    if (params.count("amount") > 0)
        out->set_amount(BTC_to_satoshis(atof(params["amount"].c_str())));
    string script;
    bool fTestNet = false;
    if (!address_to_script(params["paytoaddress"], script, fTestNet)) {
        std::cerr << "Invalid bitcoin address: " << params["paytoaddress"] << "\n";
        exit(1);
    }
    out->set_script(script);
    if (fTestNet)
        details.set_network("testnet3");

    // PaymentRequest:
    PaymentRequest request;
    string detailsBytes;
    details.SerializeToString(&detailsBytes);
    request.set_serialized_payment_details(detailsBytes);

    // Certificate chain:
    X509Certificates certChain;
    X509 *first_cert = NULL;
    X509 *last_cert = NULL;
    EVP_PKEY *pubkey = NULL;
    std::list<string> certFiles = split(params["certificates"], ",");
    for (std::list<string>::iterator it = certFiles.begin(); it != certFiles.end(); it++) {
        X509 *cert = parse_pem_cert(load_file(*it));
        certChain.add_certificate(x509_to_der(cert));
        if (first_cert == NULL) {
            first_cert = cert; // Don't free this yet, need pubkey to stay valid
            pubkey = X509_get_pubkey(cert);
        }
        else {
            X509_free(cert);
        }
        last_cert = cert;
    }

    // Fetch any missing intermediate certificates, if we can:
    fetchParentCerts(certChain, last_cert);

    string certChainBytes;
    certChain.SerializeToString(&certChainBytes);
    request.set_pki_type("x509");
    request.set_pki_data(certChainBytes);

    // Serialize the PaymentRequest in preparation for signing.
    request.set_signature(string(""));
    string data_to_sign;
    request.SerializeToString(&data_to_sign);

    // Now we want to sign the paymentRequest using the privkey that matches the cert.
    // There are many key formats and some keys can be password protected. We gloss
    // over all of that here and just assume unpassworded PEM.
    string pkey_string = load_file(params["privatekey"]);
    BIO *pkey = string_to_bio(pkey_string);
    EVP_PKEY *privkey = PEM_read_bio_PrivateKey(pkey, NULL, NULL, NULL);
    BIO_free(pkey);
    assert(privkey);

    EVP_MD_CTX* ctx = EVP_MD_CTX_create();
    assert(EVP_SignInit_ex(ctx, EVP_sha256(), NULL));
    assert(EVP_SignUpdate(ctx, data_to_sign.data(), data_to_sign.size()));
    unsigned char *signature = new unsigned char[EVP_PKEY_size(privkey)];
    unsigned int actual_signature_len;
    assert(EVP_SignFinal(ctx, signature, &actual_signature_len, privkey));
    EVP_MD_CTX_destroy(ctx);
    EVP_PKEY_free(privkey);

    // Now we have our signature, let's check it actually verifies.
    ctx = EVP_MD_CTX_create();
    if (!EVP_VerifyInit_ex(ctx, EVP_sha256(), NULL) ||
        !EVP_VerifyUpdate(ctx, data_to_sign.data(), data_to_sign.size()) ||
        !EVP_VerifyFinal(ctx, signature, actual_signature_len, pubkey)) {
        std::cerr << "Error! Signature failed; maybe private key and certificates do not match?\n";
        exit(1);
    }
    EVP_MD_CTX_destroy(ctx);
    EVP_PKEY_free(pubkey);
    X509_free(first_cert);

    // We got here, so the signature is self-consistent.
    request.set_signature(signature, actual_signature_len);
    delete[] signature;

    if (params.count("out")) {
        std::fstream outfile(params["out"].c_str(), std::ios::out | std::ios::trunc | std::ios::binary);
        assert(request.SerializeToOstream(&outfile));
    }
    else {
        assert(request.SerializeToOstream(&std::cout));
    }

    google::protobuf::ShutdownProtobufLibrary();
    EVP_cleanup(); // frees memory allocated by OpenSSL_add_all_algorithms
    ERR_free_strings(); // frees memory allocated by ERR_load_BIO_strings
}
