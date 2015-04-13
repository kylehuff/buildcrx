#ifndef BUILDCRX_H_
#define BUILDCRX_H_

#include "openssl/rsa.h"
#include "openssl/pem.h"
#include "openssl/err.h"

enum  optionIndex {
  UNKNOWN,
  HELP,
  ZIP,
  PEMFILE,
  OUTFILE,
  KEY,
  GEN,
  KEYSIZE,
  ID,
  VERBOSE,
  VERSION,
};

enum buildcrxStatus {
  SUCCESS,
  BAD_PARAMS,
  BAD_PEM_FILE,
  BAD_ZIP_FILE,
  BAD_OUT_FILE,
  BAD_PEM_STRING,
  GEN_KEY_CTX_FAIL,
  GEN_KEY_INIT_FAIL,
  GEN_KEY_SIZE_FAIL,
  GEN_KEY_FAIL,
  GET_ID_FAIL,
};

class BuildCRX {
  public:
    BuildCRX();
    ~BuildCRX();
    int loadRSAKeyFromPath(std::string&);
    int loadRSAKeyFromString(std::string);
    int genRSAKey(int);
    int packCRX();
    int writeRSAKey();
    std::string getExtensionID();

    EVP_PKEY* rsakey;
    std::string zip_file;
    std::string output_filename;
    int verbose;
  private:
};


std::string getPublicKeyString(RSA *pub) {
    BIO *bio_mem = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_RSA_PUBKEY(bio_mem, pub)) {
        printf("Unable to get Public Key data\n");
        return "";
    }

    char* mem = 0;
    long bytes = BIO_get_mem_data(bio_mem, &mem);
    std::string pubstr = std::string(mem, mem + bytes);

    BIO_free_all(bio_mem);

    return pubstr;
}

std::string getPrivateKeyString(EVP_PKEY *rsakey) {
    BIO *bio_mem = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PrivateKey(bio_mem, rsakey, NULL, NULL, 0, 0, NULL)) {
        printf("Unable to get Private Key data\n");
        return "";
    }

    char* mem = 0;
    long bytes = BIO_get_mem_data(bio_mem, &mem);
    std::string pubstr = std::string(mem, mem + bytes);

    BIO_free_all(bio_mem);

    return pubstr;
}

std::string to_hex(unsigned char s) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(2) << (int) s;
    return ss.str();
}

unsigned int to_int(unsigned char s) {
    std::stringstream ss;
    unsigned int i;
    ss << std::hex << std::setfill('0') << std::setw(2) << s;
    ss >> i;
    return i;
}

std::string to_lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), ::tolower);
  return s;
}

std::string stripKey(std::string pubstr) {
    pubstr.erase(0, pubstr.find('\n') + 1);
    pubstr.erase(std::remove(pubstr.begin(), pubstr.end(), '\n'), pubstr.end());
    pubstr.erase(pubstr.find('-'), pubstr.size());
    return pubstr;
}

#endif // BUILDCRX_H_
