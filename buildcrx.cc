/***************************************************************************
 * buildcrx v0.2
 *
 * Copyright (c) 2010 Kyle L. Huff (buildcrx@curetheitch.com)
 *
 * All rights reserved.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 ***************************************************************************/
#include <sstream>
#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string.h>

#include "buildcrx.h"
#include "optionparser/optionparser.h"

const option::Descriptor usage[] = {
  {UNKNOWN, 0,  "",   "",     option::Arg::None, "USAGE: buildcrx [options]\n\n"
                                                 "Options:" },
  {HELP,    0,  "h",  "help",   option::Arg::None, "  --help, -h  \tPrint usage and exit."},
  {ZIP,     0,  "z",  "zip",    option::Arg::Optional, "  --zip, -z  \tThe ZIP file to sign."},
  {PEMFILE, 0,  "p",  "pem",    option::Arg::Optional, "  --pemfile, -p  \tThe PEM file."},
  {OUTFILE, 0,  "o",  "out",    option::Arg::Optional, "  --out, -o  \tThe filename to output (can include path)."},
  {KEY,     0,  "k",  "key",    option::Arg::Optional, "  --key, -k  \tThe RSA key as a string."},
  {GEN,     0,  "g",  "gen",    option::Arg::None, "  --gen, -g  \tGenerate a new RSA key (will be saved to <outfile>.pem)."},
  {KEYSIZE, 0,  "s",  "size",   option::Arg::Optional, "  --size, -s  \tSize of new RSA key to generate (defaults to 1024)."},
  {ID,      0,  "i",  "id",     option::Arg::None, "  --id, -i  \tGet Extension ID from the Public Key."},
  {VERBOSE, 0,  "v",  "verbose",option::Arg::None, "  --verbose, -v  \tBe verbose."},
  {VERSION, 0,  "",   "version",option::Arg::None, "  --version  \tProgram version."},
  {UNKNOWN, 0,  "",   "",       option::Arg::None, "\nExamples:\n"
                                             "  buildcrx --pem=<path_to_pemfile> --out=<output_path> --zip=<path_to_zipfile>\n"
                                             "  buildcrx -p<path_to_pemfile> -o<output_path> -z<path_to_zipfile>\n"
                                             "  buildcrx --gen --size=1024 -z<path_to_zipfile> -o<output_path>\n" },
  {0,0,0,0,0,0}
};


BuildCRX::BuildCRX() {
  verbose = 0;
  rsakey = NULL;
}

BuildCRX::~BuildCRX() {
  if (rsakey)
    EVP_PKEY_free(rsakey);
}

std::string BuildCRX::getExtensionID() {
  int DIGEST_LENGTH = 32;
  unsigned char* derkey = NULL;
  unsigned char digest[DIGEST_LENGTH];
  char c[] = "abcdefghijklmnop";
  std::string hexDigest,
              strDigest;

  int derlen = i2d_RSA_PUBKEY(rsakey->pkey.rsa, NULL);
  i2d_RSA_PUBKEY(rsakey->pkey.rsa, &derkey);

  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update (&sha256, derkey, derlen);
  SHA256_Final(digest, &sha256);

  for (int i=0; i <= DIGEST_LENGTH/2; i++ ) {
      hexDigest += to_hex(digest[i]);
  }

  for (int i=0; i < DIGEST_LENGTH; i++) {
      strDigest += c[to_int(hexDigest[i])];
  }

  return strDigest;
}

int BuildCRX::loadRSAKeyFromPath(std::string& pem_file) {
  // pemfile is the PEM private key specified by the command line
  FILE* pemfile = fopen(pem_file.c_str(), "rb");

  if (!pemfile) {
    printf("Error opening PEM key file \"%s\"\n", pem_file.c_str());
    return BAD_PEM_FILE;
  }

  rsakey = PEM_read_PrivateKey(pemfile, NULL, NULL, NULL);

  fclose(pemfile);

  if (!rsakey)
    return BAD_PEM_FILE;

  return SUCCESS;
}

int BuildCRX::loadRSAKeyFromString(std::string key_data) {
  BIO* bio_mem;
  unsigned long err;
  bio_mem = BIO_new_mem_buf((void*)key_data.c_str(), -1);
  rsakey = PEM_read_bio_PrivateKey(bio_mem, 0, 0, 0);
  err = ERR_get_error();
  if (err != 0) { // Try as pubkey
    bio_mem = BIO_new_mem_buf((void*)key_data.c_str(), -1); // reset the bio
    rsakey = PEM_read_bio_PUBKEY(bio_mem, 0, 0, 0);
  }
  BIO_free(bio_mem);

  if (!rsakey)
    return BAD_PEM_STRING;

  if (verbose)
    std::cout << key_data << "\n" << std::endl;

  return SUCCESS;
}

int BuildCRX::genRSAKey(int size) {
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (!ctx) {
        printf("Error with RSA Context\n");
        return GEN_KEY_CTX_FAIL;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        printf("Unable to initialize keygen_init\n");
        return GEN_KEY_INIT_FAIL;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, size) <= 0) {
        printf("Unable to set key size\n");
        return GEN_KEY_SIZE_FAIL;
    }

    /* Generate key */
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        printf("Unable to generate key\n");
        return GEN_KEY_FAIL;
    }

    EVP_PKEY_CTX_free(ctx);

    rsakey = pkey;

    std::cout << getPublicKeyString(rsakey->pkey.rsa) << std::endl;

    return SUCCESS;
}

int BuildCRX::writeRSAKey() {
  std::string gen_file;
  FILE* fp;

  if (output_filename.size())
    gen_file = output_filename + ".pem";
  else {
    std::string extension_id = BuildCRX::getExtensionID();
    gen_file = extension_id + ".pem";
  }

  fp = fopen(gen_file.c_str(), "w");

  PEM_write_PrivateKey(fp, rsakey, NULL, NULL, 0, 0, NULL);

  fclose(fp);
  return SUCCESS;
}

int BuildCRX::packCRX() {
  unsigned char digest[SHA_DIGEST_LENGTH];
	char buff[256];
	int zcontents;
	size_t content_len = 0;

  FILE* zinput = fopen(zip_file.c_str(), "rb");

	// zinput is the zip file to sign and pack into our signed CRX extension package
	if (!zinput) {
		printf("error opening zip file \"%s\"\n", zip_file.c_str());
		return BAD_ZIP_FILE;
	} else {

	  if (verbose)
	    printf("Building ZIP file\n");

		if (!output_filename.size())
		  output_filename = zip_file + ".crx";

    if (verbose)
		  printf("Extension package will be output as %s\n", output_filename.c_str());

		FILE *output = fopen(output_filename.c_str(),"wb");
		if (!output)
      return BAD_OUT_FILE;
    if (verbose)
		  std::cout << "Opening output file: " << output_filename << std::endl;

		// Initialize OpenSSL
		OpenSSL_add_all_algorithms();
		OpenSSL_add_all_ciphers();
		OpenSSL_add_all_digests();

		// sign the zip file
		SHA_CTX sha1;
		SHA1_Init(&sha1);
		while ((zcontents = fread(buff, 1, sizeof(buff), zinput)) > 0) {
			SHA1_Update (&sha1, buff, (int)zcontents);
			content_len += zcontents;
		}
		SHA1_Final(digest, &sha1);

		RSA* publicKey = NULL;

		if (!rsakey) {
			printf("Error getting private key\n");
			return 3;
		}

		unsigned long check = RSA_check_key(rsakey->pkey.rsa);
		if(check != 1) {
			printf("The key is not valid..\n");
			return 4;
		}

		publicKey = EVP_PKEY_get1_RSA(rsakey);

		if(publicKey == NULL) {
			printf("Unable to extract the PublicKey from the Private Key data\n");
			ERR_print_errors_fp(stdout);
			return 5;
		}

		unsigned char sig[256];
		unsigned int sig_len = 0;
		malloc(RSA_size(rsakey->pkey.rsa));
		if (!RSA_sign(NID_sha1, digest, SHA_DIGEST_LENGTH, sig, &sig_len, rsakey->pkey.rsa)) {
			printf("Unable to sign the SHA digest\n");
			ERR_print_errors_fp(stdout);
			return 6;
		}

		if (!RSA_verify(NID_sha1, digest, SHA_DIGEST_LENGTH, sig, sig_len, publicKey)) {
			printf("The RSA signature of the digest failed\n");
			ERR_print_errors_fp(stdout);
			return 7;
		}

		// Convert the RSA PublicKey to DER format to include in the header
		unsigned char* derkey = NULL;
		int derlen = 0;
		derlen = i2d_RSA_PUBKEY(publicKey, 0);
		i2d_RSA_PUBKEY(publicKey, &derkey);

		// Create an array to hold the header data
		// Array = <VERSION>, <PublicKey Length>, <Signature Length>
		signed long header[3]={0002, derlen, sig_len};

		// Put the file MAGIC into output
		fprintf(output,"%s","Cr24");

		unsigned char byteArray[4];
		int headerSize = sizeof(header)/sizeof(header[0]);

		// Convert the header and pack into the output file
		for(int i=0; i < headerSize; i++){
			byteArray[0] = (char)((header[i] & 0XFF));
			byteArray[1] = (char)((header[i] >> 8) & 0XFF);
			byteArray[2] = (char)((header[i] >> 16) & 0xFF);
			byteArray[3] = (char)((header[i] >> 24) & 0xFF);
			fprintf(output, "%c%c%c%c", byteArray[0], byteArray[1], byteArray[2], byteArray[3]);
		}

		// Convert the DER formatted PublicKey and pack into the output file
		for(int i=0; i < derlen; i++){
			fprintf(output, "%c", (char)((derkey[i] & 0XFF)));
		}

		// Convert the signature and pack into the output file
		for(unsigned int i=0; i < sig_len; i++){
			fprintf(output, "%c", (char)((sig[i] & 0XFF)));
		}

    // Display the PublicKey used to sign the CRX extension package
    if (verbose)
	  	PEM_write_RSA_PUBKEY(stdout, publicKey);

		// Rewind the zipfile
		rewind(zinput);

		// Put the contents of the zipfile into the CRX extension package
		while (( zcontents = fgetc(zinput)) != EOF) {
			fprintf(output, "%c", zcontents );
		}

    if (verbose) {
		  printf("Content Size: %i (%4.2f KB)\n", (int)content_len, (float)content_len/1024.0);
		  printf("RSA Keysize: %i, RSA (DER) size: %i\n", RSA_size(rsakey->pkey.rsa), derlen);
		  printf("Signature Size: %i\n", sig_len);
		  printf("Saved extension to %s\n", output_filename.c_str());
		  printf("Extension ID: %s\n", BuildCRX::getExtensionID().c_str());
		}

		// Tie up loose ends
		RSA_free(publicKey);
		fclose(output);
		fclose(zinput);
		return SUCCESS;
  }
}

int main(int argc, char *argv[]) {
  std::string zip_file;
  std::string ext_dir;
  std::string pem_file;
  std::string out_file;
  std::string key_string;
  int key_size = 1024;
  int res = SUCCESS;

  argc-=(argc>0); argv+=(argc>0); // skip program name argv[0] if present
  option::Stats  stats(usage, argc, argv);
#ifdef __GNUC__
  option::Option options[stats.options_max], buffer[stats.buffer_max];
#else
  option::Option* options = (option::Option*)calloc(stats.options_max, sizeof(option::Option));
  option::Option* buffer  = (option::Option*)calloc(stats.buffer_max,  sizeof(option::Option));
#endif
  option::Parser parse(usage, argc, argv, options, buffer);

  if (parse.error())
    return 1;

  if (options[HELP] || argc == 0) {
    option::printUsage(std::cout, usage);
    return 0;
  }

  if (options[VERSION]) {
    std::cout << "BuildCRX v" << VERSION_STRING << std::endl;
    return 0;
  }

  BuildCRX buildcrx;

  if (options[VERBOSE].count() > 0) {
    std::cout << "setting verbosity: " << options[VERBOSE].count() << std::endl;
    buildcrx.verbose = options[VERBOSE].count();
  }

  if (options[ZIP])
    buildcrx.zip_file = options[ZIP].arg;

  if (options[PEMFILE] && options[PEMFILE].arg != 0) {
    pem_file = std::string(options[PEMFILE].arg);
    res = buildcrx.loadRSAKeyFromPath(pem_file);

    if (res == SUCCESS) {
      if (buildcrx.verbose)
        std::cout << "Loaded Key from file" << std::endl;
    } else
      return res;
  }

  if (options[OUTFILE])
    buildcrx.output_filename = options[OUTFILE].arg;

  if (options[KEY]) {
    res = buildcrx.loadRSAKeyFromString(options[KEY].arg);

    if (res == SUCCESS) {
      if (buildcrx.verbose)
        std::cout << "Loaded Key from string" << std::endl;
    } else
      return res;
  }

  if (options[KEYSIZE])
    key_size = atoi(options[KEYSIZE].arg);

  if (options[GEN]) {
    res = buildcrx.genRSAKey(key_size);
    if (res != SUCCESS)
      return res;
    res = buildcrx.writeRSAKey();
    if (res != SUCCESS)
      return res;
  }

  if (buildcrx.zip_file.size()) {
    res = buildcrx.packCRX();
    if (res != SUCCESS)
      return res;
  }

  if (options[ID]) {
    if (!buildcrx.rsakey) {
      option::printUsage(std::cout, usage);
      return BAD_PEM_FILE;
    }
    std::string id = buildcrx.getExtensionID();
    if (id.size())
      std::cout << id << std::endl;
    else
      return GET_ID_FAIL;
  }

	return res;
}
