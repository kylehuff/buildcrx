/***************************************************************************
 * buildcrx v0.1
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
#include <string.h>
#include "rsa.h"
#include "pem.h"
#include "err.h"

#define byte unsigned char

int main(int argc, char *argv[])
{
	if (argc < 3) /* we need arguments zipfile, pem */
	{
		printf( "usage: %s <ZIP file> <PEM file> (optional <OUTPUT PATH/FILE>)\n", argv[0] );
		return 0;
	}

	printf("Bulding ZIP file\n");

	// pemfile is the PEM private key specified by the command line
	FILE *pemfile = fopen(argv[2], "rb");
	if (!pemfile) {
		printf("Error opening PEM key file \"%s\"\n", argv[2]);
		return 1;
	}

	char dst[30];
	strncpy(dst,argv[1],strlen(argv[1])-4);
	char* filename = (char*) dst;

	// zinput is the zip file to sign and pack into our signed CRX extension package
	FILE *zinput = fopen(argv[1], "rb");
	if (!zinput) {
		printf("error opening zip file \"%s\"\n", argv[1]);
		return 2;
	} else {
		if (argc < 4) {
			strcat(filename, ".crx");
			printf("strcat: %s\n", filename);
		} else {
			filename = argv[3];
		}
		char* output_filename = strdup(filename);
		printf("Extension name is %s, and will be %s\n", argv[1], output_filename);
		FILE *output = fopen(output_filename,"wb");

		// sign the zip file
		SHA_CTX sha1;
		byte digest[SHA_DIGEST_LENGTH];
		SHA1_Init(&sha1);
		char buff[256];
		int zcontents;
		size_t content_len = 0;
		while ((zcontents = fread(buff, 1, sizeof(buff), zinput)) > 0) {
			SHA1_Update (&sha1, buff, (int)zcontents);
			content_len += zcontents;
		}
		SHA1_Final(digest, &sha1);

		RSA* privateKey = NULL;
		RSA* publicKey = NULL;

		privateKey = PEM_read_RSAPrivateKey (pemfile, NULL, NULL, NULL);
		if (!privateKey) {
			printf("Error getting private key\n");
			return 3;
		}
		unsigned long check = RSA_check_key(privateKey);
		if(check != 1)
		{
			printf("The RSA key is not valid..\n");
			return 4;
		}
		BIO* bio = NULL;
		bio = BIO_new(BIO_s_mem());
		PEM_write_bio_RSA_PUBKEY(bio, privateKey);
		publicKey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
		BIO_free_all(bio);
		if(publicKey == NULL)
		{
			printf("Unable to extract the PublicKey from the PrivateKey data\n");
			ERR_print_errors_fp(stdout);
			return 5;
		}

		unsigned char *sig = NULL;
		unsigned int sig_len = 0;
		sig = malloc(RSA_size(privateKey));
		if (!RSA_sign(NID_sha1, digest, SHA_DIGEST_LENGTH, sig, &sig_len, privateKey)) {
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
		derlen = i2d_RSA_PUBKEY(privateKey, 0);
		i2d_RSA_PUBKEY(privateKey, &derkey);

		// Create an array to hold the header data
		// Array = <VERSION>, <PublicKey Length>, <Signature Length>
		signed long header[3]={0002, derlen, sig_len};

		// Put the file MAGIC into output
		fprintf(output,"%s","Cr24");

		unsigned char byteArray[4];
		int headerSize = sizeof(header)/sizeof(header[0]);

		// Convert the header and pack into the output file
		int i = 0;
		for(i=0; i < headerSize; i++){
			byteArray[0] = (char)((header[i] & 0XFF));
			byteArray[1] = (char)((header[i] >> 8) & 0XFF);
			byteArray[2] = (char)((header[i] >> 16) & 0xFF);
			byteArray[3] = (char)((header[i] >> 24) & 0xFF);
			fprintf(output, "%c%c%c%c", byteArray[0], byteArray[1], byteArray[2], byteArray[3]);
		}

		// Convert the DER formatted PublicKey and pack into the output file
		for(i=0; i < derlen; i++){
			fprintf(output, "%c", (char)((derkey[i] & 0XFF)));
		}

		// Convert the signature and pack into the output file
		for(i=0; i < sig_len; i++){
			fprintf(output, "%c", (char)((sig[i] & 0XFF)));
		}

		// Display the PublicKey used to sign the CRX extension package
		PEM_write_RSA_PUBKEY(stdout, publicKey);

		// Rewind the zipfile
		rewind(zinput);

		// Put the contents of the zipfile into the CRX extension package
		while (( zcontents = fgetc(zinput)) != EOF) {
			fprintf(output, "%c", zcontents );
		}

		printf("Content Size: %i (%4.2f KB)\n", (int)content_len, (float)content_len/1024.0);
		printf("RSA Keysize: %i, RSA (DER) size: %i\n", RSA_size(privateKey), derlen);
		printf("Signature Size: %i\n", sig_len);
		printf("Saved extension to %s\n", output_filename);

		// Tie up loose ends
		RSA_free(privateKey);
		RSA_free(publicKey);
		fclose(output);
		fclose(zinput);
		
	}
	return 0;
}
