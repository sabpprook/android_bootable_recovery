#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/aes.h>

#define OZIP_HEAD_SIZE 0xC
#define OZIP_INFO_SIZE 0x1050
#define OZIP_RAWBLOCK_SIZE 0x4000

static AES_KEY aes;
static FILE* ozip;

const char* ozip_header = "\x4F\x50\x50\x4F\x45\x4E\x43\x52\x59\x50\x54\x21";
const unsigned char* keytable[] = {
	(const unsigned char *) "\xD6\xDC\xCF\x0A\xD5\xAC\xD4\xE0\x29\x2E\x52\x2D\xB7\xC1\x38\x1E", // R9s / R9s Plus / R11
	(const unsigned char *) "\xD7\xDB\xCE\x1A\xD4\xAF\xDC\xE1\x39\x3E\x51\x21\xCB\xDC\x43\x21", // R11s / R11s Plus
	(const unsigned char *) "\xD4\xD2\xCD\x61\xD4\xAF\xDC\xE1\x3B\x5E\x01\x22\x1B\xD1\x4D\x20", // Find X
	(const unsigned char *) "\x26\x1C\xC7\x13\x1D\x7C\x14\x81\x29\x4E\x53\x2D\xB7\x52\x38\x1E", // Find X (reserved)
	(const unsigned char *) "\x17\x2B\x3E\x14\xE4\x6F\x3C\xE1\x3E\x2B\x51\x21\xCB\xDC\x43\x21", // Realme 1
	(const unsigned char *) "\xD1\xDA\xCF\x24\x35\x1C\xE4\x28\xA9\xCE\x32\xED\x87\x32\x32\x16", // Realme 1 (reserved)
	(const unsigned char *) "\x12\xCA\xC1\x12\x11\xAA\xC3\xAE\xA2\x65\x86\x90\x12\x2C\x1E\x81", // A73 / A83
	(const unsigned char *) "\xA1\xCC\x75\x11\x5C\xAE\xCB\x89\x0E\x4A\x56\x3C\xA1\xAC\x67\xC8", // A73 (reserved)
	(const unsigned char *) "\xD4\xD2\xCE\x11\xD4\xAF\xDC\xE1\x3B\x3E\x01\x21\xCB\xD1\x4D\x20", // OPPO K1 / R17 Neo (AX7 Pro)
	(const unsigned char *) "\x17\x2B\x3E\x14\xE4\x6F\x3C\xE1\x3E\x2B\x51\x21\xCB\xDC\x43\x21", // R15
	(const unsigned char *) "\xAC\xAC\x1E\x13\xA7\x25\x31\xAE\x4A\x1B\x22\xBB\x31\xC1\xCC\x22", // Realme 3
	(const unsigned char *) "\x21\x32\x32\x1E\xA2\xCA\x86\x62\x1A\x11\x24\x1A\xBA\x51\x27\x22", // Realme 3 (reserved)
	(const unsigned char *) "\x1C\x4C\x1E\xA3\xA1\x25\x31\xAE\x49\x1B\x21\xBB\x31\x61\x3C\x11", // Realme X
};

int check_ozip_header() {
	unsigned char header[OZIP_HEAD_SIZE];

	fseek(ozip, 0, SEEK_SET);
	fread(header, OZIP_HEAD_SIZE, 1, ozip);

	return strcmp(ozip_header, (char*)header);
}

int get_decrypt_key() {
	int len = sizeof(keytable) / sizeof(&keytable);

	unsigned char encrypt[AES_BLOCK_SIZE];
	unsigned char decrypt[AES_BLOCK_SIZE];
	
	fseek(ozip, OZIP_INFO_SIZE, SEEK_SET);
	fread(encrypt, AES_BLOCK_SIZE, 1, ozip);

	for (int i = 0; i < len; i++) {
		AES_set_decrypt_key(keytable[i], 128, &aes);
		AES_decrypt(encrypt, decrypt, &aes);

		if (decrypt[0] == 0x50 && decrypt[1] == 0x4B)
			return 0;
	}

	return -1;
}

int decrypt_ozip() {
	size_t length, pos;
	unsigned char encrypt[AES_BLOCK_SIZE];
	unsigned char decrypt[AES_BLOCK_SIZE];
	unsigned char raw_data[OZIP_RAWBLOCK_SIZE];

	fseek(ozip, 0, SEEK_END);
	length = ftell(ozip);

	fseek(ozip, OZIP_INFO_SIZE, SEEK_SET);

	while ((pos = ftell(ozip)) < length) {
		fread(encrypt, AES_BLOCK_SIZE, 1, ozip);
		fread(raw_data, OZIP_RAWBLOCK_SIZE, 1, ozip);
		AES_decrypt(encrypt, decrypt, &aes);

		fseek(ozip, (pos - OZIP_INFO_SIZE), SEEK_SET);
		fwrite(&decrypt, AES_BLOCK_SIZE, 1, ozip);
		fwrite(&raw_data, OZIP_RAWBLOCK_SIZE, 1, ozip);

		fseek(ozip, OZIP_INFO_SIZE, SEEK_CUR);
	}

	ftruncate(fileno(ozip), (length - OZIP_INFO_SIZE));

	return 0;
}

int main(int argc, char** argv) {
	if (argc != 2) {
		printf("usage: %s <*.ozip>\n", argv[0]);
		return -1;
    }

	ozip = fopen(argv[1], "r+b");

	if (check_ozip_header() != 0) {
		printf("magic not match [OPPOENCRYPT!]\n");
		return -1;
	}

    if (get_decrypt_key() != 0) {
    	printf("can't find the key to decrypt\n");
		return -1;
    }

	decrypt_ozip();

	fclose(ozip);

	/*char newfile[255];
	strcpy(newfile, argv[1]);
	strcpy(strstr(newfile, ".ozip"), ".zip");
	rename(argv[1], newfile);*/

	return 0;
}