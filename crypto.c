#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#include <linux/random.h>
#include <libscrypt.h>
#include <sodium/crypto_stream_chacha20.h>

#include "crypto.h"

static const char bch_key_header[8]		= BCACHE_MASTER_KEY_HEADER;

bool disk_key_is_encrypted(struct bcache_disk_key *key)
{
	return memcmp(&key->header, bch_key_header, sizeof(bch_key_header));
}

char *read_passphrase(const char *prompt)
{
	char *buf = NULL;
	size_t buflen = 0;
	ssize_t len;

	if (isatty(STDIN_FILENO)) {
		struct termios old, new;

		fprintf(stderr, "%s", prompt);
		fflush(stderr);

		if (tcgetattr(STDIN_FILENO, &old))
			die("error getting terminal attrs");

		new = old;
		new.c_lflag &= ~ECHO;
		if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new))
			die("error setting terminal attrs");

		len = getline(&buf, &buflen, stdin);

		tcsetattr(STDIN_FILENO, TCSAFLUSH, &old);
		fprintf(stderr, "\n");
	} else {
		len = getline(&buf, &buflen, stdin);
	}

	if (len < 0)
		die("error reading passphrase");
	if (len && buf[len - 1] == '\n')
		buf[len - 1] = '\0';

	return buf;
}

void derive_passphrase(struct bch_sb_field_crypt *crypt,
		       struct bcache_key *key,
		       const char *passphrase)
{
	const unsigned char salt[] = "bcache";
	int ret;

	switch (BCH_CRYPT_KDF_TYPE(crypt)) {
	case BCH_KDF_SCRYPT:
		ret = libscrypt_scrypt((void *) passphrase, strlen(passphrase),
				       salt, sizeof(salt),
				       1ULL << BCH_KDF_SCRYPT_N(crypt),
				       1ULL << BCH_KDF_SCRYPT_R(crypt),
				       1ULL << BCH_KDF_SCRYPT_P(crypt),
				       (void *) key, sizeof(*key));
		if (ret)
			die("scrypt error: %i", ret);
		break;
	default:
		die("unknown kdf type %llu", BCH_CRYPT_KDF_TYPE(crypt));
	}

}

void disk_key_encrypt(struct bch_sb *sb,
		      struct bcache_disk_key *disk_key,
		      struct bcache_key *key)
{
	__le64 magic = __bch_sb_magic(sb);
	__le32 nonce[2];
	int ret;

	memcpy(nonce, &magic, sizeof(magic));

	ret = crypto_stream_chacha20_xor((void *) disk_key,
					 (void *) disk_key, sizeof(*disk_key),
					 (void *) nonce,
					 (void *) key);
	if (ret)
		die("chacha20 error: %i", ret);
}

void bcache_crypt_init(struct bch_sb *sb,
		       struct bch_sb_field_crypt *crypt,
		       const char *passphrase)
{
	struct bcache_key key;
	struct bcache_disk_key disk_key;

	SET_BCH_CRYPT_KDF_TYPE(crypt, BCH_KDF_SCRYPT);
	SET_BCH_KDF_SCRYPT_N(crypt, ilog2(SCRYPT_N));
	SET_BCH_KDF_SCRYPT_R(crypt, ilog2(SCRYPT_r));
	SET_BCH_KDF_SCRYPT_P(crypt, ilog2(SCRYPT_p));

	derive_passphrase(crypt, &key, passphrase);

	memcpy(&disk_key.header, bch_key_header, sizeof(bch_key_header));

	get_random_bytes(disk_key.key, sizeof(disk_key.key));
	disk_key_encrypt(sb, &disk_key, &key);

	memcpy(crypt->encryption_key, &disk_key,
	       sizeof(crypt->encryption_key));

	memzero_explicit(&disk_key, sizeof(disk_key));
	memzero_explicit(&key, sizeof(key));
}
