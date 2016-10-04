#ifndef _CRYPTO_H
#define _CRYPTO_H

#include "util.h"

struct bcache_key {
	u64	key[4];
};

struct bcache_disk_key {
	u64	header;
	u64	key[4];
};

bool disk_key_is_encrypted(struct bcache_disk_key *);
char *read_passphrase(const char *);
void derive_passphrase(struct bch_sb_field_crypt *,
		       struct bcache_key *, const char *);
void disk_key_encrypt(struct bch_sb *sb, struct bcache_disk_key *,
		      struct bcache_key *);
void bcache_crypt_init(struct bch_sb *sb, struct bch_sb_field_crypt *,
		       const char *);

#endif /* _CRYPTO_H */
