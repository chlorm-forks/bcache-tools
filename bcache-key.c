#include <errno.h>
#include <unistd.h>
#include <keyutils.h>
#include <uuid/uuid.h>

#include "bcache.h"
#include "libbcache.h"
#include "crypto.h"

int cmd_unlock(int argc, char *argv[])
{
	struct bcache_disk_key disk_key;
	struct bcache_key key;
	struct bch_sb *sb;
	struct bch_sb_field_crypt *crypt;
	char *passphrase;
	char uuid[40];
	char description[60];

	if (argc != 2)
		die("please supply a single device");

	sb = bcache_super_read(argv[1]);

	crypt = (void *) bch_sb_field_get(sb, BCH_SB_FIELD_crypt);
	if (!crypt)
		die("filesystem is not encrypted");

	memcpy(&disk_key, crypt->encryption_key,
	       sizeof(crypt->encryption_key));

	if (!disk_key_is_encrypted(&disk_key))
		die("filesystem does not have encryption key");

	passphrase = read_passphrase("Enter passphrase: ");

	derive_passphrase(crypt, &key, passphrase);

	/* Check if the user supplied the correct passphrase: */
	disk_key_encrypt(sb, &disk_key, &key);
	if (disk_key_is_encrypted(&disk_key))
		die("incorrect passphrase");

	uuid_unparse_lower(sb->user_uuid.b, uuid);
	sprintf(description, "bcache:%s", uuid);

	if (add_key("logon", description, &key, sizeof(key),
		    KEY_SPEC_USER_KEYRING) < 0)
		die("add_key error: %s", strerror(errno));

	memzero_explicit(&disk_key, sizeof(disk_key));
	memzero_explicit(&key, sizeof(key));
	memzero_explicit(passphrase, strlen(passphrase));
	free(passphrase);
	return 0;
}
