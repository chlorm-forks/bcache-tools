#ifndef _LIBBCACHE_H
#define _LIBBCACHE_H

#include "util.h"
#include "vstructs.h"
#include "stdbool.h"

extern const char * const cache_state[];
extern const char * const replacement_policies[];
extern const char * const csum_types[];
extern const char * const compression_types[];
extern const char * const str_hash_types[];
extern const char * const error_actions[];
extern const char * const bdev_cache_mode[];
extern const char * const bdev_state[];

struct dev_opts {
	int		fd;
	const char	*path;
	u64		size; /* 512 byte sectors */
	unsigned	bucket_size;
	unsigned	tier;
	bool		discard;

	u64		first_bucket;
	u64		nbuckets;
};

void bcache_format(struct dev_opts *devs, size_t nr_devs,
		   unsigned block_size,
		   unsigned btree_node_size,
		   unsigned meta_csum_type,
		   unsigned data_csum_type,
		   unsigned compression_type,
		   const char *passphrase,
		   unsigned meta_replicas,
		   unsigned data_replicas,
		   unsigned on_error_action,
		   char *label,
		   uuid_le uuid);

struct bch_sb *bcache_super_read(const char *);

void bcache_super_print(struct bch_sb *, int);

static inline struct bch_sb_field *bch_sb_field_get(struct bch_sb *sb,
						enum bch_sb_field_types type)
{
	struct bch_sb_field *f;

	vstruct_for_each(sb, f)
		if (le32_to_cpu(f->type) == type)
			return f;
	return NULL;
}

#endif /* _LIBBCACHE_H */
