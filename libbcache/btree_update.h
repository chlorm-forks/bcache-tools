#ifndef _BCACHE_BTREE_INSERT_H
#define _BCACHE_BTREE_INSERT_H

#include "btree_cache.h"
#include "btree_iter.h"
#include "buckets.h"
#include "journal.h"
#include "vstructs.h"

struct bch_fs;
struct bkey_format_state;
struct bkey_format;
struct btree;

static inline void btree_node_reset_sib_u64s(struct btree *b)
{
	b->sib_u64s[0] = b->nr.live_u64s;
	b->sib_u64s[1] = b->nr.live_u64s;
}

struct btree_reserve {
	struct disk_reservation	disk_res;
	unsigned		nr;
	struct btree		*b[BTREE_RESERVE_MAX];
};

void __bch_btree_calc_format(struct bkey_format_state *, struct btree *);
bool bch_btree_node_format_fits(struct bch_fs *c, struct btree *,
				struct bkey_format *);

/* Btree node freeing/allocation: */

/*
 * Tracks a btree node that has been (or is about to be) freed in memory, but
 * has _not_ yet been freed on disk (because the write that makes the new
 * node(s) visible and frees the old hasn't completed yet)
 */
struct pending_btree_node_free {
	bool			index_update_done;

	__le64			seq;
	enum btree_id		btree_id;
	unsigned		level;
	__BKEY_PADDED(key, BKEY_BTREE_PTR_VAL_U64s_MAX);
};

/*
 * Tracks an in progress split/rewrite of a btree node and the update to the
 * parent node:
 *
 * When we split/rewrite a node, we do all the updates in memory without
 * waiting for any writes to complete - we allocate the new node(s) and update
 * the parent node, possibly recursively up to the root.
 *
 * The end result is that we have one or more new nodes being written -
 * possibly several, if there were multiple splits - and then a write (updating
 * an interior node) which will make all these new nodes visible.
 *
 * Additionally, as we split/rewrite nodes we free the old nodes - but the old
 * nodes can't be freed (their space on disk can't be reclaimed) until the
 * update to the interior node that makes the new node visible completes -
 * until then, the old nodes are still reachable on disk.
 *
 */
struct btree_interior_update {
	struct closure			cl;
	struct bch_fs		*c;

	struct list_head		list;

	/* What kind of update are we doing? */
	enum {
		BTREE_INTERIOR_NO_UPDATE,
		BTREE_INTERIOR_UPDATING_NODE,
		BTREE_INTERIOR_UPDATING_ROOT,
		BTREE_INTERIOR_UPDATING_AS,
	} mode;

	/*
	 * BTREE_INTERIOR_UPDATING_NODE:
	 * The update that made the new nodes visible was a regular update to an
	 * existing interior node - @b. We can't write out the update to @b
	 * until the new nodes we created are finished writing, so we block @b
	 * from writing by putting this btree_interior update on the
	 * @b->write_blocked list with @write_blocked_list:
	 */
	struct btree			*b;
	struct list_head		write_blocked_list;

	/*
	 * BTREE_INTERIOR_UPDATING_AS: btree node we updated was freed, so now
	 * we're now blocking another btree_interior_update
	 * @parent_as - btree_interior_update that's waiting on our nodes to finish
	 * writing, before it can make new nodes visible on disk
	 * @wait - list of child btree_interior_updates that are waiting on this
	 * btree_interior_update to make all the new nodes visible before they can free
	 * their old btree nodes
	 */
	struct btree_interior_update	*parent_as;
	struct closure_waitlist		wait;

	/*
	 * We may be freeing nodes that were dirty, and thus had journal entries
	 * pinned: we need to transfer the oldest of those pins to the
	 * btree_interior_update operation, and release it when the new node(s)
	 * are all persistent and reachable:
	 */
	struct journal_entry_pin	journal;

	u64				journal_seq;

	/*
	 * Nodes being freed:
	 * Protected by c->btree_node_pending_free_lock
	 */
	struct pending_btree_node_free	pending[BTREE_MAX_DEPTH + GC_MERGE_NODES];
	unsigned			nr_pending;

	/* Only here to reduce stack usage on recursive splits: */
	struct keylist			parent_keys;
	/*
	 * Enough room for btree_split's keys without realloc - btree node
	 * pointers never have crc/compression info, so we only need to acount
	 * for the pointers for three keys
	 */
	u64				inline_keys[BKEY_BTREE_PTR_U64s_MAX * 3];
};

#define for_each_pending_btree_node_free(c, as, p)			\
	list_for_each_entry(as, &c->btree_interior_update_list, list)	\
		for (p = as->pending; p < as->pending + as->nr_pending; p++)

void bch_btree_node_free_inmem(struct btree_iter *, struct btree *);
void bch_btree_node_free_never_inserted(struct bch_fs *, struct btree *);

void btree_open_bucket_put(struct bch_fs *c, struct btree *);

struct btree *__btree_node_alloc_replacement(struct bch_fs *,
					     struct btree *,
					     struct bkey_format,
					     struct btree_reserve *);
struct btree *btree_node_alloc_replacement(struct bch_fs *, struct btree *,
					   struct btree_reserve *);

struct btree_interior_update *
bch_btree_interior_update_alloc(struct bch_fs *);

void bch_btree_interior_update_will_free_node(struct bch_fs *,
					      struct btree_interior_update *,
					      struct btree *);

void bch_btree_set_root_initial(struct bch_fs *, struct btree *,
				struct btree_reserve *);

void bch_btree_reserve_put(struct bch_fs *, struct btree_reserve *);
struct btree_reserve *bch_btree_reserve_get(struct bch_fs *,
					    struct btree *, unsigned,
					    unsigned, struct closure *);

int bch_btree_root_alloc(struct bch_fs *, enum btree_id, struct closure *);

/* Inserting into a given leaf node (last stage of insert): */

bool bch_btree_bset_insert_key(struct btree_iter *, struct btree *,
			       struct btree_node_iter *, struct bkey_i *);
void bch_btree_journal_key(struct btree_insert *trans, struct btree_iter *,
			   struct bkey_i *);

static inline void *btree_data_end(struct bch_fs *c, struct btree *b)
{
	return (void *) b->data + btree_bytes(c);
}

static inline struct bkey_packed *unwritten_whiteouts_start(struct bch_fs *c,
							    struct btree *b)
{
	return (void *) ((u64 *) btree_data_end(c, b) - b->whiteout_u64s);
}

static inline struct bkey_packed *unwritten_whiteouts_end(struct bch_fs *c,
							  struct btree *b)
{
	return btree_data_end(c, b);
}

static inline void *write_block(struct btree *b)
{
	return (void *) b->data + (b->written << 9);
}

static inline bool bset_written(struct btree *b, struct bset *i)
{
	return (void *) i < write_block(b);
}

static inline bool bset_unwritten(struct btree *b, struct bset *i)
{
	return (void *) i > write_block(b);
}

static inline unsigned bset_end_sector(struct bch_fs *c, struct btree *b,
				       struct bset *i)
{
	return round_up(bset_byte_offset(b, vstruct_end(i)),
			block_bytes(c)) >> 9;
}

static inline size_t bch_btree_keys_u64s_remaining(struct bch_fs *c,
						   struct btree *b)
{
	struct bset *i = btree_bset_last(b);
	unsigned used = bset_byte_offset(b, vstruct_end(i)) / sizeof(u64) +
		b->whiteout_u64s +
		b->uncompacted_whiteout_u64s;
	unsigned total = c->sb.btree_node_size << 6;

	EBUG_ON(used > total);

	if (bset_written(b, i))
		return 0;

	return total - used;
}

static inline unsigned btree_write_set_buffer(struct btree *b)
{
	/*
	 * Could buffer up larger amounts of keys for btrees with larger keys,
	 * pending benchmarking:
	 */
	return 4 << 10;
}

static inline struct btree_node_entry *want_new_bset(struct bch_fs *c,
						     struct btree *b)
{
	struct bset *i = btree_bset_last(b);
	unsigned offset = max_t(unsigned, b->written << 9,
				bset_byte_offset(b, vstruct_end(i)));
	ssize_t n = (ssize_t) btree_bytes(c) - (ssize_t)
		(offset + sizeof(struct btree_node_entry) +
		 b->whiteout_u64s * sizeof(u64) +
		 b->uncompacted_whiteout_u64s * sizeof(u64));

	EBUG_ON(offset > btree_bytes(c));

	if ((unlikely(bset_written(b, i)) && n > 0) ||
	    (unlikely(vstruct_bytes(i) > btree_write_set_buffer(b)) &&
	     n > btree_write_set_buffer(b)))
		return (void *) b->data + offset;

	return NULL;
}

/*
 * write lock must be held on @b (else the dirty bset that we were going to
 * insert into could be written out from under us)
 */
static inline bool bch_btree_node_insert_fits(struct bch_fs *c,
					      struct btree *b, unsigned u64s)
{
	if (btree_node_is_extents(b)) {
		/* The insert key might split an existing key
		 * (bch_insert_fixup_extent() -> BCH_EXTENT_OVERLAP_MIDDLE case:
		 */
		u64s += BKEY_EXTENT_U64s_MAX;
	}

	return u64s <= bch_btree_keys_u64s_remaining(c, b);
}

static inline void unreserve_whiteout(struct btree *b, struct bset_tree *t,
				      struct bkey_packed *k)
{
	if (bset_written(b, bset(b, t))) {
		EBUG_ON(b->uncompacted_whiteout_u64s <
			bkeyp_key_u64s(&b->format, k));
		b->uncompacted_whiteout_u64s -=
			bkeyp_key_u64s(&b->format, k);
	}
}

static inline void reserve_whiteout(struct btree *b, struct bset_tree *t,
				    struct bkey_packed *k)
{
	if (bset_written(b, bset(b, t))) {
		BUG_ON(!k->needs_whiteout);
		b->uncompacted_whiteout_u64s +=
			bkeyp_key_u64s(&b->format, k);
	}
}

void bch_btree_insert_node(struct btree *, struct btree_iter *,
			   struct keylist *, struct btree_reserve *,
			   struct btree_interior_update *as);

/* Normal update interface: */

struct btree_insert {
	struct bch_fs	*c;
	struct disk_reservation *disk_res;
	struct journal_res	journal_res;
	u64			*journal_seq;
	struct extent_insert_hook *hook;
	unsigned		flags;
	bool			did_work;

	unsigned short		nr;
	struct btree_insert_entry {
		struct btree_iter *iter;
		struct bkey_i	*k;
		unsigned	extra_res;
		/*
		 * true if entire key was inserted - can only be false for
		 * extents
		 */
		bool		done;
	}			*entries;
};

int __bch_btree_insert_at(struct btree_insert *);


#define _TENTH_ARG(_1, _2, _3, _4, _5, _6, _7, _8, _9, N, ...)   N
#define COUNT_ARGS(...)  _TENTH_ARG(__VA_ARGS__, 9, 8, 7, 6, 5, 4, 3, 2, 1)

#define BTREE_INSERT_ENTRY(_iter, _k)					\
	((struct btree_insert_entry) {					\
		.iter		= (_iter),				\
		.k		= (_k),					\
		.done		= false,				\
	})

#define BTREE_INSERT_ENTRY_EXTRA_RES(_iter, _k, _extra)			\
	((struct btree_insert_entry) {					\
		.iter		= (_iter),				\
		.k		= (_k),					\
		.extra_res = (_extra),					\
		.done		= false,				\
	})

/**
 * bch_btree_insert_at - insert one or more keys at iterator positions
 * @iter:		btree iterator
 * @insert_key:		key to insert
 * @disk_res:		disk reservation
 * @hook:		extent insert callback
 *
 * Return values:
 * -EINTR: locking changed, this function should be called again. Only returned
 *  if passed BTREE_INSERT_ATOMIC.
 * -EROFS: filesystem read only
 * -EIO: journal or btree node IO error
 */
#define bch_btree_insert_at(_c, _disk_res, _hook,			\
			    _journal_seq, _flags, ...)			\
	__bch_btree_insert_at(&(struct btree_insert) {			\
		.c		= (_c),					\
		.disk_res	= (_disk_res),				\
		.journal_seq	= (_journal_seq),			\
		.hook		= (_hook),				\
		.flags		= (_flags),				\
		.nr		= COUNT_ARGS(__VA_ARGS__),		\
		.entries	= (struct btree_insert_entry[]) {	\
			__VA_ARGS__					\
		}})

/*
 * Don't drop/retake locks: instead return -EINTR if need to upgrade to intent
 * locks, -EAGAIN if need to wait on btree reserve
 */
#define BTREE_INSERT_ATOMIC		(1 << 0)

/* Don't check for -ENOSPC: */
#define BTREE_INSERT_NOFAIL		(1 << 1)

/* for copygc, or when merging btree nodes */
#define BTREE_INSERT_USE_RESERVE	(1 << 2)

/*
 * Insert is for journal replay: don't get journal reservations, or mark extents
 * (bch_mark_key)
 */
#define BTREE_INSERT_JOURNAL_REPLAY	(1 << 3)

int bch_btree_insert_list_at(struct btree_iter *, struct keylist *,
			     struct disk_reservation *,
			     struct extent_insert_hook *, u64 *, unsigned);

static inline bool journal_res_insert_fits(struct btree_insert *trans,
					   struct btree_insert_entry *insert)
{
	unsigned u64s = 0;
	struct btree_insert_entry *i;

	/*
	 * If we didn't get a journal reservation, we're in journal replay and
	 * we're not journalling updates:
	 */
	if (!trans->journal_res.ref)
		return true;

	for (i = insert; i < trans->entries + trans->nr; i++)
		u64s += jset_u64s(i->k->k.u64s + i->extra_res);

	return u64s <= trans->journal_res.u64s;
}

int bch_btree_insert_check_key(struct btree_iter *, struct bkey_i *);
int bch_btree_insert(struct bch_fs *, enum btree_id, struct bkey_i *,
		     struct disk_reservation *,
		     struct extent_insert_hook *, u64 *, int flags);
int bch_btree_update(struct bch_fs *, enum btree_id,
		     struct bkey_i *, u64 *);

int bch_btree_delete_range(struct bch_fs *, enum btree_id,
			   struct bpos, struct bpos, struct bversion,
			   struct disk_reservation *,
			   struct extent_insert_hook *, u64 *);

int bch_btree_node_rewrite(struct btree_iter *, struct btree *, struct closure *);

#endif /* _BCACHE_BTREE_INSERT_H */

