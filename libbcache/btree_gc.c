/*
 * Copyright (C) 2010 Kent Overstreet <kent.overstreet@gmail.com>
 * Copyright (C) 2014 Datera Inc.
 */

#include "bcache.h"
#include "alloc.h"
#include "bkey_methods.h"
#include "btree_locking.h"
#include "btree_update.h"
#include "btree_io.h"
#include "btree_gc.h"
#include "buckets.h"
#include "clock.h"
#include "debug.h"
#include "error.h"
#include "extents.h"
#include "journal.h"
#include "keylist.h"
#include "move.h"
#include "super-io.h"
#include "writeback.h"

#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/rcupdate.h>
#include <trace/events/bcache.h>

struct range_checks {
	struct range_level {
		struct bpos	min;
		struct bpos	max;
	}			l[BTREE_MAX_DEPTH];
	unsigned		depth;
};

static void btree_node_range_checks_init(struct range_checks *r, unsigned depth)
{
	unsigned i;

	for (i = 0; i < BTREE_MAX_DEPTH; i++)
		r->l[i].min = r->l[i].max = POS_MIN;
	r->depth = depth;
}

static void btree_node_range_checks(struct bch_fs *c, struct btree *b,
				    struct range_checks *r)
{
	struct range_level *l = &r->l[b->level];

	struct bpos expected_min = bkey_cmp(l->min, l->max)
		? btree_type_successor(b->btree_id, l->max)
		: l->max;

	bch_fs_inconsistent_on(bkey_cmp(b->data->min_key, expected_min), c,
		"btree node has incorrect min key: %llu:%llu != %llu:%llu",
		b->data->min_key.inode,
		b->data->min_key.offset,
		expected_min.inode,
		expected_min.offset);

	l->max = b->data->max_key;

	if (b->level > r->depth) {
		l = &r->l[b->level - 1];

		bch_fs_inconsistent_on(bkey_cmp(b->data->min_key, l->min), c,
			"btree node min doesn't match min of child nodes: %llu:%llu != %llu:%llu",
			b->data->min_key.inode,
			b->data->min_key.offset,
			l->min.inode,
			l->min.offset);

		bch_fs_inconsistent_on(bkey_cmp(b->data->max_key, l->max), c,
			"btree node max doesn't match max of child nodes: %llu:%llu != %llu:%llu",
			b->data->max_key.inode,
			b->data->max_key.offset,
			l->max.inode,
			l->max.offset);

		if (bkey_cmp(b->data->max_key, POS_MAX))
			l->min = l->max =
				btree_type_successor(b->btree_id,
						     b->data->max_key);
	}
}

u8 bch_btree_key_recalc_oldest_gen(struct bch_fs *c, struct bkey_s_c k)
{
	const struct bch_extent_ptr *ptr;
	u8 max_stale = 0;

	if (bkey_extent_is_data(k.k)) {
		struct bkey_s_c_extent e = bkey_s_c_to_extent(k);

		extent_for_each_ptr(e, ptr) {
			struct bch_dev *ca = c->devs[ptr->dev];
			size_t b = PTR_BUCKET_NR(ca, ptr);

			if (__gen_after(ca->oldest_gens[b], ptr->gen))
				ca->oldest_gens[b] = ptr->gen;

			max_stale = max(max_stale, ptr_stale(ca, ptr));
		}
	}

	return max_stale;
}

/*
 * For runtime mark and sweep:
 */
static u8 bch_btree_mark_key(struct bch_fs *c, enum bkey_type type,
			     struct bkey_s_c k)
{
	switch (type) {
	case BKEY_TYPE_BTREE:
		bch_gc_mark_key(c, k, c->sb.btree_node_size, true);
		return 0;
	case BKEY_TYPE_EXTENTS:
		bch_gc_mark_key(c, k, k.k->size, false);
		return bch_btree_key_recalc_oldest_gen(c, k);
	default:
		BUG();
	}
}

u8 bch_btree_mark_key_initial(struct bch_fs *c, enum bkey_type type,
			  struct bkey_s_c k)
{
	atomic64_set(&c->key_version,
		     max_t(u64, k.k->version.lo,
			   atomic64_read(&c->key_version)));

	return bch_btree_mark_key(c, type, k);
}

static bool btree_gc_mark_node(struct bch_fs *c, struct btree *b)
{
	if (btree_node_has_ptrs(b)) {
		struct btree_node_iter iter;
		struct bkey unpacked;
		struct bkey_s_c k;
		u8 stale = 0;

		for_each_btree_node_key_unpack(b, k, &iter,
					       btree_node_is_extents(b),
					       &unpacked) {
			bkey_debugcheck(c, b, k);
			stale = max(stale, bch_btree_mark_key(c,
							btree_node_type(b), k));
		}

		if (btree_gc_rewrite_disabled(c))
			return false;

		if (stale > 10)
			return true;
	}

	if (btree_gc_always_rewrite(c))
		return true;

	return false;
}

static inline void __gc_pos_set(struct bch_fs *c, struct gc_pos new_pos)
{
	write_seqcount_begin(&c->gc_pos_lock);
	c->gc_pos = new_pos;
	write_seqcount_end(&c->gc_pos_lock);
}

static inline void gc_pos_set(struct bch_fs *c, struct gc_pos new_pos)
{
	BUG_ON(gc_pos_cmp(new_pos, c->gc_pos) <= 0);
	__gc_pos_set(c, new_pos);
}

static int bch_gc_btree(struct bch_fs *c, enum btree_id btree_id)
{
	struct btree_iter iter;
	struct btree *b;
	bool should_rewrite;
	struct range_checks r;
	unsigned depth = btree_id == BTREE_ID_EXTENTS ? 0 : 1;
	int ret;

	/*
	 * if expensive_debug_checks is on, run range_checks on all leaf nodes:
	 */
	if (expensive_debug_checks(c))
		depth = 0;

	btree_node_range_checks_init(&r, depth);

	for_each_btree_node(&iter, c, btree_id, POS_MIN, depth, b) {
		btree_node_range_checks(c, b, &r);

		bch_verify_btree_nr_keys(b);

		should_rewrite = btree_gc_mark_node(c, b);

		gc_pos_set(c, gc_pos_btree_node(b));

		if (should_rewrite)
			bch_btree_node_rewrite(&iter, b, NULL);

		bch_btree_iter_cond_resched(&iter);
	}
	ret = bch_btree_iter_unlock(&iter);
	if (ret)
		return ret;

	mutex_lock(&c->btree_root_lock);

	b = c->btree_roots[btree_id].b;
	bch_btree_mark_key(c, BKEY_TYPE_BTREE, bkey_i_to_s_c(&b->key));
	gc_pos_set(c, gc_pos_btree_root(b->btree_id));

	mutex_unlock(&c->btree_root_lock);
	return 0;
}

static void bch_mark_allocator_buckets(struct bch_fs *c)
{
	struct bch_dev *ca;
	struct open_bucket *ob;
	size_t i, j, iter;
	unsigned ci;

	for_each_member_device(ca, c, ci) {
		spin_lock(&ca->freelist_lock);

		fifo_for_each_entry(i, &ca->free_inc, iter)
			bch_mark_alloc_bucket(ca, &ca->buckets[i], true);

		for (j = 0; j < RESERVE_NR; j++)
			fifo_for_each_entry(i, &ca->free[j], iter)
				bch_mark_alloc_bucket(ca, &ca->buckets[i], true);

		spin_unlock(&ca->freelist_lock);
	}

	for (ob = c->open_buckets;
	     ob < c->open_buckets + ARRAY_SIZE(c->open_buckets);
	     ob++) {
		const struct bch_extent_ptr *ptr;

		mutex_lock(&ob->lock);
		open_bucket_for_each_ptr(ob, ptr) {
			ca = c->devs[ptr->dev];
			bch_mark_alloc_bucket(ca, PTR_BUCKET(ca, ptr), true);
		}
		mutex_unlock(&ob->lock);
	}
}

static void mark_metadata_sectors(struct bch_dev *ca, u64 start, u64 end,
				  enum bucket_data_type type)
{
	u64 b = start >> ca->bucket_bits;

	do {
		bch_mark_metadata_bucket(ca, ca->buckets + b, type, true);
		b++;
	} while (b < end >> ca->bucket_bits);
}

static void bch_dev_mark_superblocks(struct bch_dev *ca)
{
	struct bch_sb_layout *layout = &ca->disk_sb.sb->layout;
	unsigned i;

	for (i = 0; i < layout->nr_superblocks; i++) {
		if (layout->sb_offset[i] == BCH_SB_SECTOR)
			mark_metadata_sectors(ca, 0, BCH_SB_SECTOR,
					      BUCKET_SB);

		mark_metadata_sectors(ca,
				      layout->sb_offset[i],
				      layout->sb_offset[i] +
				      (1 << layout->sb_max_size_bits),
				      BUCKET_SB);
	}
}

/*
 * Mark non btree metadata - prios, journal
 */
void bch_mark_dev_metadata(struct bch_fs *c, struct bch_dev *ca)
{
	unsigned i;
	u64 b;

	lockdep_assert_held(&c->sb_lock);

	bch_dev_mark_superblocks(ca);

	spin_lock(&c->journal.lock);

	for (i = 0; i < ca->journal.nr; i++) {
		b = ca->journal.buckets[i];
		bch_mark_metadata_bucket(ca, ca->buckets + b,
					 BUCKET_JOURNAL, true);
	}

	spin_unlock(&c->journal.lock);

	spin_lock(&ca->prio_buckets_lock);

	for (i = 0; i < prio_buckets(ca) * 2; i++) {
		b = ca->prio_buckets[i];
		if (b)
			bch_mark_metadata_bucket(ca, ca->buckets + b,
						 BUCKET_PRIOS, true);
	}

	spin_unlock(&ca->prio_buckets_lock);
}

static void bch_mark_metadata(struct bch_fs *c)
{
	struct bch_dev *ca;
	unsigned i;

	mutex_lock(&c->sb_lock);
	gc_pos_set(c, gc_phase(GC_PHASE_SB_METADATA));

	for_each_online_member(ca, c, i)
		bch_mark_dev_metadata(c, ca);
	mutex_unlock(&c->sb_lock);
}

/* Also see bch_pending_btree_node_free_insert_done() */
static void bch_mark_pending_btree_node_frees(struct bch_fs *c)
{
	struct bch_fs_usage stats = { 0 };
	struct btree_interior_update *as;
	struct pending_btree_node_free *d;

	mutex_lock(&c->btree_interior_update_lock);
	gc_pos_set(c, gc_phase(GC_PHASE_PENDING_DELETE));

	for_each_pending_btree_node_free(c, as, d)
		if (d->index_update_done)
			__bch_gc_mark_key(c, bkey_i_to_s_c(&d->key),
					  c->sb.btree_node_size, true,
					  &stats);
	/*
	 * Don't apply stats - pending deletes aren't tracked in
	 * bch_alloc_stats:
	 */

	mutex_unlock(&c->btree_interior_update_lock);
}

/**
 * bch_gc - recompute bucket marks and oldest_gen, rewrite btree nodes
 */
void bch_gc(struct bch_fs *c)
{
	struct bch_dev *ca;
	struct bucket *g;
	struct bucket_mark new;
	u64 start_time = local_clock();
	unsigned i;
	int cpu;

	/*
	 * Walk _all_ references to buckets, and recompute them:
	 *
	 * Order matters here:
	 *  - Concurrent GC relies on the fact that we have a total ordering for
	 *    everything that GC walks - see  gc_will_visit_node(),
	 *    gc_will_visit_root()
	 *
	 *  - also, references move around in the course of index updates and
	 *    various other crap: everything needs to agree on the ordering
	 *    references are allowed to move around in - e.g., we're allowed to
	 *    start with a reference owned by an open_bucket (the allocator) and
	 *    move it to the btree, but not the reverse.
	 *
	 *    This is necessary to ensure that gc doesn't miss references that
	 *    move around - if references move backwards in the ordering GC
	 *    uses, GC could skip past them
	 */

	if (test_bit(BCH_FS_GC_FAILURE, &c->flags))
		return;

	trace_bcache_gc_start(c);

	/*
	 * Do this before taking gc_lock - bch_disk_reservation_get() blocks on
	 * gc_lock if sectors_available goes to 0:
	 */
	bch_recalc_sectors_available(c);

	down_write(&c->gc_lock);

	lg_global_lock(&c->usage_lock);

	/*
	 * Indicates to buckets code that gc is now in progress - done under
	 * usage_lock to avoid racing with bch_mark_key():
	 */
	__gc_pos_set(c, GC_POS_MIN);

	/* Save a copy of the existing bucket stats while we recompute them: */
	for_each_member_device(ca, c, i) {
		ca->usage_cached = __bch_dev_usage_read(ca);
		for_each_possible_cpu(cpu) {
			struct bch_dev_usage *p =
				per_cpu_ptr(ca->usage_percpu, cpu);
			memset(p, 0, sizeof(*p));
		}
	}

	c->usage_cached = __bch_fs_usage_read(c);
	for_each_possible_cpu(cpu) {
		struct bch_fs_usage *p =
			per_cpu_ptr(c->usage_percpu, cpu);

		memset(p->s, 0, sizeof(p->s));
		p->persistent_reserved = 0;
	}

	lg_global_unlock(&c->usage_lock);

	/* Clear bucket marks: */
	for_each_member_device(ca, c, i)
		for_each_bucket(g, ca) {
			bucket_cmpxchg(g, new, ({
				new.owned_by_allocator	= 0;
				new.data_type		= 0;
				new.cached_sectors	= 0;
				new.dirty_sectors	= 0;
			}));
			ca->oldest_gens[g - ca->buckets] = new.gen;
		}

	/* Walk allocator's references: */
	bch_mark_allocator_buckets(c);

	/* Walk btree: */
	while (c->gc_pos.phase < (int) BTREE_ID_NR) {
		int ret = c->btree_roots[c->gc_pos.phase].b
			? bch_gc_btree(c, (int) c->gc_pos.phase)
			: 0;

		if (ret) {
			bch_err(c, "btree gc failed: %d", ret);
			set_bit(BCH_FS_GC_FAILURE, &c->flags);
			up_write(&c->gc_lock);
			return;
		}

		gc_pos_set(c, gc_phase(c->gc_pos.phase + 1));
	}

	bch_mark_metadata(c);
	bch_mark_pending_btree_node_frees(c);
	bch_writeback_recalc_oldest_gens(c);

	for_each_member_device(ca, c, i)
		atomic_long_set(&ca->saturated_count, 0);

	/* Indicates that gc is no longer in progress: */
	gc_pos_set(c, gc_phase(GC_PHASE_DONE));

	up_write(&c->gc_lock);
	trace_bcache_gc_end(c);
	bch_time_stats_update(&c->btree_gc_time, start_time);

	/*
	 * Wake up allocator in case it was waiting for buckets
	 * because of not being able to inc gens
	 */
	for_each_member_device(ca, c, i)
		bch_wake_allocator(ca);
}

/* Btree coalescing */

static void recalc_packed_keys(struct btree *b)
{
	struct bkey_packed *k;

	memset(&b->nr, 0, sizeof(b->nr));

	BUG_ON(b->nsets != 1);

	for (k =  btree_bkey_first(b, b->set);
	     k != btree_bkey_last(b, b->set);
	     k = bkey_next(k))
		btree_keys_account_key_add(&b->nr, 0, k);
}

static void bch_coalesce_nodes(struct btree *old_nodes[GC_MERGE_NODES],
			       struct btree_iter *iter)
{
	struct btree *parent = iter->nodes[old_nodes[0]->level + 1];
	struct bch_fs *c = iter->c;
	unsigned i, nr_old_nodes, nr_new_nodes, u64s = 0;
	unsigned blocks = btree_blocks(c) * 2 / 3;
	struct btree *new_nodes[GC_MERGE_NODES];
	struct btree_interior_update *as;
	struct btree_reserve *res;
	struct keylist keylist;
	struct bkey_format_state format_state;
	struct bkey_format new_format;

	memset(new_nodes, 0, sizeof(new_nodes));
	bch_keylist_init(&keylist, NULL, 0);

	/* Count keys that are not deleted */
	for (i = 0; i < GC_MERGE_NODES && old_nodes[i]; i++)
		u64s += old_nodes[i]->nr.live_u64s;

	nr_old_nodes = nr_new_nodes = i;

	/* Check if all keys in @old_nodes could fit in one fewer node */
	if (nr_old_nodes <= 1 ||
	    __vstruct_blocks(struct btree_node, c->block_bits,
			     DIV_ROUND_UP(u64s, nr_old_nodes - 1)) > blocks)
		return;

	res = bch_btree_reserve_get(c, parent, nr_old_nodes,
				    BTREE_INSERT_NOFAIL|
				    BTREE_INSERT_USE_RESERVE,
				    NULL);
	if (IS_ERR(res)) {
		trace_bcache_btree_gc_coalesce_fail(c,
				BTREE_GC_COALESCE_FAIL_RESERVE_GET);
		return;
	}

	if (bch_keylist_realloc(&keylist, NULL, 0,
			(BKEY_U64s + BKEY_EXTENT_U64s_MAX) * nr_old_nodes)) {
		trace_bcache_btree_gc_coalesce_fail(c,
				BTREE_GC_COALESCE_FAIL_KEYLIST_REALLOC);
		goto out;
	}

	/* Find a format that all keys in @old_nodes can pack into */
	bch_bkey_format_init(&format_state);

	for (i = 0; i < nr_old_nodes; i++)
		__bch_btree_calc_format(&format_state, old_nodes[i]);

	new_format = bch_bkey_format_done(&format_state);

	/* Check if repacking would make any nodes too big to fit */
	for (i = 0; i < nr_old_nodes; i++)
		if (!bch_btree_node_format_fits(c, old_nodes[i], &new_format)) {
			trace_bcache_btree_gc_coalesce_fail(c,
					BTREE_GC_COALESCE_FAIL_FORMAT_FITS);
			goto out;
		}

	trace_bcache_btree_gc_coalesce(c, parent, nr_old_nodes);

	as = bch_btree_interior_update_alloc(c);

	for (i = 0; i < nr_old_nodes; i++)
		bch_btree_interior_update_will_free_node(c, as, old_nodes[i]);

	/* Repack everything with @new_format and sort down to one bset */
	for (i = 0; i < nr_old_nodes; i++)
		new_nodes[i] = __btree_node_alloc_replacement(c, old_nodes[i],
							      new_format, res);

	/*
	 * Conceptually we concatenate the nodes together and slice them
	 * up at different boundaries.
	 */
	for (i = nr_new_nodes - 1; i > 0; --i) {
		struct btree *n1 = new_nodes[i];
		struct btree *n2 = new_nodes[i - 1];

		struct bset *s1 = btree_bset_first(n1);
		struct bset *s2 = btree_bset_first(n2);
		struct bkey_packed *k, *last = NULL;

		/* Calculate how many keys from @n2 we could fit inside @n1 */
		u64s = 0;

		for (k = s2->start;
		     k < vstruct_last(s2) &&
		     vstruct_blocks_plus(n1->data, c->block_bits,
					 u64s + k->u64s) <= blocks;
		     k = bkey_next(k)) {
			last = k;
			u64s += k->u64s;
		}

		if (u64s == le16_to_cpu(s2->u64s)) {
			/* n2 fits entirely in n1 */
			n1->key.k.p = n1->data->max_key = n2->data->max_key;

			memcpy_u64s(vstruct_last(s1),
				    s2->start,
				    le16_to_cpu(s2->u64s));
			le16_add_cpu(&s1->u64s, le16_to_cpu(s2->u64s));

			set_btree_bset_end(n1, n1->set);

			six_unlock_write(&n2->lock);
			bch_btree_node_free_never_inserted(c, n2);
			six_unlock_intent(&n2->lock);

			memmove(new_nodes + i - 1,
				new_nodes + i,
				sizeof(new_nodes[0]) * (nr_new_nodes - i));
			new_nodes[--nr_new_nodes] = NULL;
		} else if (u64s) {
			/* move part of n2 into n1 */
			n1->key.k.p = n1->data->max_key =
				bkey_unpack_pos(n1, last);

			n2->data->min_key =
				btree_type_successor(iter->btree_id,
						     n1->data->max_key);

			memcpy_u64s(vstruct_last(s1),
				    s2->start, u64s);
			le16_add_cpu(&s1->u64s, u64s);

			memmove(s2->start,
				vstruct_idx(s2, u64s),
				(le16_to_cpu(s2->u64s) - u64s) * sizeof(u64));
			s2->u64s = cpu_to_le16(le16_to_cpu(s2->u64s) - u64s);

			set_btree_bset_end(n1, n1->set);
			set_btree_bset_end(n2, n2->set);
		}
	}

	for (i = 0; i < nr_new_nodes; i++) {
		struct btree *n = new_nodes[i];

		recalc_packed_keys(n);
		btree_node_reset_sib_u64s(n);

		bch_btree_build_aux_trees(n);
		six_unlock_write(&n->lock);

		bch_btree_node_write(c, n, &as->cl, SIX_LOCK_intent, -1);
	}

	/*
	 * The keys for the old nodes get deleted. We don't want to insert keys
	 * that compare equal to the keys for the new nodes we'll also be
	 * inserting - we can't because keys on a keylist must be strictly
	 * greater than the previous keys, and we also don't need to since the
	 * key for the new node will serve the same purpose (overwriting the key
	 * for the old node).
	 */
	for (i = 0; i < nr_old_nodes; i++) {
		struct bkey_i delete;
		unsigned j;

		for (j = 0; j < nr_new_nodes; j++)
			if (!bkey_cmp(old_nodes[i]->key.k.p,
				      new_nodes[j]->key.k.p))
				goto next;

		bkey_init(&delete.k);
		delete.k.p = old_nodes[i]->key.k.p;
		bch_keylist_add_in_order(&keylist, &delete);
next:
		i = i;
	}

	/*
	 * Keys for the new nodes get inserted: bch_btree_insert_keys() only
	 * does the lookup once and thus expects the keys to be in sorted order
	 * so we have to make sure the new keys are correctly ordered with
	 * respect to the deleted keys added in the previous loop
	 */
	for (i = 0; i < nr_new_nodes; i++)
		bch_keylist_add_in_order(&keylist, &new_nodes[i]->key);

	/* Insert the newly coalesced nodes */
	bch_btree_insert_node(parent, iter, &keylist, res, as);

	BUG_ON(!bch_keylist_empty(&keylist));

	BUG_ON(iter->nodes[old_nodes[0]->level] != old_nodes[0]);

	BUG_ON(!bch_btree_iter_node_replace(iter, new_nodes[0]));

	for (i = 0; i < nr_new_nodes; i++)
		btree_open_bucket_put(c, new_nodes[i]);

	/* Free the old nodes and update our sliding window */
	for (i = 0; i < nr_old_nodes; i++) {
		bch_btree_node_free_inmem(iter, old_nodes[i]);
		six_unlock_intent(&old_nodes[i]->lock);

		/*
		 * the index update might have triggered a split, in which case
		 * the nodes we coalesced - the new nodes we just created -
		 * might not be sibling nodes anymore - don't add them to the
		 * sliding window (except the first):
		 */
		if (!i) {
			old_nodes[i] = new_nodes[i];
		} else {
			old_nodes[i] = NULL;
			if (new_nodes[i])
				six_unlock_intent(&new_nodes[i]->lock);
		}
	}
out:
	bch_keylist_free(&keylist, NULL);
	bch_btree_reserve_put(c, res);
}

static int bch_coalesce_btree(struct bch_fs *c, enum btree_id btree_id)
{
	struct btree_iter iter;
	struct btree *b;
	unsigned i;

	/* Sliding window of adjacent btree nodes */
	struct btree *merge[GC_MERGE_NODES];
	u32 lock_seq[GC_MERGE_NODES];

	/*
	 * XXX: We don't have a good way of positively matching on sibling nodes
	 * that have the same parent - this code works by handling the cases
	 * where they might not have the same parent, and is thus fragile. Ugh.
	 *
	 * Perhaps redo this to use multiple linked iterators?
	 */
	memset(merge, 0, sizeof(merge));

	__for_each_btree_node(&iter, c, btree_id, POS_MIN, 0, b, U8_MAX) {
		memmove(merge + 1, merge,
			sizeof(merge) - sizeof(merge[0]));
		memmove(lock_seq + 1, lock_seq,
			sizeof(lock_seq) - sizeof(lock_seq[0]));

		merge[0] = b;

		for (i = 1; i < GC_MERGE_NODES; i++) {
			if (!merge[i] ||
			    !six_relock_intent(&merge[i]->lock, lock_seq[i]))
				break;

			if (merge[i]->level != merge[0]->level) {
				six_unlock_intent(&merge[i]->lock);
				break;
			}
		}
		memset(merge + i, 0, (GC_MERGE_NODES - i) * sizeof(merge[0]));

		bch_coalesce_nodes(merge, &iter);

		for (i = 1; i < GC_MERGE_NODES && merge[i]; i++) {
			lock_seq[i] = merge[i]->lock.state.seq;
			six_unlock_intent(&merge[i]->lock);
		}

		lock_seq[0] = merge[0]->lock.state.seq;

		if (test_bit(BCH_FS_GC_STOPPING, &c->flags)) {
			bch_btree_iter_unlock(&iter);
			return -ESHUTDOWN;
		}

		bch_btree_iter_cond_resched(&iter);

		/*
		 * If the parent node wasn't relocked, it might have been split
		 * and the nodes in our sliding window might not have the same
		 * parent anymore - blow away the sliding window:
		 */
		if (iter.nodes[iter.level + 1] &&
		    !btree_node_intent_locked(&iter, iter.level + 1))
			memset(merge + 1, 0,
			       (GC_MERGE_NODES - 1) * sizeof(merge[0]));
	}
	return bch_btree_iter_unlock(&iter);
}

/**
 * bch_coalesce - coalesce adjacent nodes with low occupancy
 */
void bch_coalesce(struct bch_fs *c)
{
	u64 start_time;
	enum btree_id id;

	if (test_bit(BCH_FS_GC_FAILURE, &c->flags))
		return;

	down_read(&c->gc_lock);
	trace_bcache_gc_coalesce_start(c);
	start_time = local_clock();

	for (id = 0; id < BTREE_ID_NR; id++) {
		int ret = c->btree_roots[id].b
			? bch_coalesce_btree(c, id)
			: 0;

		if (ret) {
			if (ret != -ESHUTDOWN)
				bch_err(c, "btree coalescing failed: %d", ret);
			set_bit(BCH_FS_GC_FAILURE, &c->flags);
			return;
		}
	}

	bch_time_stats_update(&c->btree_coalesce_time, start_time);
	trace_bcache_gc_coalesce_end(c);
	up_read(&c->gc_lock);
}

static int bch_gc_thread(void *arg)
{
	struct bch_fs *c = arg;
	struct io_clock *clock = &c->io_clock[WRITE];
	unsigned long last = atomic_long_read(&clock->now);
	unsigned last_kick = atomic_read(&c->kick_gc);

	set_freezable();

	while (1) {
		unsigned long next = last + c->capacity / 16;

		while (atomic_long_read(&clock->now) < next) {
			set_current_state(TASK_INTERRUPTIBLE);

			if (kthread_should_stop()) {
				__set_current_state(TASK_RUNNING);
				return 0;
			}

			if (atomic_read(&c->kick_gc) != last_kick) {
				__set_current_state(TASK_RUNNING);
				break;
			}

			bch_io_clock_schedule_timeout(clock, next);
			try_to_freeze();
		}

		last = atomic_long_read(&clock->now);
		last_kick = atomic_read(&c->kick_gc);

		bch_gc(c);
		if (!btree_gc_coalesce_disabled(c))
			bch_coalesce(c);

		debug_check_no_locks_held();
	}

	return 0;
}

void bch_gc_thread_stop(struct bch_fs *c)
{
	set_bit(BCH_FS_GC_STOPPING, &c->flags);

	if (c->gc_thread)
		kthread_stop(c->gc_thread);

	c->gc_thread = NULL;
	clear_bit(BCH_FS_GC_STOPPING, &c->flags);
}

int bch_gc_thread_start(struct bch_fs *c)
{
	struct task_struct *p;

	BUG_ON(c->gc_thread);

	p = kthread_create(bch_gc_thread, c, "bcache_gc");
	if (IS_ERR(p))
		return PTR_ERR(p);

	c->gc_thread = p;
	wake_up_process(c->gc_thread);
	return 0;
}

/* Initial GC computes bucket marks during startup */

static void bch_initial_gc_btree(struct bch_fs *c, enum btree_id id)
{
	struct btree_iter iter;
	struct btree *b;
	struct range_checks r;

	btree_node_range_checks_init(&r, 0);

	if (!c->btree_roots[id].b)
		return;

	/*
	 * We have to hit every btree node before starting journal replay, in
	 * order for the journal seq blacklist machinery to work:
	 */
	for_each_btree_node(&iter, c, id, POS_MIN, 0, b) {
		btree_node_range_checks(c, b, &r);

		if (btree_node_has_ptrs(b)) {
			struct btree_node_iter node_iter;
			struct bkey unpacked;
			struct bkey_s_c k;

			for_each_btree_node_key_unpack(b, k, &node_iter,
						       btree_node_is_extents(b),
						       &unpacked)
				bch_btree_mark_key_initial(c, btree_node_type(b), k);
		}

		bch_btree_iter_cond_resched(&iter);
	}

	bch_btree_iter_unlock(&iter);

	bch_btree_mark_key(c, BKEY_TYPE_BTREE,
			   bkey_i_to_s_c(&c->btree_roots[id].b->key));
}

int bch_initial_gc(struct bch_fs *c, struct list_head *journal)
{
	enum btree_id id;

	for (id = 0; id < BTREE_ID_NR; id++)
		bch_initial_gc_btree(c, id);

	if (journal)
		bch_journal_mark(c, journal);

	bch_mark_metadata(c);

	/*
	 * Skip past versions that might have possibly been used (as nonces),
	 * but hadn't had their pointers written:
	 */
	if (c->sb.encryption_type)
		atomic64_add(1 << 16, &c->key_version);

	gc_pos_set(c, gc_phase(GC_PHASE_DONE));
	set_bit(BCH_FS_INITIAL_GC_DONE, &c->flags);

	return 0;
}
