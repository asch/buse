// Copyright (C) 2021 Vojtech Aschenbrenner <v@asch.cz>

#include <linux/blkdev.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/module.h>

#include "asm-generic/atomic-instrumented.h"
#include "asm-generic/errno-base.h"
#include "buse-chrdev.h"
#include "buse-blkdev.h"
#include "buse-rqueue.h"
#include "buse-wqueue.h"
#include "linux/bitmap.h"
#include "linux/blk-mq.h"
#include "linux/blk_types.h"
#include "linux/list.h"
#include "linux/slab.h"
#include "linux/spinlock.h"
#include "linux/vmalloc.h"
#include "linux/wait.h"
#include "main.h"

/*
 * Copy data from the shared memory to the memory specified by the io request.
 */
static void copy_to_request(struct request *rq, char *src)
{
	char *dst;
	size_t len;
	struct bio_vec bvec;
	struct req_iterator iter;

	rq_for_each_segment(bvec, rq, iter) {
		len = bvec.bv_len;
		dst = kmap_atomic(bvec.bv_page);
		memcpy(dst + bvec.bv_offset, src, len);
		kunmap_atomic(dst);
		src += len;
	}
}

/*
 * Acknowledge from the userspace that the read is done. If draining is true, it means that we are
 * shutting down and we are no longer servig to the userspace daemon.
 *
 * Data are copied from the shared memory (filled by user space) to the io request destination. Then
 * the bitmap tracking the free space in shared memory is updated and read requests is finished.
 */
void ack_read_request(struct buse_rqueue *rq, u64 shmem_offset, bool draining)
{
	struct buse *buse = rq->buse;
	struct read_chunk *ch;
	int shmem_offset_block = shmem_offset / buse->block_size;
	int shmem_offset_blocks_cnt = buse->read_shm_size / buse->block_size;

	if (shmem_offset % buse->block_size ||
			shmem_offset_block >= shmem_offset_blocks_cnt) {
		BUG();

	}

	mutex_lock(&rq->lock);

	ch = rq->chunk_from_bitmap[shmem_offset_block];
	rq->chunk_from_bitmap[shmem_offset_block] = NULL;

	copy_to_request(ch->cmd->rq, rq->shmem + shmem_offset);

	bitmap_release_region(rq->free_chunks_bitmap, shmem_offset_block,
			order_base_2(blk_rq_bytes(ch->cmd->rq) / buse->block_size));

	list_del_init(&ch->list);

	if (draining)
		blk_mq_end_request(ch->cmd->rq, BLK_STS_IOERR);
	else
		blk_mq_end_request(ch->cmd->rq, BLK_STS_OK);

	kfree(ch);

	wake_up(&rq->free_chunks_avail);
	mutex_unlock(&rq->lock);
}

/*
 * If the read chunk is actually a termination chunk leading to device shutdown.
 */
bool is_rqueue_term(struct read_chunk *ch)
{
	return ch->shmem_offset == -1;
}

/*
 * Pulls read chunk from the busy queue and returns it. If there is no read chunk in the busy queue,
 * we sleep. If the chunks is not a termination chunk, we add to the fetched list meaning that the
 * chunk is in userspace but not yet acknowledged. It is for the case of userspace failure and
 * potential rerun fetched but not yet acknowledged chunks.
 */
struct read_chunk *pop_read_request_wait(struct buse_rqueue *rq)
{
	int ret;
	struct read_chunk *ch = NULL;

	ret = wait_event_interruptible(rq->busy_chunks_avail, !list_empty(&rq->busy_chunks));
	if (ret < 0)
		return ERR_PTR(-EAGAIN);

	mutex_lock(&rq->lock);

	BUG_ON(list_empty(&rq->busy_chunks));

	ch = list_first_entry(&rq->busy_chunks, struct read_chunk, list);
	list_del_init(&ch->list);

	if (!is_rqueue_term(ch))
		list_add_tail(&ch->list, &rq->fetched_chunks);
	mutex_unlock(&rq->lock);

	return ch;
}

/*
 * Allocates space in shared memory for a new read chunk corresponding to the cmd.
 */
static struct read_chunk *create_read_chunk(struct buse_cmd *cmd)
{
	struct buse_queue *q = cmd->queue;
	struct buse_rqueue *rq = &q->r;
	struct buse *buse = q->r.buse;
	struct request *r = cmd->rq;
	size_t len = blk_rq_sectors(r);
	size_t sector = blk_rq_pos(r);
	int chunk_index;
	int ret;
	struct read_chunk *ch;

	size_t shmem_blocks = buse->read_shm_size / buse->block_size;

	chunk_index = bitmap_find_free_region(rq->free_chunks_bitmap, shmem_blocks, order_base_2(len * SECTOR_SIZE / buse->block_size));
	if (chunk_index < 0) {
		ret = -EFAULT;
		goto err;
	}

	ch = kmalloc(sizeof(*ch), GFP_KERNEL);
	if (!ch) {
		ret = -ENOMEM;
		goto err_bitmap;
	}

	ch->len = len;
	ch->sector = sector;
	ch->cmd = cmd;
	ch->shmem_offset = chunk_index * buse->block_size;
	rq->chunk_from_bitmap[chunk_index] = ch;

	return ch;

err_bitmap:
	bitmap_release_region(rq->free_chunks_bitmap, chunk_index, order_base_2(len * SECTOR_SIZE / buse->block_size));
err:
	return ERR_PTR(ret);
}

/*
 * Creates a read chunk and puts it to the busy queue. The chunks is fetched from the busy queue by
 * the user space. The busy queue is woken up, in case it slept.
 */
blk_status_t buse_read_plain(struct buse_cmd *cmd)
{
	struct buse_queue *q = cmd->queue;
	struct buse_rqueue *rq = &q->r;
	struct read_chunk *ch;
	struct buse *buse = rq->buse;
	size_t len = (u64)blk_rq_bytes(cmd->rq) / buse->block_size;

again:
	if (cmd->canceled) {
		blk_mq_end_request(cmd->rq, BLK_STS_IOERR);
		return BLK_STS_IOERR;
	}

	mutex_lock(&rq->lock);

	if (rq->terminated) {
		blk_mq_end_request(cmd->rq, BLK_STS_IOERR);
		mutex_unlock(&rq->lock);
		return BLK_STS_IOERR;
	}

	ch = create_read_chunk(cmd);
	if (IS_ERR(ch)) {
		size_t shmem_blocks = buse->read_shm_size / buse->block_size;
		mutex_unlock(&rq->lock);
		wait_event_interruptible(rq->free_chunks_avail,
				bitmap_find_next_zero_area(rq->free_chunks_bitmap, shmem_blocks, 0, len, 0)
				< shmem_blocks - len);
		goto again;
	}

	list_add_tail(&ch->list, &rq->busy_chunks);
	blk_mq_start_request(cmd->rq);
	wake_up(&rq->busy_chunks_avail);
	mutex_unlock(&rq->lock);

	return BLK_STS_OK;
}

/*
 * Sends termination chunk to the rq.
 */
void rqueue_send_term(struct buse_rqueue *rq)
{
	struct read_chunk *ch;
	size_t shmem_blocks = rq->buse->read_shm_size / rq->buse->block_size;
again:
	mutex_lock(&rq->lock);

	if (!bitmap_empty(rq->free_chunks_bitmap, shmem_blocks)) {
		mutex_unlock(&rq->lock);
		wait_event_interruptible(rq->free_chunks_avail, bitmap_empty(rq->free_chunks_bitmap, shmem_blocks));
		goto again;
	}


	if (wq_has_sleeper(&rq->free_chunks_avail)) {
		wake_up(&rq->free_chunks_avail);
		mutex_unlock(&rq->lock);
		goto again;
	}

	ch = kzalloc(sizeof(*ch), GFP_KERNEL);
	if (!ch) {
		pr_alert("Cannot allocate termination packet! Check traffic and shut down manually!\n");
		return;
	}

	ch->shmem_offset = (u64)-1;
	list_add_tail(&ch->list, &rq->busy_chunks);
	rq->terminated = true;
	wake_up(&rq->busy_chunks_avail);

	mutex_unlock(&rq->lock);
}

static bool overlaps(size_t x, size_t x_len, size_t y, size_t y_len)
{
	return ((x <= y && x + x_len > y) || (x >= y && x < y + y_len));
}

/*
 * Adds a dependent read to the write chunk. When that write chunk is acknowledged, all dependent
 * reads are allowed to be send to userspace.
 */
static int read_dep_add(struct buse_cmd *cmd, struct write_chunk *ch)
{
	struct rq_node *node = kzalloc(sizeof(*node), GFP_KERNEL);
	if (!node)
		return -ENOMEM;

	node->rq = cmd->rq;
	atomic_inc(&cmd->read.write_deps);
	list_add_tail(&node->list, &ch->dependent_reads);

	return 0;
}

/*
 * Checks if the command has conflict with any of writes in the write chunk. Conflict means that
 * read reads data written be the write. This is read after write hazard.
 */
static bool is_read_dep_conflict(struct buse_cmd *cmd, struct write_chunk *ch)
{
	size_t sector = blk_rq_pos(cmd->rq);
	size_t len = blk_rq_sectors(cmd->rq);
	int i;
	struct writelist_item *w;

	if (!ch || is_flush_packet(ch))
		return false;

	w = ch->writelist_frontier - ch->num_writes;
	for (i = 0; i < ch->num_writes; i++, w++)
		if (overlaps(sector, len, w->sector, w->len))
			return true;

	return false;
}

/*
 * First checks for read after write hazards and add potential conflicting reads to the appropriate
 * write chunks. If no conflict was found and there is no more queues to check the read processed.
 * Otherwise the read is processed as a callback when depending write chunk is acknowledged.
 */
static int rqueue_read_checked(void *data)
{
	int ret;
	struct cmd_q_args *args = data;
	struct buse_cmd *cmd = args->cmd;
	struct buse_queue *q = args->q;
	struct buse_wqueue *wq = &q->w;
	struct write_chunk *ch;

	mutex_lock(&wq->lock);
	list_for_each_entry(ch, &wq->busy_chunks, list)
		if (is_read_dep_conflict(cmd, ch)) {
			ret = read_dep_add(cmd, ch);
			if (ret) {
				pr_alert("Cannot add read dep from busy_chunks\n");
				goto err;
			}
		}

	list_for_each_entry(ch, &wq->fetched_chunks, list)
		if (is_read_dep_conflict(cmd, ch)) {
			ret = read_dep_add(cmd, ch);
			if (ret) {
				pr_alert("Cannot add read dep from fetched_chunks\n");
				goto err;
			}
		}

	if (is_read_dep_conflict(cmd, wq->active_chunk)) {
		ret = read_dep_add(cmd, wq->active_chunk);
		if (ret) {
			pr_alert("Cannot add read dep from active_chunk\n");
			goto err;
		}
		close_chunk(wq);
	}

	goto ret;

err:
	cmd->canceled = true;
ret:
	mutex_unlock(&wq->lock);
	if (atomic_dec_and_test(&args->cmd->read.queues_pending) &&
			atomic_read(&args->cmd->read.write_deps) == 0 &&
			atomic_cmpxchg(&args->cmd->read.queues_pending, 0, 1) == 0) {
		buse_read_plain(args->cmd);
	}

	kfree(data);

	// Here it depends on whether sequential or threaded version is used.
	return 0; // For sequential version
	//do_exit(0); // For threaded version
}

/*
 * Spawns checked reads on all queues.
 */
blk_status_t buse_read(struct buse_cmd *cmd)
{
	int i;
	struct cmd_q_args *args;
	struct buse_queue *q = cmd->queue;
	struct buse *buse = q->r.buse;
	size_t num_queues = buse->num_queues;

	atomic_set(&cmd->read.write_deps, 0);
	atomic_set(&cmd->read.queues_pending, num_queues);

	for (i = 0; i < num_queues; i++) {
		args = kzalloc(sizeof(*args), GFP_KERNEL);
		if (!args)
			goto err;

		args->cmd = cmd;
		args->q = &buse->queues[i];


		// Asynchronous version
		//if (kthread_run(rqueue_read_checked, args, "buse-queue_read_checked_th%d", i) < 0) {
		//	pr_alert("Cannot spawn rqueue_read_checked thread!\n");
		//	goto err_args;
		//}

		rqueue_read_checked(args); // Sequential version
	}

	return BLK_STS_OK;

//err_args:
	kfree(args);
err:
	atomic_sub(num_queues - i, &cmd->read.queues_pending);
	cmd->canceled = true;

	if (!i)
		return BLK_STS_AGAIN;

	return BLK_STS_OK;
}

/*
 * Drains all the queues because the is shutting down non-gracefully and we don't want memory leaks.
 */
static void rqueue_drain(struct buse_rqueue *rq)
{
	struct read_chunk *chunk;
	uint r_chunks = rq->buse->read_shm_size / rq->buse->block_size;
	int i;

	for (i = 0; i < r_chunks; i++) {
		size_t offset = i * rq->buse->block_size;
		if (rq->chunk_from_bitmap[i])
			ack_read_request(rq, offset, true);
	}

	while (!list_empty(&rq->busy_chunks)) {
		chunk = list_first_entry(&rq->busy_chunks, struct read_chunk, list);
		mutex_unlock(&rq->lock);
		if (is_rqueue_term(chunk)) {
			mutex_lock(&rq->lock);
			list_del_init(&chunk->list);
			mutex_unlock(&rq->lock);
			kfree(chunk);
		} else
			ack_read_request(rq, chunk->shmem_offset, true);
		mutex_lock(&rq->lock);
	}
}

/*
 * Deallocates the read queue.
 */
static void rqueue_exit(struct buse_rqueue *rq)
{
	rqueue_drain(rq);
	kfree(rq->chunk_from_bitmap);
	bitmap_free(rq->free_chunks_bitmap);
	vfree(rq->shmem);
}

/*
 * Allocates the read queue.
 */
static int rqueue_init(struct buse_rqueue *rq)
{
	int ret;
	struct buse *buse = rq->buse;
	uint r_chunks = buse->read_shm_size / buse->block_size;

	init_waitqueue_head(&rq->busy_chunks_avail);
	init_waitqueue_head(&rq->free_chunks_avail);
	INIT_LIST_HEAD(&rq->busy_chunks);
	INIT_LIST_HEAD(&rq->fetched_chunks);
	mutex_init(&rq->lock);

	rq->size = buse->read_shm_size;

	rq->shmem = vmalloc_user(rq->size);
	if (!rq->shmem) {
		ret = -ENOMEM;
		goto err;
	}

	rq->free_chunks_bitmap = bitmap_zalloc(r_chunks, GFP_KERNEL);
	if (!rq->free_chunks_bitmap) {
		ret = -ENOMEM;
		goto err_shmem;
	}

	rq->chunk_from_bitmap = kcalloc(r_chunks, sizeof(struct read_chunk *), GFP_KERNEL);
	if (!rq->chunk_from_bitmap) {
		ret = -ENOMEM;
		goto err_bitmap;
	}

	return 0;

err_bitmap:
	bitmap_free(rq->free_chunks_bitmap);
err_shmem:
	vfree(rq->shmem);
err:
	return ret;
}

/*
 * Init all read queues.
 */
int buse_rqueues_init(struct buse *buse)
{
	int ret, i;
	struct buse_queue *q;

	for (i = 0, q = buse->queues; i < buse->num_queues; i++, q++) {
		q->r.buse = buse;
		ret = rqueue_init(&q->r);
		if (ret) {
			i++;
			q++;
			goto err;
		}
	}

	return 0;

err:
	for (i--, q--; i > 0; i--, q--)
		rqueue_exit(&q->r);

	return ret;
}

/*
 * Deinit all read queues.
 */
int buse_rqueues_exit(struct buse *buse)
{
	int i;
	struct buse_queue *q;

	for (i = 0, q = buse->queues; i < buse->num_queues; i++, q++)
		rqueue_exit(&q->r);

	return 0;
}

/*
 * Rerun all fetched chunks by the user space again. This is called when user space failes without
 * acknowledging read chunks and reconnects again.
 */
static void rerun_read_chunks(struct buse_rqueue *rq)
{
	struct read_chunk *ch;

	mutex_lock(&rq->lock);
	while (!list_empty(&rq->fetched_chunks)) {
		ch = list_last_entry(&rq->fetched_chunks, struct read_chunk, list);
		list_del_init(&ch->list);
		list_add(&ch->list, &rq->busy_chunks);
	}
	wake_up(&rq->busy_chunks_avail);
	mutex_unlock(&rq->lock);
}

/*
 * Set the queue to be bound.
 */
void buse_rqueue_bind(struct buse_rqueue *rq)
{
	mutex_lock(&rq->buse->configfs_mutex);
	atomic_set(&rq->bound, 1);
	mutex_unlock(&rq->buse->configfs_mutex);
	buse_blkdev_init_cond(rq->buse);
	rerun_read_chunks(rq);
}

/*
 * Returns true if all read queues are bound. I.e. have connected the userspace counterpart.
 */
bool buse_rqueues_bound(struct buse *buse)
{
	int i;
	struct buse_rqueue *rq;

	for (i = 0; i < buse->num_queues; i++) {
		rq = &buse->queues[i].r;
		if (atomic_read(&rq->bound) == 0)
			return false;
	}

	return true;
}
