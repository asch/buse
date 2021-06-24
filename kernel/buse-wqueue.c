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
#include "linux/gfp.h"
#include "linux/list.h"
#include "linux/slab.h"
#include "linux/topology.h"
#include "linux/wait.h"
#include "main.h"

static bool valid_buse_cmd(struct buse_cmd *cmd)
{
	return cmd->magic == BUSE_MAGIC;
}

/*
 * Finalizer for flush chunk when it is acknowledged from the user space.
 */
static void flush_finalize(struct write_chunk *ch, struct buse_wqueue *wq, bool draining)
{
	struct buse_cmd *cmd = ch->cmd;

	if (!valid_buse_cmd(cmd)) {
		pr_debug("Invalid flush cmd!\n");
		return;
	}

	mutex_lock(&wq->lock);
	list_del_init(&ch->list);
	mutex_unlock(&wq->lock);

	kfree(ch);

	if (atomic_dec_and_test(&cmd->flush.queues_pending)) {
		if (draining)
			blk_mq_end_request(cmd->rq,
					cmd->canceled ? BLK_STS_IOERR : BLK_STS_OK);
		else
			blk_mq_end_request(cmd->rq,
					cmd->canceled ? BLK_STS_AGAIN : BLK_STS_OK);
	}
}

static size_t chunk_index(struct buse_wqueue *wq, struct write_chunk *wc)
{
	void *chunks_ = wq->chunks;
	void *wc_ = wc;

	return (wc_ - chunks_) / sizeof(*wc);
}

/*
 * Initialize write chunk structure.
 */
static void init_write_chunk(struct buse_wqueue *wq, struct write_chunk *ch)
{
	size_t max_writes = wq->buse->write_chunk_size / wq->buse->block_size;
	u64 i = chunk_index(wq, ch);

	ch->shmem_offset = i * wq->buse->write_chunk_size;
	ch->writelist_frontier = wq->shmem + ch->shmem_offset;
	ch->data_frontier = ch->writelist_frontier + max_writes;
	ch->num_writes = 0;

	INIT_LIST_HEAD(&ch->dependent_reads);

	mutex_lock(&wq->lock);
	list_add_tail(&ch->list, &wq->free_chunks);
	mutex_unlock(&wq->lock);
}

/*
 * Finalizer for write chunk. It initiates read on all dependent reads from the read after write
 * hazard check. Then it just recycle the write chunk for future usage.
 */
static int write_finalize(struct write_chunk *ch, struct buse_wqueue *wq)
{
	struct rq_node *rq;
	struct buse_cmd *cmd;

	mutex_lock(&wq->lock);

	// Remove from fetched list
	list_del_init(&ch->list);

	mutex_unlock(&wq->lock);

	while (!list_empty(&ch->dependent_reads)) {
		rq = list_first_entry(&ch->dependent_reads, struct rq_node, list);
		cmd = blk_mq_rq_to_pdu(rq->rq);
		if (atomic_dec_and_test(&cmd->read.write_deps) &&
				atomic_read(&cmd->read.queues_pending) == 0 &&
				atomic_cmpxchg(&cmd->read.queues_pending, 0, 1) == 0) {

			buse_read_plain(cmd);
		}

		list_del_init(&rq->list);
		kfree(rq);
	}

	init_write_chunk(wq, ch);
	wake_up(&wq->free_chunks_avail);

	return 0;
}

static bool is_flush_offset(u64 offset)
{
	return offset > (1UL << 32);
}

bool is_flush_packet(struct write_chunk *wc)
{
	return is_flush_offset(wc->shmem_offset);
}

/*
 * When userspace acknowledge the write chunk we perform appropriate actions based on the write
 * chunk type.
 */
void ack_write_request(struct buse_wqueue *wq, u64 chunk_offset, bool draining)
{
	if (is_flush_offset(chunk_offset))
		flush_finalize((struct write_chunk *)chunk_offset, wq, draining);
	else {
		struct write_chunk *ch;
		u64 chunk_index = chunk_offset / wq->buse->write_chunk_size;
		uint chunks_total = wq->buse->write_shm_size / wq->buse->write_chunk_size;

		if (chunk_offset % wq->buse->write_chunk_size ||
				chunk_index >= chunks_total) {
			BUG();
		}

		ch = &wq->chunks[chunk_index];
		write_finalize(ch, wq);
	}
}

/*
 * Pulls write chunk from the busy queue and returns it. If there is no write chunk in the busy queue,
 * we sleep. If the chunks is not a termination chunk, we add to the fetched list meaning that the
 * chunk is in userspace but not yet acknowledged. It is for the case of userspace failure and
 * potential rerun fetched but not yet acknowledged chunks.
 */
struct write_chunk *pop_write_request_wait(struct buse_wqueue *wq)
{
	struct write_chunk *ch = NULL;
	int ret;

	ret = wait_event_interruptible(wq->busy_chunks_avail, !list_empty(&wq->busy_chunks));
	if (ret < 0)
		return ERR_PTR(-EAGAIN);

	mutex_lock(&wq->lock);

	BUG_ON(list_empty(&wq->busy_chunks));

	ch = list_first_entry(&wq->busy_chunks, struct write_chunk, list);
	list_del_init(&ch->list);

	if (!is_wqueue_term(ch))
		list_add_tail(&ch->list, &wq->fetched_chunks);

	mutex_unlock(&wq->lock);

	return ch;
}

/*
 * Closes active chunk of the queue, i.e. no more writes can be written to the chunk and a new
 * chunks has to be opened. This usually means that flush happened or the chunk is full.
 */
int close_chunk(struct buse_wqueue *wq)
{
	struct write_chunk *ch = wq->active_chunk;

	if (!ch || !ch->num_writes)
		goto end;

	list_add_tail(&ch->list, &wq->busy_chunks);
	wq->active_chunk = NULL;

	wake_up(&wq->busy_chunks_avail);

end:
	return 0;
}

/*
 * Opens new active chunk if there is any free chunk.
 */
int open_chunk(struct buse_wqueue *wq)
{
	BUG_ON(wq->active_chunk);

	if (list_empty(&wq->free_chunks))
		return -EFAULT;

	wq->active_chunk = list_first_entry(&wq->free_chunks, struct write_chunk, list);
	list_del_init(&wq->active_chunk->list);

	return 0;
}

/*
 * Returns amount of free bytes in the chunk.
 */
static size_t chunk_free_bytes(struct buse_wqueue *wq, struct write_chunk *ch)
{
	void *end = wq->shmem + ch->shmem_offset + wq->buse->write_chunk_size;
	return end - ch->data_frontier;
}

/*
 * Splits long writes to multiple writes not crossing the collision areas boundary and adds the
 * sequential number to each write.
 */
static void divide_add_collision(struct buse_cmd *cmd, struct write_chunk *ch)
{
	struct buse* buse = cmd->queue->w.buse;
	size_t offset = blk_rq_pos(cmd->rq) * SECTOR_SIZE;
	s64 size = blk_rq_bytes(cmd->rq);
	size_t col_size = buse->collision_area_size;
	struct writelist_item write;
	size_t flag = req_op(cmd->rq);

	size_t new_size = round_up(offset+1, col_size) - offset;
	size_t col_id = offset / col_size;
	u64 id = atomic_add_return(1, &buse->collision_counters[col_id]);
	if (new_size > size)
		new_size = size;


	write.sector = offset / SECTOR_SIZE;
	write.len = new_size / SECTOR_SIZE;
	write.id = id;
	write.flag = flag;
	memcpy(ch->writelist_frontier, &write, sizeof(write));
	ch->writelist_frontier++;
	ch->num_writes++;

	offset += new_size;
	size -= new_size;

	for (; size > 0; size -= col_size, offset += col_size) {
		size_t col_id = offset / col_size;
		u64 id = atomic_add_return(1, &buse->collision_counters[col_id]);
		write.sector = offset / SECTOR_SIZE;
		write.len = col_size / SECTOR_SIZE;
		if (size < col_size)
			write.len = size / SECTOR_SIZE;
		write.id = id;
		write.flag = flag;
		memcpy(ch->writelist_frontier, &write, sizeof(write));
		ch->writelist_frontier++;
		ch->num_writes++;
	}
}

/*
 * Copy data to the shared memory from the memory specified by the io request.
 */
static void copy_to_chunk(struct buse_cmd *cmd, struct write_chunk *ch)
{
	char *src;
	size_t len;
	struct bio_vec bvec;
	struct req_iterator iter;
	struct request *rq = cmd->rq;

	divide_add_collision(cmd, ch);

	if (req_op(rq) == REQ_OP_WRITE) {
		rq_for_each_segment(bvec, rq, iter) {
			len = bvec.bv_len;
			src = kmap_atomic(bvec.bv_page);
			memcpy(ch->data_frontier, src + bvec.bv_offset, len);
			kunmap_atomic(src);
			ch->data_frontier += len;
		}
	}
}

/*
 * Compute number of needed slots in the metadata area of the write chunk since the write can be
 * split into multiple writes.
 */
static size_t needed_slots(struct buse_cmd *cmd)
{
	size_t size = blk_rq_bytes(cmd->rq);
	struct buse *buse = cmd->queue->w.buse;

	// Upper bound of the crossing areas.
	return size / buse->collision_area_size + 2;
}

/*
 * Number of free write metadata slots in the chunk.
 */
static size_t chunk_free_slots(struct buse_wqueue * wq, struct write_chunk *ch)
{
	size_t max_writes = wq->buse->write_chunk_size / wq->buse->block_size;
	return max_writes - ch->num_writes;
}

/*
 * True if the chunk is termination chunk.
 */
bool is_wqueue_term(struct write_chunk *ch)
{
	return ch->shmem_offset == -1;
}

/*
 * Sends termination chunk to the write queue.
 */
void wqueue_send_term(struct buse_wqueue *wq)
{
	struct write_chunk *fake_chunk;

again:
	mutex_lock(&wq->lock);

	if (!list_empty(&wq->busy_chunks)) {
		mutex_unlock(&wq->lock);
		wait_event_interruptible(wq->free_chunks_avail, list_empty(&wq->busy_chunks));
		goto again;
	}

	if (wq_has_sleeper(&wq->free_chunks_avail)) {
		wake_up(&wq->free_chunks_avail);
		mutex_unlock(&wq->lock);
		goto again;
	}

	fake_chunk = kzalloc(sizeof(*fake_chunk), GFP_KERNEL);
	if (!fake_chunk) {
		pr_debug("Cannot allocate for term uspace_packet!\n");
		return;
	}

	fake_chunk->shmem_offset = (u64)-1;

	close_chunk(wq);
	list_add_tail(&fake_chunk->list, &wq->busy_chunks);
	wq->terminated = true;
	wake_up(&wq->busy_chunks_avail);

	mutex_unlock(&wq->lock);
}

/*
 * Copies data to the active chunk and immediately acknowledge the write request.
 */
blk_status_t buse_write(struct buse_cmd *cmd)
{
	struct buse_queue *q = cmd->queue;
	struct buse_wqueue *wq = &q->w;
	struct request *rq = cmd->rq;
	size_t max_writes = wq->buse->write_chunk_size / wq->buse->block_size;

	if (req_op(rq) == REQ_OP_WRITE)
		BUG_ON(blk_rq_bytes(rq) > wq->buse->write_chunk_size - max_writes * sizeof(struct writelist_item));

again:
	if (cmd->canceled)
		return BLK_STS_IOERR;

	mutex_lock(&wq->lock);

	if (wq->terminated) {
		mutex_unlock(&wq->lock);
		return BLK_STS_IOERR;
	}

	if (wq->active_chunk &&
			(chunk_free_bytes(wq, wq->active_chunk) < blk_rq_bytes(rq) ||
			 chunk_free_slots(wq, wq->active_chunk) < needed_slots(cmd)))
		close_chunk(wq);

	if (!wq->active_chunk && open_chunk(wq) < 0) {
		mutex_unlock(&wq->lock);
		wait_event_interruptible(wq->free_chunks_avail, !list_empty(&wq->free_chunks));
		goto again;
	}

	blk_mq_start_request(rq);
	BUG_ON(wq->active_chunk->num_writes > max_writes);
	copy_to_chunk(cmd, wq->active_chunk);
	mutex_unlock(&wq->lock);

	blk_mq_end_request(rq, BLK_STS_OK);

	return BLK_STS_OK;
}

/*
 * Send flush chunk to the queue.
 */
static int send_flush(struct buse_wqueue* wq, struct buse_cmd *cmd)
{
	struct write_chunk *fake_chunk = kmalloc(sizeof(*fake_chunk), GFP_KERNEL);
	if (!fake_chunk) {
		pr_debug("Cannot allocate for flush uspace_packet!\n");
		return -1;
	}

	fake_chunk->shmem_offset = (u64)fake_chunk;
	fake_chunk->num_writes = (u64)fake_chunk;
	fake_chunk->cmd = cmd;

	list_add_tail(&fake_chunk->list, &wq->busy_chunks);
	wake_up(&wq->busy_chunks_avail);

	return 0;
}

/*
 * Per queue flush operation. Closes active chunk and immediately after it sends the flush chunk.
 */
static int wqueue_flush(void *data)
{
	struct cmd_q_args *args = data;
	struct buse_wqueue *wq = &args->q->w;
	struct buse_cmd *cmd = args->cmd;

	mutex_lock(&wq->lock);
	close_chunk(wq);
	if (send_flush(wq, args->cmd) == -1) {
		pr_debug("Cannot send flush packet from flusher!\n");
		cmd->canceled = true;
		if (atomic_dec_and_test(&cmd->flush.queues_pending)) {
			blk_mq_start_request(cmd->rq);
			blk_mq_end_request(cmd->rq, BLK_STS_AGAIN);
		}
	}
	mutex_unlock(&wq->lock);

	kfree(data);
	do_exit(0);
}

/*
 * Flush operation. It broadcasts flush to all queues.
 */
blk_status_t buse_flush(struct buse_cmd *cmd)
{
	int i;
	struct cmd_q_args *args;
	struct buse_queue *q = cmd->queue;
	struct buse *buse = q->w.buse;
	size_t num_queues = buse->num_queues;

	atomic_set(&cmd->flush.queues_pending, num_queues);

	for (i = 0; i < num_queues; i++) {
		args = kzalloc(sizeof(*args), GFP_KERNEL);
		if (!args) {
			pr_debug("Cannot allocate!\n");
			goto err;
		}

		args->cmd = cmd;
		args->q = &buse->queues[i];

		if (kthread_run(wqueue_flush, args, "buse-flush%d", i) < 0) {
			pr_alert("Cannot spawn wqueue_flush thread!\n");
			goto err_args;
		}
	}

	return BLK_STS_OK;

err_args:
	kfree(args);
err:
	atomic_sub(num_queues - i, &cmd->flush.queues_pending);
	cmd->canceled = true;

	if (!i)
		return BLK_STS_AGAIN;

	return BLK_STS_OK;
}

/*
 * Another implementation of the flush logic. This one does flush broadcasting sequentially without
 * spawning additional threads. Kept here for potentional architecture change in the future.
 */
//blk_status_t buse_flush(struct buse_cmd *cmd)
//{
//	int i;
//	struct buse_queue *q = cmd->queue;
//	struct buse *buse = q->w.buse;
//	size_t num_queues = buse->num_queues;
//	struct buse_wqueue *wq;
//	size_t collision_areas = buse->size / buse->collision_area_size;
//
//	atomic_set(&cmd->flush.queues_pending, num_queues);
//
//	for (i = 0; i < num_queues; i++) {
//		wq = &buse->queues[i].w;
//		mutex_lock(&wq->lock);
//	}
//
//	for (i = 0; i < num_queues; i++) {
//		wq = &buse->queues[i].w;
//		close_chunk(wq);
//		if (send_flush(wq, cmd) == -1) {
//			pr_debug("Cannot send flush packet from flusher!\n");
//			cmd->canceled = true;
//			if (atomic_dec_and_test(&cmd->flush.queues_pending)) {
//				blk_mq_start_request(cmd->rq);
//				blk_mq_end_request(cmd->rq, BLK_STS_AGAIN);
//			}
//			break;
//		}
//	}
//
//	memset(wq->buse->collision_counters, 0, collision_areas);
//
//	for (i = 0; i < num_queues; i++) {
//		wq = &buse->queues[i].w;
//		mutex_unlock(&wq->lock);
//	}
//
//	return BLK_STS_OK;
//}

/*
 * Drains all the queues because the is shutting down non-gracefully and we don't want memory leaks.
 */
static void wqueue_drain(struct buse_wqueue *wq)
{
	struct write_chunk *chunk;

	mutex_lock(&wq->lock);
	close_chunk(wq);
	while (!list_empty(&wq->busy_chunks)) {
		chunk = list_first_entry(&wq->busy_chunks, struct write_chunk, list);
		mutex_unlock(&wq->lock);
		if (is_wqueue_term(chunk)) {
			mutex_lock(&wq->lock);
			list_del_init(&chunk->list);
			mutex_unlock(&wq->lock);
			kfree(chunk);
		} else
			ack_write_request(wq, chunk->shmem_offset, true);
		mutex_lock(&wq->lock);
	}

	while (!list_empty(&wq->fetched_chunks)) {
		chunk = list_first_entry(&wq->fetched_chunks, struct write_chunk, list);
		mutex_unlock(&wq->lock);
		ack_write_request(wq, chunk->shmem_offset, true);
		mutex_lock(&wq->lock);
	}
	mutex_unlock(&wq->lock);
}

/*
 * Deallocates the write queue.
 */
static void wqueue_exit(struct buse_wqueue *wq)
{
	wqueue_drain(wq);
	kfree(wq->chunks);
	vfree(wq->shmem);
}

/*
 * Allocates the read queue.
 */
static int wqueue_init(struct buse_wqueue *wq)
{
	int ret, i;
	struct buse *buse = wq->buse;
	uint w_chunks = buse->write_shm_size / buse->write_chunk_size;
	int numa_node = buse_get_numa_node_for_queue_id(wq->buse, wq->q->id);

	init_waitqueue_head(&wq->busy_chunks_avail);
	init_waitqueue_head(&wq->free_chunks_avail);
	INIT_LIST_HEAD(&wq->free_chunks);
	INIT_LIST_HEAD(&wq->busy_chunks);
	INIT_LIST_HEAD(&wq->fetched_chunks);

	mutex_init(&wq->lock);

	wq->size = buse->write_shm_size;

	wq->shmem = vmalloc_node(wq->size, numa_node);
	if (wq->shmem == NULL) {
		ret = -ENOMEM;
		goto err;
	}

	wq->chunks = kcalloc(w_chunks, sizeof(*wq->chunks), GFP_KERNEL);
	if (!wq->chunks) {
		ret = -ENOMEM;
		goto err_shmem;
	}

	for (i = 0; i < w_chunks; i++)
		init_write_chunk(wq, &wq->chunks[i]);

	open_chunk(wq);

	return 0;

err_shmem:
	vfree(wq->shmem);
err:
	return ret;
}

/*
 * Init all write queues.
 */
int buse_wqueues_init(struct buse *buse)
{
	int ret, i;
	struct buse_queue *q;
	size_t collisions_areas = buse->size / buse->collision_area_size;

	for (i = 0, q = buse->queues; i < buse->num_queues; i++, q++) {
		q->w.buse = buse;
		q->w.q = q;
		ret = wqueue_init(&q->w);
		if (ret) {
			i++;
			q++;
			goto err;
		}
	}

	buse->collision_counters = kcalloc(collisions_areas, sizeof(*buse->collision_counters), GFP_KERNEL);
	if (!buse->collision_counters) {
		ret = -ENOMEM;
		goto err;
	}

	return 0;

err:
	for (i--, q--; i > 0; i--, q--)
		wqueue_exit(&q->w);

	return ret;
}

/*
 * Deinit all write queues.
 */
int buse_wqueues_exit(struct buse *buse)
{
	int i;
	struct buse_queue *q;

	for (i = 0, q = buse->queues; i < buse->num_queues; i++, q++)
		wqueue_exit(&q->w);

	kfree(buse->collision_counters);

	return 0;
}

/*
 * Rerun all fetched chunks by the user space again. This is called when user space failes without
 * acknowledging write chunks and reconnects again.
 */
static void rerun_write_chunks(struct buse_wqueue *wq)
{
	struct write_chunk *ch;

	mutex_lock(&wq->lock);
	while (!list_empty(&wq->fetched_chunks)) {
		ch = list_last_entry(&wq->fetched_chunks, struct write_chunk, list);
		list_del_init(&ch->list);
		list_add(&ch->list, &wq->busy_chunks);
	}
	wake_up(&wq->busy_chunks_avail);
	mutex_unlock(&wq->lock);
}

/*
 * Set the queue to be bound.
 */
void buse_wqueue_bind(struct buse_wqueue *wq)
{
	atomic_set(&wq->bound, 1);
	buse_blkdev_init_cond(wq->buse);
	rerun_write_chunks(wq);
}

/*
 * Returns true if all write queues are bound. I.e. have connected the userspace counterpart.
 */
bool buse_wqueues_bound(struct buse *buse)
{
	int i;
	struct buse_wqueue *wq;

	for (i = 0; i < buse->num_queues; i++) {
		wq = &buse->queues[i].w;
		if (atomic_read(&wq->bound) == 0)
			return false;
	}

	return true;
}
