/* Copyright (C) 2021 Vojtech Aschenbrenner <v@asch.cz> */

#ifndef BUSE_RQUEUE_H
#define BUSE_RQUEUE_H

#include <linux/blkdev.h>
#include "main.h"

/*
 * Spawns checked reads on all queues.
 */
blk_status_t buse_read(struct buse_cmd *cmd);

/*
 * Creates a read chunk and puts it to the busy queue. The chunks is fetched from the busy queue by
 * the user space. The busy queue is woken up, in case it slept.
 */
blk_status_t buse_read_plain(struct buse_cmd *cmd);

/*
 * Init all read queues.
 */
int buse_rqueues_init(struct buse *buse);

/*
 * Deinit all read queues.
 */
int buse_rqueues_exit(struct buse *buse);

/*
 * Pulls read chunk from the busy queue and returns it. If there is no read chunk in the busy queue,
 * we sleep. If the chunks is not a termination chunk, we add to the fetched list meaning that the
 * chunk is in userspace but not yet acknowledged. It is for the case of userspace failure and
 * potential rerun fetched but not yet acknowledged chunks.
 */
struct read_chunk *pop_read_request_wait(struct buse_rqueue *rq);

/*
 * Acknowledge from the userspace that the read is done. If draining is true, it means that we are
 * shutting down and we are no longer servig to the userspace daemon.
 *
 * Data are copied from the shared memory (filled by user space) to the io request destination. Then
 * the bitmap tracking the free space in shared memory is updated and read requests is finished.
 */
void ack_read_request(struct buse_rqueue *rqueue, u64 shmem_offset, bool draining);

/*
 * Returns true if all read queues are bound. I.e. have connected the userspace counterpart.
 */
bool buse_rqueues_bound(struct buse *buse);

/*
 * Set the queue to be bound.
 */
void buse_rqueue_bind(struct buse_rqueue *rq);

/*
 * Sends termination chunk to the rq.
 */
void rqueue_send_term(struct buse_rqueue *rq);


/*
 * If the read chunk is actually a termination chunk leading to device shutdown.
 */
bool is_rqueue_term(struct read_chunk *ch);

#endif
