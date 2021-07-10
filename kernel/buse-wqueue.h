/* Copyright (C) 2021 Vojtech Aschenbrenner <v@asch.cz> */

#ifndef BUSE_WQUEUE_H
#define BUSE_WQUEUE_H

#include <linux/blkdev.h>
#include "main.h"

/*
 * When userspace acknowledge the write chunk we perform appropriate actions based on the write
 * chunk type.
 */
void ack_write_request(struct buse_wqueue *wq, u64 chunk_offset, bool draining);

/*
 * Copies data to the active chunk and immediately acknowledge the write request.
 */
blk_status_t buse_write(struct buse_cmd *cmd);

/*
 * Init all write queues.
 */
int buse_wqueues_init(struct buse *buse);

/*
 * Deinit all write queues.
 */
int buse_wqueues_exit(struct buse *buse);

/*
 * Flush operation. It broadcasts flush to all queues.
 */
blk_status_t buse_flush(struct buse_cmd *cmd);

/*
 * Closes active chunk of the queue, i.e. no more writes can be written to the chunk and a new
 * chunks has to be opened. This usually means that flush happened or the chunk is full.
 */
int close_chunk(struct buse_wqueue *wq);

bool is_flush_packet(struct write_chunk *wc);

/*
 * Pulls write chunk from the busy queue and returns it. If there is no write chunk in the busy queue,
 * we sleep. If the chunks is not a termination chunk, we add to the fetched list meaning that the
 * chunk is in userspace but not yet acknowledged. It is for the case of userspace failure and
 * potential rerun fetched but not yet acknowledged chunks.
 */
struct write_chunk *pop_write_request_wait(struct buse_wqueue *wq);

/*
 * Returns true if all write queues are bound. I.e. have connected the userspace counterpart.
 */
bool buse_wqueues_bound(struct buse *buse);

/*
 * Set the queue to be bound.
 */
void buse_wqueue_bind(struct buse_wqueue *wq);

/*
 * Sends termination chunk to the write queue.
 */
void wqueue_send_term(struct buse_wqueue *wq);

/*
 * True if the chunk is termination chunk.
 */
bool is_wqueue_term(struct write_chunk *ch);

#endif
