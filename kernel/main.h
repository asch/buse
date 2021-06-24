// Copyright (C) 2021 Vojtech Aschenbrenner <v@asch.cz>

#ifndef BUSE_MAIN_H
#define BUSE_MAIN_H

#include <linux/blk-mq.h>
#include <linux/cdev.h>
#include <linux/configfs.h>

#define BUSE_MAGIC 0xB3

extern const char *buse_blkdev_name;
extern const int buse_blkdev_max_minors;
extern int buse_blkdev_major;
extern struct class *buse_chrdev_class;

/*
 * Per block device structure containing all necessary fields for creating mq block device.
 */
struct buse_blkdev
{
	struct blk_mq_tag_set tag_set;
	struct gendisk *disk;
	struct request_queue *request_queue;

	// Flag which is set once the device is created. This is important because we don't create
	// device immediately but wait until all control queues are connected. Hence it is important
	// to keep track of it to know whether to destroy the block device during shut down.
	bool created;
};

/*
 * Global module structure.
 */
struct buse
{
	// Configfs related fields.
	struct config_item item;
	struct mutex configfs_mutex;

	// Indicator that device was stopped. All further io requests are refused.
	atomic_t stopped;

	// Block device related structure.
	struct buse_blkdev blkdev;

	// Sequential numbers for writes. We define one counter per collision domain to
	// avoid excessive cache coherency protocol traffic. This creates ordering on all writes
	// inside the collision domain which is enough. A counter per sector would be optimal, but
	// memory inefficient. One counter per whole address space would be to contended. Collision
	// domains are a good compromise.
	atomic_t *collision_counters;

	// Individual queues structure related to the created character devices.
	struct buse_queue *queues;
	int num_queues;

	// Attributes set by configfs operations.

	// Setting to 1 powers on the device and queues can be bound.
	bool power;

	// Index of the created block device corresponding to the created configfs node with mkdir.
	u64 index;

	// Size of the device in bytes.
	u64 size;

	// Block size. This should be 512 or 4096.
	u64 block_size;

	// Max size of one write chunk which is passed to the userspace.
	u64 write_chunk_size;

	// Size of the shared memory between kernel and userspace which is used for sending write
	// chunks to the userspace. This is per one write queue.
	u64 write_shm_size;

	// Size of the shared memory between kernel and userspace which is used for sending
	// individual reads to the userspace. This is per one write queue. Compared to writes reads
	// are not batched into chunks. Each individual read is sent to userspace.
	u64 read_shm_size;

	// Queue depth of the created block device.
	u64 queue_depth;

	// Number of hw queues block device provides. Usually number of CPUs is the right value.
	u64 hw_queues;

	// Size of the area sharing the space of write sequential numbers.
	u64 collision_area_size;

	// Instructs blk-mq no to use scheduler on the queues.
	bool no_scheduler;

	// For future usage.
	bool can_secure_erase;
	bool can_write_same;
	bool can_write_zeroes;
	bool can_discard;
};

/*
 * Per character device structure. Character device represents a queue in our model.
 */
struct buse_chrdev
{
	struct cdev cdev;
	struct device *dev;
	dev_t region;
};

/*
 * Read queue structure.
 */
struct buse_rqueue
{
	// Pointer to the main buse structure.
	struct buse *buse;

	// Pointer to the corresponding struct queue
	struct buse_queue *q;

	// Character device corresponding to the read queue.
	struct buse_chrdev chrdev;

	// Shared memory area between kernel and user space.
	void *shmem;
	size_t size;

	// Flag whether individual queue is bound, i.e. the character device is opened and mmaped.
	atomic_t bound;

	// Mapping from the bitmap index to the read chunk. Used when bitmap index is acknowledged
	// to know what read to acknowledge.
	struct read_chunk **chunk_from_bitmap;

	// Waitqueue on the event when no busy chunk is available, i.e. there is nothing to send to
	// the userspace.
	wait_queue_head_t busy_chunks_avail;

	// Waitqueue on the event when no free chunk is available, i.e. there is no space to process
	// additional reads.
	wait_queue_head_t free_chunks_avail;

	// Lock per the whole read queue.
	struct mutex lock;

	// Bitmap for keeping track of free space in shared memory.
	unsigned long *free_chunks_bitmap;

	// Queue with chunks ready to be sent to user space.
	struct list_head busy_chunks;

	// Queue with chunks already sent to user space. Important when user space side crashes to
	// rerun not acknowledged but fetched reads again.
	struct list_head fetched_chunks;

	// If true the termination chunk was already sent to user space and no other chunk can be
	// processed by the other end of the queue.
	bool terminated;
};

/*
 * Description of individual write in the metadata part of the chunk.
 */
struct writelist_item
{
	// First written sector.
	size_t sector;

	// Length of the write in sectors.
	size_t len;

	// Sequential number of write.
	size_t id;

	// Reserved for future usage.
	size_t flag;
};

/*
 * Write chunk is the unit sent to the user space. It containes batched writes and is split into two
 * parts. Metadata part containes information about the writes and data part contains their data.
 */
struct write_chunk
{
	// Chunk can be part of list.
	struct list_head list;

	// Offset to the shared memory where the chunk starts.
	u64 shmem_offset;

	// Number of writes batched in the chunk.
	u64 num_writes;

	// Helper pointer to keep track where next write of data should go.
	void *data_frontier;

	// Helper pointer to keep track where next write of metadata should go.
	struct writelist_item *writelist_frontier;

	// List of all reads waiting for any write in the chunk. These reads are postponed and woken
	// up when the write is acknowledged. Solution of the read after write hazard.
	struct list_head dependent_reads;

	// If the chunks is flush chunk, i.e. just performing the flush operation, we store the cmd
	// pointer here to be able to acknowledge it easily.
	struct buse_cmd *cmd;
};

/*
 * Read chunk is the unit sent to the user space. In contrast to write chunk it has variable length
 * and corresponds to exactly one read request.
 */
struct read_chunk
{
	// Part of the list.
	struct list_head list;

	// First sector of the read.
	size_t sector;

	// Length of the read in sectors.
	size_t len;

	// Offset in the shared memory where the chunk starts.
	size_t shmem_offset;

	// Pointer to cmd which has to acknowledged when this chunk is acknowledged.
	struct buse_cmd *cmd;
};

/*
 * Write queue structure.
 */
struct buse_wqueue
{
	// Pointer to the main buse structure.
	struct buse *buse;

	// Pointer to the corresponding struct queue
	struct buse_queue *q;

	// Character device corresponding to the read queue.
	struct buse_chrdev chrdev;

	// Shared memory area between kernel and user space.
	void *shmem;
	size_t size;

	// Flag whether individual queue is bound, i.e. the character device is opened and mmaped.
	atomic_t bound;

	// Waitqueue on the event when no busy chunk is available, i.e. there is nothing to send to
	// the userspace.
	wait_queue_head_t busy_chunks_avail;

	// Waitqueue on the event when no free chunk is available, i.e. there is no space to process
	// additional reads.
	wait_queue_head_t free_chunks_avail;

	// Array of all write chunks.
	struct write_chunk *chunks;

	// Lock per the whole write queue.
	struct mutex lock;


	// Queue keeping track of free write chunks.
	struct list_head free_chunks;

	// Queue with chunks ready to be sent to user space.
	struct list_head busy_chunks;

	// Queue with chunks already sent to user space. Important when user space side crashes to
	// rerun not acknowledged but fetched writes again.
	struct list_head fetched_chunks;

	// Currently active chunk in the individual queue. All writes are going to this chunk.
	struct write_chunk *active_chunk;

	// If true the termination chunk was already sent to user space and no other chunk can be
	// processed by the other end of the queue.
	bool terminated;
};

/*
 * Putting read and write queues together and assign them id. Just for convenience and easier
 * debugging.
 */
struct buse_queue
{
	struct buse_rqueue r;
	struct buse_wqueue w;
	size_t id;
};

/*
 * Request extension to be insertable to the list.
 */
struct rq_node
{
	struct list_head list;
	struct request *rq;
};

/*
 * Custom cmd which is allocated for each cmd comming from the blk-mq queue. It contains
 */
struct buse_cmd
{
	// Magic number to be more sure we read the right memory.
	u8 magic;

	// Corresponding request to the cmd.
	struct request *rq;

	// Queue where the request arrived.
	struct buse_queue *queue;

	// True if some operation failed and at the end the cmd should be canceled and report it to
	// the blk-mq.
	bool canceled;

	// Helper fields for different types of commands.
	union {
		struct {
			// How many more queues need to do their check for read after write hazard.
			atomic_t queues_pending;

			// How many writes need to be acknowledged until the read can be send to
			// user space.
			atomic_t write_deps;
		} read;

		struct {
			// How many more queues need to send the flush chunk. This is used when
			// broadcasting flush command.
			atomic_t queues_pending;
		} flush;
	};
};

/*
 * Helper for passing arguments when creating new thread.
 */
struct cmd_q_args
{
	struct buse_cmd *cmd;
	struct buse_queue *q;
};

// Adds new buse device with given index.
struct buse *buse_add(uint index);

// Delete buse device.
void buse_del(struct buse *buse);

// Turns on buse.
int buse_on(struct buse *buse);

// Turns off buse. Cannot be started again.
int buse_off(struct buse *buse);

// Stops buse. No io requests are accepted but can be started again.
void buse_stop(struct buse *buse);

// Checks if all queues are connected and if they are it creates the block device and is ready to
// serve io commands.
void buse_blkdev_init_cond(struct buse *buse);

#endif
