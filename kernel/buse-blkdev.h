// Copyright (C) 2021 Vojtech Aschenbrenner <v@asch.cz>

#ifndef BUSE_BLKDEV_H
#define BUSE_BLKDEV_H

#include "main.h"

/*
 * Block device initialization. All configuration parameters are set according to the configured
 * values in struct buse. This is only related to the block device side of the module.
 */
int buse_blkdev_init(struct buse *buse);


/*
 * Remove the block device if it was created, otherwiese just cleanup tagset.
 */
void buse_blkdev_exit(struct buse *buse);


/*
 * Registers the block device so that it is visible to the system.
 */
void buse_gendisk_register(struct buse *buse);

/*
 * Returns numa node for given queue id.
 */
int buse_get_numa_node_for_queue_id(struct buse *buse, int queue_id);

#endif
