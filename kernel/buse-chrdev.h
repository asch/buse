// Copyright (C) 2021 Vojtech Aschenbrenner <v@asch.cz>

#ifndef BUSE_CHRDEV_H
#define BUSE_CHRDEV_H

#include <linux/cdev.h>
#include "main.h"

/*
 * Init all needed character devices for queues to the userspace.
 */
int buse_chrdev_init(struct buse *buse);

void buse_chrdev_exit(struct buse *buse);

#endif
