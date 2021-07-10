/* Copyright (C) 2021 Vojtech Aschenbrenner <v@asch.cz> */

#ifndef BUSE_CONFIGFS_H
#define BUSE_CONFIGFS_H

/*
 * Initialize configfs subsystem. Later on it is used for all the operation with the kernel module.
 */
int buse_configfs_init(void);

/*
 * Deinit of configfs.
 */
void buse_configfs_exit(void);

#endif
