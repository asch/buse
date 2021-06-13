// Copyright (C) 2021 Vojtech Aschenbrenner <v@asch.cz>

/*
 * This module contains all configfs related configuration. Every configfs attribute needs to define:
 *
 * 1) buse_`attr`_show() function returning the current value.
 *
 * 2) buse_`attr`_store() setting the value and eventually doing function calls.
 *
 * 3) define macro CONFIGFS_ATTR(buse_, `attr`);
 *
 * 4) put &buse_attr_`attr` record to the buse_attrs[]
 *
 * This process can be a bit repetitive for some attributes, but we keep it like that for better
 * control over allowed inserted values and not obfuscating the code with unclean macros.
 */

#include <linux/configfs.h>
#include "buse-configfs.h"
#include "linux/blk-mq.h"
#include "linux/err.h"
#include "linux/kernel.h"
#include "main.h"
#include "buse-wqueue.h"
#include "buse-rqueue.h"

static inline struct buse *to_buse(struct config_item *item)
{
	return item ? container_of(item, struct buse, item) : NULL;
}

static ssize_t buse_power_show(struct config_item *item, char *page)
{
	struct buse *buse = to_buse(item);

	return snprintf(page, PAGE_SIZE, "%d\n", buse->power);
}

static ssize_t buse_power_store(struct config_item *item, const char *page, size_t count)
{
	struct buse *buse = to_buse(item);
	int ret;
	bool power;
	int i;
	struct buse_wqueue *wq;
	struct buse_rqueue *rq;

	ret = kstrtobool(page, &power);
	if (ret)
		goto err;

	mutex_lock(&buse->configfs_mutex);

	if (power == buse->power) {
		ret = -EINVAL;
		goto err_mutex;
	}

	atomic_set(&buse->stopped, !power);

	if (!power)
		buse_stop(buse);

	if (power && buse->queues) {
		for (i = 0; i < buse->num_queues; i++) {
			wq = &buse->queues[i].w;
			mutex_lock(&wq->lock);
			wq->terminated = false;
			mutex_unlock(&wq->lock);
		}

		for (i = 0; i < buse->num_queues; i++) {
			rq = &buse->queues[i].r;
			mutex_lock(&rq->lock);
			rq->terminated = false;
			mutex_unlock(&rq->lock);
		}
	}

	if (power && !buse->queues) {
		ret = buse_on(buse);
		if (ret)
			goto err_mutex;
	}

	buse->power = power;
	ret = count;

err_mutex:
	mutex_unlock(&buse->configfs_mutex);
err:
	return ret;
}

CONFIGFS_ATTR(buse_, power);

static ssize_t buse_hw_queues_show(struct config_item *item, char *page)
{
	struct buse *buse = to_buse(item);

	return snprintf(page, PAGE_SIZE, "%llu\n", buse->hw_queues);
}

static ssize_t buse_hw_queues_store(struct config_item *item, const char *page, size_t count)
{
	struct buse *buse = to_buse(item);
	int ret;
	u64 hw_queues;

	if (buse->power)
		return -EBUSY;

	ret = kstrtou64(page, 0, &hw_queues);
	if (ret)
		goto err;

	buse->hw_queues = hw_queues;

	return count;

err:
	return ret;
}

CONFIGFS_ATTR(buse_, hw_queues);

static ssize_t buse_queue_depth_show(struct config_item *item, char *page)
{
	struct buse *buse = to_buse(item);

	return snprintf(page, PAGE_SIZE, "%llu\n", buse->queue_depth);
}

static ssize_t buse_queue_depth_store(struct config_item *item, const char *page, size_t count)
{
	struct buse *buse = to_buse(item);
	int ret;
	u64 queue_depth;

	if (buse->power)
		return -EBUSY;

	ret = kstrtou64(page, 0, &queue_depth);
	if (ret)
		goto err;

	buse->queue_depth = queue_depth;

	return count;

err:
	return ret;
}

CONFIGFS_ATTR(buse_, queue_depth);

static ssize_t buse_can_write_same_show(struct config_item *item, char *page)
{
	struct buse *buse = to_buse(item);

	return snprintf(page, PAGE_SIZE, "%d\n", buse->can_write_same);
}

static ssize_t buse_can_write_same_store(struct config_item *item, const char *page, size_t count)
{
	struct buse *buse = to_buse(item);
	int ret;
	bool can_write_same;

	if (buse->power)
		return -EBUSY;

	ret = kstrtobool(page, &can_write_same);
	if (ret)
		goto err;

	buse->can_write_same = can_write_same;

	return count;

err:
	return ret;
}

CONFIGFS_ATTR(buse_, can_write_same);

static ssize_t buse_can_write_zeroes_show(struct config_item *item, char *page)
{
	struct buse *buse = to_buse(item);

	return snprintf(page, PAGE_SIZE, "%d\n", buse->can_write_zeroes);
}

static ssize_t buse_can_write_zeroes_store(struct config_item *item, const char *page, size_t count)
{
	struct buse *buse = to_buse(item);
	int ret;
	bool can_write_zeroes;

	if (buse->power)
		return -EBUSY;

	ret = kstrtobool(page, &can_write_zeroes);
	if (ret)
		goto err;

	buse->can_write_zeroes = can_write_zeroes;

	return count;

err:
	return ret;
}

CONFIGFS_ATTR(buse_, can_write_zeroes);

static ssize_t buse_can_discard_show(struct config_item *item, char *page)
{
	struct buse *buse = to_buse(item);

	return snprintf(page, PAGE_SIZE, "%d\n", buse->can_discard);
}

static ssize_t buse_can_discard_store(struct config_item *item, const char *page, size_t count)
{
	struct buse *buse = to_buse(item);
	int ret;
	bool can_discard;

	if (buse->power)
		return -EBUSY;

	ret = kstrtobool(page, &can_discard);
	if (ret)
		goto err;

	buse->can_discard = can_discard;

	return count;

err:
	return ret;
}

CONFIGFS_ATTR(buse_, can_discard);

static ssize_t buse_can_secure_erase_show(struct config_item *item, char *page)
{
	struct buse *buse = to_buse(item);

	return snprintf(page, PAGE_SIZE, "%d\n", buse->can_secure_erase);
}

static ssize_t buse_can_secure_erase_store(struct config_item *item, const char *page, size_t count)
{
	struct buse *buse = to_buse(item);
	int ret;
	bool can_secure_erase;

	if (buse->power)
		return -EBUSY;

	ret = kstrtobool(page, &can_secure_erase);
	if (ret)
		goto err;

	buse->can_secure_erase = can_secure_erase;

	return count;

err:
	return ret;
}

CONFIGFS_ATTR(buse_, can_secure_erase);

static ssize_t buse_no_scheduler_show(struct config_item *item, char *page)
{
	struct buse *buse = to_buse(item);

	return snprintf(page, PAGE_SIZE, "%d\n", buse->no_scheduler);
}

static ssize_t buse_no_scheduler_store(struct config_item *item, const char *page, size_t count)
{
	struct buse *buse = to_buse(item);
	int ret;
	bool no_scheduler;

	if (buse->power)
		return -EBUSY;

	ret = kstrtobool(page, &no_scheduler);
	if (ret)
		goto err;

	buse->no_scheduler = no_scheduler;

	return count;

err:
	return ret;
}

CONFIGFS_ATTR(buse_, no_scheduler);

static ssize_t buse_read_shm_size_show(struct config_item *item, char *page)
{
	struct buse *buse = to_buse(item);

	return snprintf(page, PAGE_SIZE, "%llu\n", buse->read_shm_size);
}

static ssize_t buse_read_shm_size_store(struct config_item *item, const char *page, size_t count)
{
	struct buse *buse = to_buse(item);
	int ret;
	u64 read_shm_size;

	if (buse->power)
		return -EBUSY;

	ret = kstrtou64(page, 0, &read_shm_size);
	if (ret)
		goto err;

	buse->read_shm_size = read_shm_size;

	return count;

err:
	return ret;
}

CONFIGFS_ATTR(buse_, read_shm_size);

static ssize_t buse_write_shm_size_show(struct config_item *item, char *page)
{
	struct buse *buse = to_buse(item);

	return snprintf(page, PAGE_SIZE, "%llu\n", buse->write_shm_size);
}

static ssize_t buse_write_shm_size_store(struct config_item *item, const char *page, size_t count)
{
	struct buse *buse = to_buse(item);
	int ret;
	u64 write_shm_size;

	if (buse->power)
		return -EBUSY;

	ret = kstrtou64(page, 0, &write_shm_size);
	if (ret)
		goto err;

	buse->write_shm_size = write_shm_size;;

	return count;

err:
	return ret;
}

CONFIGFS_ATTR(buse_, write_shm_size);

static ssize_t buse_write_chunk_size_show(struct config_item *item, char *page)
{
	struct buse *buse = to_buse(item);

	return snprintf(page, PAGE_SIZE, "%llu\n", buse->write_chunk_size);
}

static ssize_t buse_write_chunk_size_store(struct config_item *item, const char *page, size_t count)
{
	struct buse *buse = to_buse(item);
	int ret;
	u64 write_chunk_size;

	if (buse->power)
		return -EBUSY;

	ret = kstrtou64(page, 0, &write_chunk_size);
	if (ret)
		goto err;

	buse->write_chunk_size = write_chunk_size;

	return count;

err:
	return ret;
}

CONFIGFS_ATTR(buse_, write_chunk_size);

static ssize_t buse_blocksize_show(struct config_item *item, char *page)
{
	struct buse *buse = to_buse(item);

	return snprintf(page, PAGE_SIZE, "%llu\n", buse->block_size);
}

static ssize_t buse_blocksize_store(struct config_item *item, const char *page, size_t count)
{
	struct buse *buse = to_buse(item);
	int ret;
	u64 blocksize;

	if (buse->power)
		return -EBUSY;

	ret = kstrtou64(page, 0, &blocksize);
	if (ret)
		goto err;

	buse->block_size = blocksize;

	return count;

err:
	return ret;
}

CONFIGFS_ATTR(buse_, blocksize);

static ssize_t buse_size_show(struct config_item *item, char *page)
{
	struct buse *buse = to_buse(item);

	return snprintf(page, PAGE_SIZE, "%llu\n", buse->size);
}

static ssize_t buse_size_store(struct config_item *item, const char *page, size_t count)
{
	struct buse *buse = to_buse(item);
	int ret;
	u64 size;

	if (buse->power)
		return -EBUSY;

	ret = kstrtou64(page, 0, &size);
	if (ret)
		goto err;

	buse->size = size;

	return count;

err:
	return ret;
}

CONFIGFS_ATTR(buse_, size);

static ssize_t buse_collision_area_size_show(struct config_item *item, char *page)
{
	struct buse *buse = to_buse(item);

	return snprintf(page, PAGE_SIZE, "%llu\n", buse->collision_area_size);
}

static ssize_t buse_collision_area_size_store(struct config_item *item, const char *page, size_t count)
{
	struct buse *buse = to_buse(item);
	int ret;
	u64 collision_area_size;

	if (buse->power)
		return -EBUSY;

	ret = kstrtou64(page, 0, &collision_area_size);
	if (ret)
		goto err;

	if (collision_area_size % buse->block_size != 0 ||
			collision_area_size > buse->size)
		collision_area_size = buse->block_size;

	buse->collision_area_size = collision_area_size;

	return count;

err:
	return ret;
}

CONFIGFS_ATTR(buse_, collision_area_size);

static struct configfs_attribute *buse_attrs[] = {
	&buse_attr_collision_area_size,
	&buse_attr_size,
	&buse_attr_blocksize,
	&buse_attr_write_chunk_size,
	&buse_attr_write_shm_size,
	&buse_attr_read_shm_size,
	&buse_attr_hw_queues,
	&buse_attr_queue_depth,
	&buse_attr_no_scheduler,
	&buse_attr_can_secure_erase,
	&buse_attr_can_write_same,
	&buse_attr_can_write_zeroes,
	&buse_attr_can_discard,
	&buse_attr_power,
	NULL,
};

static void buse_release(struct config_item *item)
{
	struct buse *buse = to_buse(item);

	if (buse->power)
		return;
}

static struct configfs_item_operations buse_ops = {
	.release	= buse_release,
};

static const struct config_item_type buse_type = {
	.ct_item_ops	= &buse_ops,
	.ct_attrs	= buse_attrs,
	.ct_owner	= THIS_MODULE,
};

static struct config_item *buse_group_make_item(struct config_group *group, const char *name)
{
	struct buse *buse;
	uint index;
	int ret;

	ret = kstrtouint(name, 0, &index);
	if (ret < 0)
		return ERR_PTR(ret);

	buse = buse_add(index);
	if (IS_ERR(buse))
		return ERR_PTR(-ENOMEM);

	config_item_init_type_name(&buse->item, name, &buse_type);

	return &buse->item;
}

static void buse_group_drop_item(struct config_group *group, struct config_item *item)
{
	struct buse *buse = to_buse(item);

	mutex_lock(&buse->configfs_mutex);

	if (buse->power)
		goto err;

	buse_off(buse);
	buse_del(buse);
	config_item_put(item);

err:
	mutex_unlock(&buse->configfs_mutex);
}

static struct configfs_group_operations buse_group_ops = {
	.make_item	= buse_group_make_item,
	.drop_item	= buse_group_drop_item,
};

static const struct config_item_type buse_group_type = {
	.ct_group_ops	= &buse_group_ops,
	.ct_owner	= THIS_MODULE,
};

static struct configfs_subsystem buse_subsys = {
	.su_group = {
		.cg_item = {
			.ci_namebuf = "buse",
			.ci_type = &buse_group_type,
		},
	},
};

/*
 * Initialize configfs subsystem. Later on it is used for all the operation with the kernel module.
 */
int buse_configfs_init(void)
{
	int ret;

	config_group_init(&buse_subsys.su_group);
	mutex_init(&buse_subsys.su_mutex);
	ret = configfs_register_subsystem(&buse_subsys);
	if (ret)
		goto err;

	return 0;

err:
	return ret;
}

/*
 * Deinit of configfs.
 */
void buse_configfs_exit(void)
{
	configfs_unregister_subsystem(&buse_subsys);
}
