/* Copyright (C) 2021 Vojtech Aschenbrenner <v@asch.cz> */

#include <linux/blkdev.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include "buse-blkdev.h"
#include "buse-chrdev.h"
#include "buse-rqueue.h"
#include "buse-wqueue.h"
#include "main.h"

/*
 * Callback for mmap(). It is reserved for future usage.
 */
static void vm_open(struct vm_area_struct *vma)
{
}

/*
 * Callback for munap(). It is reserved for future usage.
 */
static void vm_close(struct vm_area_struct *vma)
{
}

/*
 * VM fault callback for write queue. First pass through the shared memory generates faults and
 * fills the address mapping.
 */
static vm_fault_t vm_fault_wqueue(struct vm_fault *vmf)
{
	struct buse_wqueue *wq = vmf->vma->vm_private_data;
	pgoff_t offset = vmf->pgoff << PAGE_SHIFT;
	struct page *page;

	if (offset >= wq->buse->write_shm_size)
		return -EFAULT;

	page = vmalloc_to_page(wq->shmem + offset);

	get_page(page);
	vmf->page = page;

	return 0;
}

/*
 * VM fault callback for read queue. First pass through the shared memory generates faults and fills
 * the address mapping.
 */
static vm_fault_t vm_fault_rqueue(struct vm_fault *vmf)
{
	struct buse_rqueue *rq = vmf->vma->vm_private_data;
	pgoff_t offset = vmf->pgoff << PAGE_SHIFT;
	struct page *page;

	if (offset >= rq->buse->write_shm_size)
		return -EFAULT;

	page = vmalloc_to_page(rq->shmem + offset);

	get_page(page);
	vmf->page = page;

	return 0;
}

struct buse_wqueue *inode_get_wqueue(struct inode *inode)
{
	return container_of(inode->i_cdev, struct buse_wqueue, chrdev.cdev);
}

struct buse_rqueue *inode_get_rqueue(struct inode *inode)
{
	return container_of(inode->i_cdev, struct buse_rqueue, chrdev.cdev);
}

/*
 * File close() callback for write queue. We immediately set that the queue is unbound.
 */
static int chrdev_release_wqueue(struct inode *inode, struct file *file)
{
	struct buse_wqueue *wq = inode_get_wqueue(inode);
	if (!wq || atomic_read(&wq->bound) == 0)
		return -EFAULT;

	atomic_set(&wq->bound, 0);

	return 0;
}

/*
 * File close() callback for read queue. We immediately set that the queue is unbound.
 */
static int chrdev_release_rqueue(struct inode *inode, struct file *file)
{
	struct buse_rqueue *rq = inode_get_rqueue(inode);
	if (!rq || atomic_read(&rq->bound) == 0)
		return -EFAULT;

	atomic_set(&rq->bound, 0);

	return 0;
}

/*
 * File open() callback for write queue. We immediately set that the queue is bound.
 */
static int chrdev_open_wqueue(struct inode *inode, struct file *file)
{
	struct buse_wqueue *wq = inode_get_wqueue(inode);
	if (!wq || atomic_read(&wq->bound) == 1)
		return -EFAULT;

	file->private_data = wq;
	buse_wqueue_bind(wq);

	return 0;
}

/*
 * File open() callback for read queue. We immediately set that the queue is bound.
 */
static int chrdev_open_rqueue(struct inode *inode, struct file *file)
{
	struct buse_rqueue *rq = inode_get_rqueue(inode);
	if (!rq || atomic_read(&rq->bound) == 1)
		return -EFAULT;

	file->private_data = rq;
	buse_rqueue_bind(rq);

	return 0;
}

static struct vm_operations_struct vm_ops_wqueue = {
	.close = vm_close,
	.fault = vm_fault_wqueue,
	.open = vm_open,
};

static struct vm_operations_struct vm_ops_rqueue = {
	.close = vm_close,
	.fault = vm_fault_rqueue,
	.open = vm_open,
};

/*
 * File mmap() callback for write queue.
 */
static int chrdev_mmap_wqueue(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &vm_ops_wqueue;
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_private_data = file->private_data;
	vm_open(vma);

	return 0;
}

/*
 * File mmap() callback for read queue.
 */
static int chrdev_mmap_rqueue(struct file *file, struct vm_area_struct *vma)
{
	vma->vm_ops = &vm_ops_rqueue;
	vma->vm_flags |= VM_DONTEXPAND | VM_DONTDUMP;
	vma->vm_private_data = file->private_data;
	vm_open(vma);

	return 0;
}

/*
 * File write() callback for read queue. Writing to the read queue character device the userspace
 * acknowledge that the read request is done. The written value is offset to the shared memory.
 */
ssize_t chrdev_write_rqueue(struct file *file, const char __user *buf, size_t len, loff_t *off)
{
	u64 data_offset;
	unsigned long ret;
	struct buse_rqueue *rq = inode_get_rqueue(file->f_inode);

	if (len != 8) {
		BUG();
		return 0;
	}

	if (*off != 0) {
		BUG();
		return 0;
	}

	ret = copy_from_user(&data_offset, buf, len);
	if (ret) {
		pr_alert("Cannot copy\n");
		return -ENOMEM;
	}

	ack_read_request(rq, data_offset, false);

	*off = 0;

	return len;
}

/*
 * File write() callback for write queue. Writing to the write queue character device the userspace
 * acknowledge that the write chunk was processed. The written value is offset to the shared memory.
 */
ssize_t chrdev_write_wqueue(struct file *file, const char __user *buf, size_t len, loff_t *off)
{
	u64 chunk_offset;
	struct buse_wqueue *wq = inode_get_wqueue(file->f_inode);
	unsigned long ret = copy_from_user(&chunk_offset, buf, len);

	if (len != 8) {
		BUG();
		return 0;
	}

	if (*off != 0) {
		BUG();
		return 0;
	}

	if (ret) {
		pr_alert("Cannot copy\n");
		return -ENOMEM;
	}

	ack_write_request(wq, chunk_offset, false);

	return len;
}

/*
 * File read() callback for write queue. Userspace reads metadata about the write chunk coming to
 * the block device. It is number of batched writes in the chunk and offset to the shared memory
 * where the chunks is located.
 */
ssize_t chrdev_read_wqueue(struct file *file, char __user *buf, size_t len, loff_t *off)
{
	struct write_chunk *chunk;
	int ret;
	struct buse_wqueue *wq = inode_get_wqueue(file->f_inode);

	if (len != 16) {
		BUG();
		return 0;
	}

	if (*off != 0) {
		BUG();
		return 0;
	}

	chunk = pop_write_request_wait(wq);
	if (IS_ERR(chunk)) {
		return PTR_ERR(chunk);
	}

	ret = copy_to_user(buf, &chunk->shmem_offset, sizeof(chunk->shmem_offset));
	buf += sizeof(chunk->shmem_offset);
	if (ret) {
		pr_alert("copy_to_user failed\n");
		return -EFAULT;
	}

	ret = copy_to_user(buf, &chunk->num_writes, sizeof(chunk->num_writes));
	if (ret) {
		pr_alert("copy_to_user failed\n");
		return -EFAULT;
	}

	if (is_wqueue_term(chunk))
		kfree(chunk);

	return len;
}

/*
 * File read() callback for read queue. Userspace reads metadata about the read request coming to
 * the block device and offset to the shared memory where data should be read into.
 */
ssize_t chrdev_read_rqueue(struct file *file, char __user *buf, size_t len, loff_t *off)
{
	struct buse_rqueue *rq = inode_get_rqueue(file->f_inode);
	struct read_chunk *chunk;
	int ret;

	if (len != 24) {
		BUG();
		return 0;
	}

	if (*off != 0) {
		BUG();
		return 0;
	}

	chunk = pop_read_request_wait(rq);
	if (IS_ERR(chunk)) {
		return PTR_ERR(chunk);
	}

	ret = copy_to_user(buf, &chunk->sector, sizeof(chunk->sector));
	buf += sizeof(chunk->sector);
	if (ret) {
		pr_alert("copy_to_user failed\n");
		return -EFAULT;
	}

	ret = copy_to_user(buf, &chunk->len, sizeof(chunk->len));
	buf += sizeof(chunk->len);
	if (ret) {
		pr_alert("copy_to_user failed\n");
		return -EFAULT;
	}

	ret = copy_to_user(buf, &chunk->shmem_offset, sizeof(chunk->shmem_offset));
	buf += sizeof(chunk->shmem_offset);
	if (ret) {
		pr_alert("copy_to_user failed\n");
		return -EFAULT;
	}

	if (is_rqueue_term(chunk))
		kfree(chunk);

	return len;
}

const struct file_operations chrdev_fops_wqueue = {
	.mmap = chrdev_mmap_wqueue,
	.open = chrdev_open_wqueue,
	.owner = THIS_MODULE,
	.read = chrdev_read_wqueue,
	.write = chrdev_write_wqueue,
	.release = chrdev_release_wqueue,
};

const struct file_operations chrdev_fops_rqueue = {
	.mmap = chrdev_mmap_rqueue,
	.open = chrdev_open_rqueue,
	.owner = THIS_MODULE,
	.read = chrdev_read_rqueue,
	.write = chrdev_write_rqueue,
	.release = chrdev_release_rqueue,
};

/*
 * Init one character device corresponding to one of the queues.
 */
static int chrdev_queue_init(struct buse_chrdev *chrdev, dev_t minor, char *name,
		int i, const struct file_operations *fops)
{
	int ret;

	chrdev->region = minor;
	cdev_init(&chrdev->cdev, fops);
	ret = cdev_add(&chrdev->cdev, minor, 1);
	if (ret < 0)
		goto err;

	chrdev->dev = device_create(buse_chrdev_class, NULL, minor, NULL,"%s%d", name, i);
	if (IS_ERR(chrdev->dev)) {
		ret = PTR_ERR(chrdev->dev);
		goto err_cdev;
	}

	return 0;

err_cdev:
	cdev_del(&chrdev->cdev);
err:
	return ret;
}

static void chrdev_queue_exit(struct buse_chrdev *chrdev)
{
	device_destroy(buse_chrdev_class, chrdev->region);
	cdev_del(&chrdev->cdev);
}

/*
 * Deallocated read queues related character devices.
 */
static void chrdev_rqueues_exit(struct buse *buse)
{
	int i;
	struct buse_queue *q = buse->queues;
	struct buse_rqueue *rq;
	dev_t minor;

	for (i = 0, q = buse->queues; i < buse->num_queues; i++, q++) {
		rq = &q->r;
		minor = rq->chrdev.region;
		chrdev_queue_exit(&rq->chrdev);
	}

	minor -= buse->num_queues - 1;
	unregister_chrdev_region(minor, buse->num_queues);
}

/*
 * Deallocated write queues related character devices.
 */
static void chrdev_wqueues_exit(struct buse *buse)
{
	int i;
	struct buse_queue *q = buse->queues;
	struct buse_wqueue *wq;
	dev_t minor;

	for (i = 0, q = buse->queues; i < buse->num_queues; i++, q++) {
		wq = &q->w;
		minor = wq->chrdev.region;
		chrdev_queue_exit(&wq->chrdev);
	}

	minor -= buse->num_queues - 1;
	unregister_chrdev_region(minor, buse->num_queues);
}

/*
 * Allocate read queues related character devices.
 */
static int chrdev_rqueues_init(struct buse *buse)
{
	int ret, i;
	struct buse_queue *q;
	struct buse_rqueue *rq;
	dev_t minor;
	char name[DISK_NAME_LEN];
	snprintf(name, DISK_NAME_LEN, "%s%llu-r", buse_blkdev_name, buse->index);

	ret = alloc_chrdev_region(&minor, 0, buse->num_queues, name);
	if (ret < 0)
		goto err;

	for (i = 0, q = buse->queues; i < buse->num_queues; i++, q++, minor++) {
		rq = &q->r;
		ret = chrdev_queue_init(&rq->chrdev, minor, name, i, &chrdev_fops_rqueue);
		if (ret)
			goto err_alloc;
	}

	return 0;

err_alloc:
	for (; i > 0; i--, q--, minor--) {
		rq = &q->r;
		chrdev_queue_exit(&rq->chrdev);
	}

	unregister_chrdev_region(minor, buse->num_queues);
err:
	return ret;
}

/*
 * Allocate write queues related character devices.
 */
static int chrdev_wqueues_init(struct buse *buse)
{
	int ret, i;
	struct buse_queue *q;
	struct buse_wqueue *wq;
	dev_t minor;
	char name[DISK_NAME_LEN];
	snprintf(name, DISK_NAME_LEN, "%s%llu-w", buse_blkdev_name, buse->index);

	ret = alloc_chrdev_region(&minor, 0, buse->num_queues, name);
	if (ret < 0)
		goto err;

	for (i = 0, q = buse->queues; i < buse->num_queues; i++, q++, minor++) {
		wq = &q->w;
		ret = chrdev_queue_init(&wq->chrdev, minor, name, i, &chrdev_fops_wqueue);
		if (ret)
			goto err_alloc;
	}

	return 0;

err_alloc:
	for (; i > 0; i--, q--, minor--) {
		wq = &q->w;
		chrdev_queue_exit(&wq->chrdev);
	}

	unregister_chrdev_region(minor, buse->num_queues);
err:
	return ret;
}

/*
 * Init all needed character devices for queues to the userspace.
 */
int buse_chrdev_init(struct buse *buse)
{
	int ret;

	ret = chrdev_wqueues_init(buse);
	if (ret)
		goto err;

	ret = chrdev_rqueues_init(buse);
	if (ret)
		goto err_wqueues;

	return 0;

err_wqueues:
	chrdev_wqueues_exit(buse);
err:
	return ret;
}

void buse_chrdev_exit(struct buse *buse)
{
	chrdev_rqueues_exit(buse);
	chrdev_wqueues_exit(buse);
}
