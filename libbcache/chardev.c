#include "bcache.h"
#include "super.h"
#include "super-io.h"

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/major.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/bcache-ioctl.h>

static long bch_ioctl_assemble(struct bch_ioctl_assemble __user *user_arg)
{
	struct bch_ioctl_assemble arg;
	const char *err;
	u64 *user_devs = NULL;
	char **devs = NULL;
	unsigned i;
	int ret = -EFAULT;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	if (arg.flags || arg.pad)
		return -EINVAL;

	user_devs = kmalloc_array(arg.nr_devs, sizeof(u64), GFP_KERNEL);
	if (!devs)
		return -ENOMEM;

	devs = kcalloc(arg.nr_devs, sizeof(char *), GFP_KERNEL);

	if (copy_from_user(user_devs, user_arg->devs,
			   sizeof(u64) * arg.nr_devs))
		goto err;

	for (i = 0; i < arg.nr_devs; i++) {
		devs[i] = strndup_user((const char __user *)(unsigned long)
				       user_devs[i],
				       PATH_MAX);
		if (!devs[i]) {
			ret = -ENOMEM;
			goto err;
		}
	}

	err = bch_fs_open(devs, arg.nr_devs, bch_opts_empty(), NULL);
	if (err) {
		pr_err("Could not open filesystem: %s", err);
		ret = -EINVAL;
		goto err;
	}

	ret = 0;
err:
	if (devs)
		for (i = 0; i < arg.nr_devs; i++)
			kfree(devs[i]);
	kfree(devs);
	return ret;
}

static long bch_ioctl_incremental(struct bch_ioctl_incremental __user *user_arg)
{
	struct bch_ioctl_incremental arg;
	const char *err;
	char *path;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	if (arg.flags || arg.pad)
		return -EINVAL;

	path = strndup_user((const char __user *)(unsigned long) arg.dev, PATH_MAX);
	if (!path)
		return -ENOMEM;

	err = bch_fs_open_incremental(path);
	kfree(path);

	if (err) {
		pr_err("Could not register bcache devices: %s", err);
		return -EINVAL;
	}

	return 0;
}

static long bch_global_ioctl(unsigned cmd, void __user *arg)
{
	switch (cmd) {
	case BCH_IOCTL_ASSEMBLE:
		return bch_ioctl_assemble(arg);
	case BCH_IOCTL_INCREMENTAL:
		return bch_ioctl_incremental(arg);
	default:
		return -ENOTTY;
	}
}

static long bch_ioctl_query_uuid(struct bch_fs *c,
			struct bch_ioctl_query_uuid __user *user_arg)
{
	return copy_to_user(&user_arg->uuid,
			    &c->sb.user_uuid,
			    sizeof(c->sb.user_uuid));
}

static long bch_ioctl_start(struct bch_fs *c, struct bch_ioctl_start __user *user_arg)
{
	struct bch_ioctl_start arg;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	if (arg.flags || arg.pad)
		return -EINVAL;

	return bch_fs_start(c) ? -EIO : 0;
}

static long bch_ioctl_stop(struct bch_fs *c)
{
	bch_fs_stop(c);
	return 0;
}

/* returns with ref on ca->ref */
static struct bch_dev *bch_device_lookup(struct bch_fs *c,
					 const char __user *dev)
{
	struct block_device *bdev;
	struct bch_dev *ca;
	char *path;
	unsigned i;

	path = strndup_user(dev, PATH_MAX);
	if (!path)
		return ERR_PTR(-ENOMEM);

	bdev = lookup_bdev(strim(path));
	kfree(path);
	if (IS_ERR(bdev))
		return ERR_CAST(bdev);

	for_each_member_device(ca, c, i)
		if (ca->disk_sb.bdev == bdev)
			goto found;

	ca = NULL;
found:
	bdput(bdev);
	return ca;
}

#if 0
static struct bch_member *bch_uuid_lookup(struct bch_fs *c, uuid_le uuid)
{
	struct bch_sb_field_members *mi = bch_sb_get_members(c->disk_sb);
	unsigned i;

	lockdep_assert_held(&c->sb_lock);

	for (i = 0; i < c->disk_sb->nr_devices; i++)
		if (!memcmp(&mi->members[i].uuid, &uuid, sizeof(uuid)))
			return &mi->members[i];

	return NULL;
}
#endif

static long bch_ioctl_disk_add(struct bch_fs *c,
			       struct bch_ioctl_disk __user *user_arg)
{
	struct bch_ioctl_disk arg;
	char *path;
	int ret;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	if (arg.flags || arg.pad)
		return -EINVAL;

	path = strndup_user((const char __user *)(unsigned long) arg.dev, PATH_MAX);
	if (!path)
		return -ENOMEM;

	ret = bch_dev_add(c, path);
	kfree(path);

	return ret;
}

static long bch_ioctl_disk_remove(struct bch_fs *c,
				  struct bch_ioctl_disk __user *user_arg)
{
	struct bch_ioctl_disk arg;
	struct bch_dev *ca;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	ca = bch_device_lookup(c, (const char __user *)(unsigned long) arg.dev);
	if (IS_ERR(ca))
		return PTR_ERR(ca);

	return bch_dev_remove(c, ca, arg.flags);
}

static long bch_ioctl_disk_online(struct bch_fs *c,
				  struct bch_ioctl_disk __user *user_arg)
{
	struct bch_ioctl_disk arg;
	char *path;
	int ret;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	if (arg.flags || arg.pad)
		return -EINVAL;

	path = strndup_user((const char __user *)(unsigned long) arg.dev, PATH_MAX);
	if (!path)
		return -ENOMEM;

	ret = bch_dev_online(c, path);
	kfree(path);
	return ret;
}

static long bch_ioctl_disk_offline(struct bch_fs *c,
				   struct bch_ioctl_disk __user *user_arg)
{
	struct bch_ioctl_disk arg;
	struct bch_dev *ca;
	int ret;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	if (arg.pad)
		return -EINVAL;

	ca = bch_device_lookup(c, (const char __user *)(unsigned long) arg.dev);
	if (IS_ERR(ca))
		return PTR_ERR(ca);

	ret = bch_dev_offline(c, ca, arg.flags);
	percpu_ref_put(&ca->ref);
	return ret;
}

static long bch_ioctl_disk_set_state(struct bch_fs *c,
				     struct bch_ioctl_disk_set_state __user *user_arg)
{
	struct bch_ioctl_disk_set_state arg;
	struct bch_dev *ca;
	int ret;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	ca = bch_device_lookup(c, (const char __user *)(unsigned long) arg.dev);
	if (IS_ERR(ca))
		return PTR_ERR(ca);

	ret = bch_dev_set_state(c, ca, arg.new_state, arg.flags);

	percpu_ref_put(&ca->ref);
	return ret;
}

static long bch_ioctl_disk_evacuate(struct bch_fs *c,
				    struct bch_ioctl_disk __user *user_arg)
{
	struct bch_ioctl_disk arg;
	struct bch_dev *ca;
	int ret;

	if (copy_from_user(&arg, user_arg, sizeof(arg)))
		return -EFAULT;

	ca = bch_device_lookup(c, (const char __user *)(unsigned long) arg.dev);
	if (IS_ERR(ca))
		return PTR_ERR(ca);

	ret = bch_dev_evacuate(c, ca);

	percpu_ref_put(&ca->ref);
	return ret;
}

long bch_fs_ioctl(struct bch_fs *c, unsigned cmd, void __user *arg)
{
	/* ioctls that don't require admin cap: */
	switch (cmd) {
	case BCH_IOCTL_QUERY_UUID:
		return bch_ioctl_query_uuid(c, arg);
	}

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	/* ioctls that do require admin cap: */
	switch (cmd) {
	case BCH_IOCTL_START:
		return bch_ioctl_start(c, arg);
	case BCH_IOCTL_STOP:
		return bch_ioctl_stop(c);

	case BCH_IOCTL_DISK_ADD:
		return bch_ioctl_disk_add(c, arg);
	case BCH_IOCTL_DISK_REMOVE:
		return bch_ioctl_disk_remove(c, arg);
	case BCH_IOCTL_DISK_ONLINE:
		return bch_ioctl_disk_online(c, arg);
	case BCH_IOCTL_DISK_OFFLINE:
		return bch_ioctl_disk_offline(c, arg);
	case BCH_IOCTL_DISK_SET_STATE:
		return bch_ioctl_disk_set_state(c, arg);
	case BCH_IOCTL_DISK_EVACUATE:
		return bch_ioctl_disk_evacuate(c, arg);

	default:
		return -ENOTTY;
	}
}

static long bch_chardev_ioctl(struct file *filp, unsigned cmd, unsigned long v)
{
	struct bch_fs *c = filp->private_data;
	void __user *arg = (void __user *) v;

	return c
		? bch_fs_ioctl(c, cmd, arg)
		: bch_global_ioctl(cmd, arg);
}

static const struct file_operations bch_chardev_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl = bch_chardev_ioctl,
	.open		= nonseekable_open,
};

static int bch_chardev_major;
static struct class *bch_chardev_class;
static struct device *bch_chardev;
static DEFINE_IDR(bch_chardev_minor);

void bch_fs_chardev_exit(struct bch_fs *c)
{
	if (!IS_ERR_OR_NULL(c->chardev))
		device_unregister(c->chardev);
	if (c->minor >= 0)
		idr_remove(&bch_chardev_minor, c->minor);
}

int bch_fs_chardev_init(struct bch_fs *c)
{
	c->minor = idr_alloc(&bch_chardev_minor, c, 0, 0, GFP_KERNEL);
	if (c->minor < 0)
		return c->minor;

	c->chardev = device_create(bch_chardev_class, NULL,
				   MKDEV(bch_chardev_major, c->minor), NULL,
				   "bcache%u-ctl", c->minor);
	if (IS_ERR(c->chardev))
		return PTR_ERR(c->chardev);

	return 0;
}

void bch_chardev_exit(void)
{
	if (!IS_ERR_OR_NULL(bch_chardev_class))
		device_destroy(bch_chardev_class,
			       MKDEV(bch_chardev_major, 255));
	if (!IS_ERR_OR_NULL(bch_chardev_class))
		class_destroy(bch_chardev_class);
	if (bch_chardev_major > 0)
		unregister_chrdev(bch_chardev_major, "bcache");
}

int __init bch_chardev_init(void)
{
	bch_chardev_major = register_chrdev(0, "bcache-ctl", &bch_chardev_fops);
	if (bch_chardev_major < 0)
		return bch_chardev_major;

	bch_chardev_class = class_create(THIS_MODULE, "bcache");
	if (IS_ERR(bch_chardev_class))
		return PTR_ERR(bch_chardev_class);

	bch_chardev = device_create(bch_chardev_class, NULL,
				    MKDEV(bch_chardev_major, 255),
				    NULL, "bcache-ctl");
	if (IS_ERR(bch_chardev))
		return PTR_ERR(bch_chardev);

	return 0;
}
