#include "basic.h"

static inline struct basicmmfs_sb_info *get_sb_info(struct kobject *kobj)
{
	return container_of(kobj, struct basicmmfs_sb_info, kobj);
}

static ssize_t stats_show(struct kobject *kobj, struct kobj_attribute *attr,
		char *buf)
{
	int count = 0;
	struct basicmmfs_sb_info *sbi = get_sb_info(kobj);

	count += sprintf(buf, "Total Pages: %lld\n", sbi->num_pages);
	count += sprintf(&buf[count], "Free Pages: %lld\n", sbi->free_pages);

	return count;
}

static ssize_t stats_store(struct kobject *kobj, struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	return -EINVAL;
}
static struct kobj_attribute stats_attr =
__ATTR(stats, 0444, stats_show, stats_store);

static struct attribute *basicmmfs_attr[] = {
	&stats_attr.attr,
	NULL,
};

const struct attribute_group basicmmfs_attr_group = {
	.attrs = basicmmfs_attr,
};

static void empty_release(struct kobject *kobj) {}

const struct kobj_type basicmmfs_kobj_ktype = {
	.release 	= empty_release,
	.sysfs_ops 	= &kobj_sysfs_ops,
};
