#include <linux/types.h>
#include <linux/file_only_mem.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/namei.h>

enum file_only_mem_state {
	FOM_OFF = 0,
	FOM_SINGLE_PROC = 1,
	FOM_ALL = 2
};

static enum file_only_mem_state fom_state = FOM_OFF;
static pid_t fom_proc = 0;
char file_dir[256];

bool use_file_only_mem(pid_t pid) {
	if (fom_state == FOM_OFF) {
		return false;
	} if (fom_state == FOM_SINGLE_PROC) {
		return pid == fom_proc;
	} else if (fom_state == FOM_ALL) {
		return true;
	}

	// Should never reach here
	return false;
}

///////////////////////////////////////////////////////////////////////////////
// sysfs files
static ssize_t fom_state_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", fom_state);
}

static ssize_t fom_state_store(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int state;
	int ret;

	ret = kstrtoint(buf, 0, &state);

	if (ret != 0) {
		fom_state = FOM_OFF;
		return ret;
	} else if (state >= FOM_OFF && state <= FOM_ALL) {
		fom_state = state;
		return count;
	} else {
		fom_state = FOM_OFF;
		return -EINVAL;
	}
}
static struct kobj_attribute fom_state_attribute =
__ATTR(state, 0644, fom_state_show, fom_state_store);

static ssize_t fom_pid_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", fom_proc);
}

static ssize_t fom_pid_store(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	pid_t pid;
	int ret;

	ret = kstrtoint(buf, 0, &pid);

	if (ret != 0) {
		fom_proc = 0;
		return ret;
	}

	fom_proc = pid;

	return count;
}
static struct kobj_attribute fom_pid_attribute =
__ATTR(pid, 0644, fom_pid_show, fom_pid_store);

static ssize_t fom_dir_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", file_dir);
}

static ssize_t fom_dir_store(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	struct path p;
	int err;

	if (count > sizeof(file_dir)) {
		memset(file_dir, 0, sizeof(file_dir));
		return -ENOMEM;
	}

	strncpy(file_dir, buf, sizeof(file_dir));

	// echo likes to put an extra \n at the end of the string
	// if it's there, remove it
	if (file_dir[count - 1] == '\n')
		file_dir[count - 1] = '\0';

	// Check if the given path is actually a valid directory
	err = kern_path(file_dir, LOOKUP_DIRECTORY, &p);

	if (err) {
		memset(file_dir, 0, sizeof(file_dir));
		return err;
	}

	return count;
}
static struct kobj_attribute fom_file_dir_attribute =
__ATTR(file_dir, 0644, fom_dir_show, fom_dir_store);

static struct attribute *file_only_mem_attr[] = {
	&fom_state_attribute.attr,
	&fom_pid_attribute.attr,
	&fom_file_dir_attribute.attr,
	NULL,
};

static const struct attribute_group file_only_mem_attr_group = {
	.attrs = file_only_mem_attr,
};

///////////////////////////////////////////////////////////////////////////////
// Init
static int __init file_only_memory_init(void)
{
	struct kobject *fom_kobj;
	int err;

	memset(file_dir, 0, sizeof(file_dir));

	fom_kobj = kobject_create_and_add("fom", mm_kobj);
	if (unlikely(!fom_kobj)) {
		pr_err("failed to create the file only memory kobject\n");
		return -ENOMEM;
	}

	err = sysfs_create_group(fom_kobj, &file_only_mem_attr_group);
	if (err) {
		pr_err("failed to register the file only memory group\n");
		kobject_put(fom_kobj);
		return err;
	}

	return 0;
}
subsys_initcall(file_only_memory_init);
