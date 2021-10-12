#include <linux/types.h>
#include <linux/file_only_mem.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/security.h>
#include <linux/vmalloc.h>

enum file_only_mem_state {
	FOM_OFF = 0,
	FOM_SINGLE_PROC = 1,
	FOM_ALL = 2
};

// Start is inclusive, end is exclusive
struct fom_mapping {
	u64 start;
	u64 end;
	struct file *file;

	struct rb_node node;
};

struct fom_proc {
	pid_t pid;
	struct rb_root mappings;

	struct rb_node node;
};


static enum file_only_mem_state fom_state = FOM_OFF;
static pid_t cur_proc = 0;
static char file_dir[PATH_MAX];
static struct rb_root fom_procs = RB_ROOT;
static DECLARE_RWSEM(fom_procs_sem);

///////////////////////////////////////////////////////////////////////////////
// struct fom_proc functions

static struct fom_proc *get_fom_proc(pid_t pid) {
	struct rb_node *node = fom_procs.rb_node;

	while (node) {
		struct fom_proc *proc = rb_entry(node, struct fom_proc, node);

		if (pid < proc->pid)
			node = node->rb_left;
		else if (pid > proc->pid)
			node = node->rb_right;
		else
			return proc;
	}

	return NULL;
}

static void insert_new_proc(struct fom_proc *new_proc) {
	struct rb_node **new = &(fom_procs.rb_node);
	struct rb_node *parent = NULL;

	while (*new) {
		struct fom_proc *cur = rb_entry(*new, struct fom_proc, node);

		parent = *new;
		if (new_proc->pid < cur->pid)
			new = &((*new)->rb_left);
		else if (new_proc->pid > cur->pid)
			new = &((*new)->rb_right);
		else {
			pr_err("insert_new_proc: Attempting to insert already existing proc\n");
			BUG();
		}
	}

	rb_link_node(&new_proc->node, parent, new);
	rb_insert_color(&new_proc->node, &fom_procs);
}

///////////////////////////////////////////////////////////////////////////////
// struct fom_mapping functions

static void insert_new_mapping(struct fom_proc *proc, struct fom_mapping *new_map) {
	struct rb_node **new = &(proc->mappings.rb_node);
	struct rb_node *parent = NULL;

	while (*new) {
		struct fom_mapping *cur = rb_entry(*new, struct fom_mapping, node);

		// Check for an overlap
		if ((new_map->start >= cur->start && new_map->start < cur->end) ||
			(new_map->end > cur->start && new_map->end <= cur->end)) {
			pr_err("insert_new_mapping: Attempting to insert overlapping mapping\n");
			BUG();
		}

		parent = *new;
		if (new_map->start < cur->start)
			new = &((*new)->rb_left);
		else
			new = &((*new)->rb_right);
	}

	rb_link_node(&new_map->node, parent, new);
	rb_insert_color(&new_map->node, &proc->mappings);
}

///////////////////////////////////////////////////////////////////////////////
// Helper functions

// Most of this is taken from do_sys_truncate in fs/open.c
static int truncate_fom_file(struct file *f, unsigned long len) {
	struct inode *inode;
	struct dentry *dentry;
	int error;

	dentry = f->f_path.dentry;
	inode = dentry->d_inode;

	sb_start_write(inode->i_sb);
	error = locks_verify_truncate(inode, f, len);
	if (!error)
		error = security_path_truncate(&f->f_path);
	if (!error)
		error = do_truncate(file_mnt_user_ns(f), dentry, len,
				    ATTR_MTIME | ATTR_CTIME, f);
	sb_end_write(inode->i_sb);

	return error;
}

// Most of this is taken from do_unlinkat in fs/namei.c
static void delete_fom_file(struct file *f) {
	struct vfsmount *mnt;
	struct dentry *dentry;
	struct dentry *parent;
	int error;

	filp_close(f, current->files);

	mnt = f->f_path.mnt;
	dentry = f->f_path.dentry;
	parent = dentry->d_parent;

	error = mnt_want_write(mnt);
	if (error) {
		pr_err("delete_fom_file: Can't delete file\n");
		return;
	}

	inode_lock_nested(parent->d_inode, I_MUTEX_PARENT);

	error = security_path_unlink(&f->f_path, dentry);
	if (error)
		goto err;

	vfs_unlink(mnt_user_ns(mnt), parent->d_inode, dentry, NULL);

err:
	inode_unlock(parent->d_inode);
	mnt_drop_write(mnt);
}

///////////////////////////////////////////////////////////////////////////////
// External API functions

bool use_file_only_mem(pid_t pid) {
	if (fom_state == FOM_OFF) {
		return false;
	} if (fom_state == FOM_SINGLE_PROC) {
		return pid == cur_proc;
	} else if (fom_state == FOM_ALL) {
		return true;
	}

	// Should never reach here
	return false;
}

struct file *fom_create_new_file(unsigned long start, unsigned long len,
		unsigned long prot, pid_t pid)
{
	struct fom_proc *proc;
	struct fom_mapping *mapping = NULL;
	struct file *f;
	int open_flags = O_EXCL | O_TMPFILE;
	int ret = 0;
	umode_t open_mode = 0;
	bool new_proc = false;

	down_read(&fom_procs_sem);
	proc = get_fom_proc(pid);
	up_read(&fom_procs_sem);
	// Create the proc data structure if it does not already exist
	if (!proc) {
		new_proc = true;

		proc = vmalloc(sizeof(struct fom_proc));
		if (!proc) {
			pr_err("fom_create_new_file: not enough memory for proc\n");
			return NULL;
		}

		proc->pid = pid;
		proc->mappings = RB_ROOT;
	}

	// Determine what flags to use for the call to open
	if (prot & PROT_EXEC)
		open_mode |= S_IXUSR;

	if ((prot & (PROT_READ | PROT_WRITE)) == (PROT_READ | PROT_WRITE)) {
		open_flags |= O_RDWR;
		open_mode |= S_IRUSR | S_IWUSR;
	} else if (prot & PROT_WRITE) {
		open_flags |= O_WRONLY;
		open_mode |= S_IWUSR;
	} else if (prot & PROT_READ) {
		// It doesn't make sense for anon memory to be read only,
		goto err;
	}

	f = filp_open(file_dir, open_flags, open_mode);
	if (IS_ERR(f))
		goto err;

	// Set the file to the correct size
	ret = truncate_fom_file(f, len);
	if (ret) {
		delete_fom_file(f);
		goto err;
	}

	// Create the new mapping
	mapping = vmalloc(sizeof(struct fom_mapping));
	if (!mapping) {
		pr_err("fom_create_new_file: not enough memory for mapping\n");
		goto err;
	}
	mapping->start = start;
	mapping->end = start + len;
	mapping->file = f;

	down_write(&fom_procs_sem);
	insert_new_mapping(proc, mapping);

	// If we created a new fom_proc, add it to the rb_tree
	if (new_proc)
		insert_new_proc(proc);
	up_write(&fom_procs_sem);

	return f;

err:
	if (new_proc)
		vfree(proc);
	return NULL;
}

void fom_check_exiting_proc(pid_t pid) {
	struct fom_proc *proc;
	struct rb_node *node;

	down_read(&fom_procs_sem);
	proc = get_fom_proc(pid);
	up_read(&fom_procs_sem);

	if (!proc)
		return;

	down_write(&fom_procs_sem);

	// First, free the mappings tree
	node = proc->mappings.rb_node;
	while (node) {
		struct fom_mapping *map = rb_entry(node, struct fom_mapping, node);
		rb_erase(node, &proc->mappings);
		node = proc->mappings.rb_node;

		delete_fom_file(map->file);

		vfree(map);
	}

	// Now, remove the proc from the procs tree and free it
	// TODO: I might be able to remove the proc from the proc tree first,
	// then free everything else without holding any locks...
	rb_erase(&proc->node, &fom_procs);
	vfree(proc);

	up_write(&fom_procs_sem);
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
	return sprintf(buf, "%d\n", cur_proc);
}

static ssize_t fom_pid_store(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	pid_t pid;
	int ret;

	ret = kstrtoint(buf, 0, &pid);

	if (ret != 0) {
		cur_proc = 0;
		return ret;
	}

	cur_proc = pid;

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

	if (count > PATH_MAX) {
		memset(file_dir, 0, PATH_MAX);
		return -ENOMEM;
	}

	strncpy(file_dir, buf, PATH_MAX);

	// echo likes to put an extra \n at the end of the string
	// if it's there, remove it
	if (file_dir[count - 1] == '\n')
		file_dir[count - 1] = '\0';

	// Check if the given path is actually a valid directory
	err = kern_path(file_dir, LOOKUP_DIRECTORY, &p);

	if (err) {
		memset(file_dir, 0, PATH_MAX);
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

	memset(file_dir, 0, PATH_MAX);

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
