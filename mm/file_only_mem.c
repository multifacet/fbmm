#include <linux/types.h>
#include <linux/file_only_mem.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/security.h>
#include <linux/vmalloc.h>
#include <linux/falloc.h>
#include <linux/timekeeping.h>

enum file_only_mem_state {
	FOM_OFF = 0,
	FOM_SINGLE_PROC = 1,
	FOM_ALL = 2
};

struct fom_file {
	struct file *f;
	unsigned long original_start; // Used to compute the offset for fallocate
	int count;
};

// Start is inclusive, end is exclusive
struct fom_mapping {
	u64 start;
	u64 end;
	struct fom_file *file;

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

static ktime_t file_create_time = 0;
static u64 num_file_creates = 0;
static ktime_t file_register_time = 0;
static u64 num_file_registers = 0;

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
			pr_err("insert_new_mapping: old mapping %llx %llx\n",
				cur->start, cur->end);
			pr_err("insert_new_mapping: new mapping %llx %llx\n",
				new_map->start, new_map->end);
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

// Returns the first mapping in proc where addr < mapping->end, NULL if none exists.
// Mostly taken from find_vma
static struct fom_mapping *find_mapping(struct fom_proc *proc, unsigned long addr) {
	struct fom_mapping *mapping = NULL;
	struct rb_node *node = proc->mappings.rb_node;

	while (node) {
		struct fom_mapping *tmp = rb_entry(node, struct fom_mapping, node);

		if (tmp->end > addr) {
			mapping = tmp;
			if (tmp->start <= addr)
				break;
			node = node->rb_left;
		} else {
			node = node->rb_right;
		}
	}

	return mapping;
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

static void drop_fom_file(struct fom_mapping *map) {
	map->file->count--;
	if (map->file->count <= 0) {
		delete_fom_file(map->file->f);
		fput(map->file->f);
		vfree(map->file);
		map->file = NULL;
	}
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

struct file *fom_create_new_file(unsigned long len, unsigned long prot) {
	struct file *f;
	int open_flags = O_EXCL | O_TMPFILE;
	umode_t open_mode = 0;
	int ret = 0;
	ktime_t start_time = ktime_get_ns();

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
		return NULL;
	}

	f = filp_open(file_dir, open_flags, open_mode);
	if (IS_ERR(f))
		return NULL;

	// Set the file to the correct size
	ret = truncate_fom_file(f, len);
	if (ret) {
		delete_fom_file(f);
		return NULL;
	}

	file_create_time += ktime_get_ns() - start_time;
	num_file_creates++;

	return f;
}

void fom_register_file(pid_t pid, struct file *f,
		unsigned long start, unsigned long len)
{
	struct fom_proc *proc;
	struct fom_mapping *mapping = NULL;
	struct fom_file *file = NULL;
	bool new_proc = false;
	ktime_t start_time = ktime_get_ns();

	down_read(&fom_procs_sem);
	proc = get_fom_proc(pid);
	up_read(&fom_procs_sem);
	// Create the proc data structure if it does not already exist
	if (!proc) {
		new_proc = true;

		proc = vmalloc(sizeof(struct fom_proc));
		if (!proc) {
			pr_err("fom_create_new_file: not enough memory for proc\n");
			return;
		}

		proc->pid = pid;
		proc->mappings = RB_ROOT;
	}

	file = vmalloc(sizeof(struct fom_file));
	if (!file)
		goto err;

	file->f = f;
	if (!file->f)
		goto err;
	file->count = 1;
	file->original_start = start;

	// Create the new mapping
	mapping = vmalloc(sizeof(struct fom_mapping));
	if (!mapping) {
		pr_err("fom_create_new_file: not enough memory for mapping\n");
		goto err;
	}
	mapping->start = start;
	mapping->end = start + len;
	mapping->file = file;

	down_write(&fom_procs_sem);

	insert_new_mapping(proc, mapping);

	// If we created a new fom_proc, add it to the rb_tree
	if (new_proc)
		insert_new_proc(proc);
	up_write(&fom_procs_sem);

	file_register_time += ktime_get_ns() - start_time;
	num_file_registers++;

	return;
err:
	if (new_proc)
		vfree(proc);
	if (file)
		vfree(file);
}

int fom_munmap(pid_t pid, unsigned long start, unsigned long len) {
	struct fom_proc *proc = NULL;
	struct fom_mapping *old_mapping = NULL;
	unsigned long end = start + len;
	unsigned long falloc_offset, falloc_len;
	struct file *falloc_file = NULL;
	bool do_falloc = false;
	int ret = 0;

	down_read(&fom_procs_sem);
	proc = get_fom_proc(pid);
	up_read(&fom_procs_sem);

	if (!proc)
		return 0;

	// a munmap call can span multiple memory ranges, so we might have to do this
	// multiple times
	while (start < end) {
		unsigned long next_start;

		// Finds the first mapping where start < mapping->end, so we have to
		// check if old_mapping is actually within the range
		down_read(&fom_procs_sem);
		old_mapping = find_mapping(proc, start);
		if (!old_mapping || end <= old_mapping->start)
			goto exit_locked;

		next_start = old_mapping->end;
		up_read(&fom_procs_sem);

		// If the unmap range entirely contains the mapping, we can simply delete it
		if (start <= old_mapping->start && old_mapping->end <= end) {
			// First, we have to grab a write lock
			down_write(&fom_procs_sem);

			rb_erase(&old_mapping->node, &proc->mappings);
			drop_fom_file(old_mapping);

			// If old_mapping->file is null, it has been deleted.
			// Otherwise, we should punch a hole in this mapping
			if (old_mapping->file) {
				falloc_offset =
					old_mapping->start - old_mapping->file->original_start;
				falloc_len = old_mapping->end - old_mapping->start;
				falloc_file = old_mapping->file->f;
				do_falloc = true;
			}

			vfree(old_mapping);

			up_write(&fom_procs_sem);
		}
		// If the unmap range takes only the end of the mapping, truncate the file
		else if (start < old_mapping->end && old_mapping->end <= end) {
			down_write(&fom_procs_sem);

			falloc_offset = start - old_mapping->file->original_start;
			falloc_len = old_mapping->end - start;
			old_mapping->end = start;
			falloc_file = old_mapping->file->f;
			do_falloc = true;

			up_write(&fom_procs_sem);
		}
		// If the unmap range trims off only the beginning of the mapping,
		// deallocate the beginning
		else if (start <= old_mapping->start && old_mapping->start < end) {
			down_write(&fom_procs_sem);

			falloc_offset = old_mapping->start - old_mapping->file->original_start;
			falloc_len = end - old_mapping->start;
			old_mapping->start = end;
			falloc_file = old_mapping->file->f;
			do_falloc = true;

			up_write(&fom_procs_sem);
		}
		// If the unmap range is entirely within a mapping, poke a hole
		// in the middle of the file and create a new mapping to represent
		// the split
		else if (old_mapping->start < start && end < old_mapping->end) {
			struct fom_mapping *new_mapping = vmalloc(sizeof(struct fom_mapping));

			if (!new_mapping) {
				pr_err("fom_munmap: can't allocate new fom_mapping\n");
				return -ENOMEM;
			}

			new_mapping->start = end;
			new_mapping->end = old_mapping->end;

			down_write(&fom_procs_sem);
			old_mapping->end = start;

			new_mapping->file = old_mapping->file;
			new_mapping->file->count++;

			insert_new_mapping(proc, new_mapping);

			falloc_offset = start - old_mapping->file->original_start;
			falloc_len = end - start;
			falloc_file = old_mapping->file->f;
			do_falloc = true;
			up_write(&fom_procs_sem);
		}

		if (do_falloc) {
			ret = vfs_fallocate(falloc_file,
					FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
					falloc_offset, falloc_len);
		}

		start = next_start;
	}

	return ret;
exit_locked:
	up_read(&fom_procs_sem);
	return ret;
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

		drop_fom_file(map);

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

static ssize_t fom_stats_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
    u64 avg_create_time = 0;
    u64 avg_register_time = 0;
    ssize_t count;

    if (num_file_creates != 0) {
        avg_create_time = file_create_time / num_file_creates;
    }
    if (num_file_registers != 0) {
        avg_register_time = file_register_time / num_file_registers;
    }

    count = sprintf(buf, "file create times: %lld %lld %lld\n", file_create_time,
        num_file_creates, avg_create_time);
    count += sprintf(&buf[count], "file register times: %lld %lld %lld\n", file_register_time,
        num_file_registers, avg_register_time);

    return count;
}

static ssize_t fom_stats_store(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	file_create_time = 0;
	num_file_creates = 0;
	file_register_time = 0;
	num_file_registers = 0;
	return count;
}
static struct kobj_attribute fom_stats_attribute =
__ATTR(stats, 0644, fom_stats_show, fom_stats_store);

static struct attribute *file_only_mem_attr[] = {
	&fom_state_attribute.attr,
	&fom_pid_attribute.attr,
	&fom_file_dir_attribute.attr,
	&fom_stats_attribute.attr,
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
