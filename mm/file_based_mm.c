#include <linux/types.h>
#include <linux/file_based_mm.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/namei.h>
#include <linux/fs.h>
#include <linux/mman.h>
#include <linux/security.h>
#include <linux/vmalloc.h>
#include <linux/falloc.h>
#include <linux/timekeeping.h>

enum file_based_mm_state {
	FBMM_OFF = 0,
	FBMM_SINGLE_PROC = 1,
	FBMM_ALL = 2
};

struct fbmm_file {
	struct file *f;
	unsigned long original_start; // Used to compute the offset for fallocate
	int count;
};

// Start is inclusive, end is exclusive
struct fbmm_mapping {
	u64 start;
	u64 end;
	struct fbmm_file *file;

	struct rb_node node;
};

struct fbmm_proc {
	pid_t pid;
	struct rb_root mappings;

	struct rb_node node;
};


static enum file_based_mm_state fbmm_state = FBMM_OFF;
static pid_t cur_proc = 0;
static char file_dir[PATH_MAX];
static struct rb_root fbmm_procs = RB_ROOT;
static DECLARE_RWSEM(fbmm_procs_sem);

static ktime_t file_create_time = 0;
static u64 num_file_creates = 0;
static ktime_t file_register_time = 0;
static u64 num_file_registers = 0;

static int fbmm_prealloc_map_populate = 1;

///////////////////////////////////////////////////////////////////////////////
// struct fbmm_proc functions

static struct fbmm_proc *get_fbmm_proc(pid_t pid) {
	struct rb_node *node = fbmm_procs.rb_node;

	while (node) {
		struct fbmm_proc *proc = rb_entry(node, struct fbmm_proc, node);

		if (pid < proc->pid)
			node = node->rb_left;
		else if (pid > proc->pid)
			node = node->rb_right;
		else
			return proc;
	}

	return NULL;
}

static void insert_new_proc(struct fbmm_proc *new_proc) {
	struct rb_node **new = &(fbmm_procs.rb_node);
	struct rb_node *parent = NULL;

	while (*new) {
		struct fbmm_proc *cur = rb_entry(*new, struct fbmm_proc, node);

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
	rb_insert_color(&new_proc->node, &fbmm_procs);
}

///////////////////////////////////////////////////////////////////////////////
// struct fbmm_mapping functions

static void insert_new_mapping(struct fbmm_proc *proc, struct fbmm_mapping *new_map) {
	struct rb_node **new = &(proc->mappings.rb_node);
	struct rb_node *parent = NULL;

	while (*new) {
		struct fbmm_mapping *cur = rb_entry(*new, struct fbmm_mapping, node);

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
static struct fbmm_mapping *find_mapping(struct fbmm_proc *proc, unsigned long addr) {
	struct fbmm_mapping *mapping = NULL;
	struct rb_node *node = proc->mappings.rb_node;

	while (node) {
		struct fbmm_mapping *tmp = rb_entry(node, struct fbmm_mapping, node);

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
static int truncate_fbmm_file(struct file *f, unsigned long len, int flags) {
	struct inode *inode;
	struct dentry *dentry;
	int error;

	dentry = f->f_path.dentry;
	inode = dentry->d_inode;

	if ((flags & MAP_POPULATE) && fbmm_prealloc_map_populate) {
		error = vfs_truncate(&f->f_path, len);
		if (!error)
			error = vfs_fallocate(f, 0, 0, len);
	} else {
		sb_start_write(inode->i_sb);
		error = security_path_truncate(&f->f_path);
		if (!error)
			error = do_truncate(file_mnt_user_ns(f), dentry, len,
					    ATTR_MTIME | ATTR_CTIME, f);
		sb_end_write(inode->i_sb);
	}

	return error;
}

static void drop_fbmm_file(struct fbmm_mapping *map) {
	map->file->count--;
	if (map->file->count <= 0) {
		filp_close(map->file->f, current->files);
		fput(map->file->f);
		vfree(map->file);
		map->file = NULL;
	}
}

///////////////////////////////////////////////////////////////////////////////
// External API functions

bool use_file_based_mm(pid_t pid) {
	if (fbmm_state == FBMM_OFF) {
		return false;
	} if (fbmm_state == FBMM_SINGLE_PROC) {
		return pid == cur_proc;
	} else if (fbmm_state == FBMM_ALL) {
		return true;
	}

	// Should never reach here
	return false;
}

struct file *fbmm_create_new_file(unsigned long len, unsigned long prot, int flags) {
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
	ret = truncate_fbmm_file(f, len, flags);
	if (ret) {
		filp_close(f, current->files);
		return NULL;
	}

	file_create_time += ktime_get_ns() - start_time;
	num_file_creates++;

	return f;
}

void fbmm_register_file(pid_t pid, struct file *f,
		unsigned long start, unsigned long len)
{
	struct fbmm_proc *proc;
	struct fbmm_mapping *mapping = NULL;
	struct fbmm_file *file = NULL;
	bool new_proc = false;
	ktime_t start_time = ktime_get_ns();

	down_read(&fbmm_procs_sem);
	proc = get_fbmm_proc(pid);
	up_read(&fbmm_procs_sem);
	// Create the proc data structure if it does not already exist
	if (!proc) {
		new_proc = true;

		proc = vmalloc(sizeof(struct fbmm_proc));
		if (!proc) {
			pr_err("fbmm_create_new_file: not enough memory for proc\n");
			return;
		}

		proc->pid = pid;
		proc->mappings = RB_ROOT;
	}

	file = vmalloc(sizeof(struct fbmm_file));
	if (!file)
		goto err;

	file->f = f;
	if (!file->f)
		goto err;
	file->count = 1;
	file->original_start = start;

	// Create the new mapping
	mapping = vmalloc(sizeof(struct fbmm_mapping));
	if (!mapping) {
		pr_err("fbmm_create_new_file: not enough memory for mapping\n");
		goto err;
	}
	mapping->start = start;
	mapping->end = start + len;
	mapping->file = file;

	down_write(&fbmm_procs_sem);

	insert_new_mapping(proc, mapping);

	// If we created a new fbmm_proc, add it to the rb_tree
	if (new_proc)
		insert_new_proc(proc);
	up_write(&fbmm_procs_sem);

	file_register_time += ktime_get_ns() - start_time;
	num_file_registers++;

	return;
err:
	if (new_proc)
		vfree(proc);
	if (file)
		vfree(file);
}

int fbmm_munmap(pid_t pid, unsigned long start, unsigned long len) {
	struct fbmm_proc *proc = NULL;
	struct fbmm_mapping *old_mapping = NULL;
	unsigned long end = start + len;
	unsigned long falloc_offset, falloc_len;
	struct file *falloc_file = NULL;
	bool do_falloc = false;
	int ret = 0;

	down_read(&fbmm_procs_sem);
	proc = get_fbmm_proc(pid);
	up_read(&fbmm_procs_sem);

	if (!proc)
		return 0;

	// a munmap call can span multiple memory ranges, so we might have to do this
	// multiple times
	while (start < end) {
		unsigned long next_start;

		// Finds the first mapping where start < mapping->end, so we have to
		// check if old_mapping is actually within the range
		down_read(&fbmm_procs_sem);
		old_mapping = find_mapping(proc, start);
		if (!old_mapping || end <= old_mapping->start)
			goto exit_locked;

		next_start = old_mapping->end;
		up_read(&fbmm_procs_sem);

		// If the unmap range entirely contains the mapping, we can simply delete it
		if (start <= old_mapping->start && old_mapping->end <= end) {
			// First, we have to grab a write lock
			down_write(&fbmm_procs_sem);

			rb_erase(&old_mapping->node, &proc->mappings);
			drop_fbmm_file(old_mapping);

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

			up_write(&fbmm_procs_sem);
		}
		// If the unmap range takes only the end of the mapping, truncate the file
		else if (start < old_mapping->end && old_mapping->end <= end) {
			down_write(&fbmm_procs_sem);

			falloc_offset = start - old_mapping->file->original_start;
			falloc_len = old_mapping->end - start;
			old_mapping->end = start;
			falloc_file = old_mapping->file->f;
			do_falloc = true;

			up_write(&fbmm_procs_sem);
		}
		// If the unmap range trims off only the beginning of the mapping,
		// deallocate the beginning
		else if (start <= old_mapping->start && old_mapping->start < end) {
			down_write(&fbmm_procs_sem);

			falloc_offset = old_mapping->start - old_mapping->file->original_start;
			falloc_len = end - old_mapping->start;
			old_mapping->start = end;
			falloc_file = old_mapping->file->f;
			do_falloc = true;

			up_write(&fbmm_procs_sem);
		}
		// If the unmap range is entirely within a mapping, poke a hole
		// in the middle of the file and create a new mapping to represent
		// the split
		else if (old_mapping->start < start && end < old_mapping->end) {
			struct fbmm_mapping *new_mapping = vmalloc(sizeof(struct fbmm_mapping));

			if (!new_mapping) {
				pr_err("fbmm_munmap: can't allocate new fbmm_mapping\n");
				return -ENOMEM;
			}

			new_mapping->start = end;
			new_mapping->end = old_mapping->end;

			down_write(&fbmm_procs_sem);
			old_mapping->end = start;

			new_mapping->file = old_mapping->file;
			new_mapping->file->count++;

			insert_new_mapping(proc, new_mapping);

			falloc_offset = start - old_mapping->file->original_start;
			falloc_len = end - start;
			falloc_file = old_mapping->file->f;
			do_falloc = true;
			up_write(&fbmm_procs_sem);
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
	up_read(&fbmm_procs_sem);
	return ret;
}

void fbmm_check_exiting_proc(pid_t pid) {
	struct fbmm_proc *proc;
	struct rb_node *node;

	down_read(&fbmm_procs_sem);
	proc = get_fbmm_proc(pid);
	up_read(&fbmm_procs_sem);

	if (!proc)
		return;

	down_write(&fbmm_procs_sem);

	// First, free the mappings tree
	node = proc->mappings.rb_node;
	while (node) {
		struct fbmm_mapping *map = rb_entry(node, struct fbmm_mapping, node);
		rb_erase(node, &proc->mappings);
		node = proc->mappings.rb_node;

		drop_fbmm_file(map);

		vfree(map);
	}

	// Now, remove the proc from the procs tree and free it
	// TODO: I might be able to remove the proc from the proc tree first,
	// then free everything else without holding any locks...
	rb_erase(&proc->node, &fbmm_procs);
	vfree(proc);

	up_write(&fbmm_procs_sem);
}

///////////////////////////////////////////////////////////////////////////////
// sysfs files
static ssize_t fbmm_state_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", fbmm_state);
}

static ssize_t fbmm_state_store(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int state;
	int ret;

	ret = kstrtoint(buf, 0, &state);

	if (ret != 0) {
		fbmm_state = FBMM_OFF;
		return ret;
	} else if (state >= FBMM_OFF && state <= FBMM_ALL) {
		fbmm_state = state;
		return count;
	} else {
		fbmm_state = FBMM_OFF;
		return -EINVAL;
	}
}
static struct kobj_attribute fbmm_state_attribute =
__ATTR(state, 0644, fbmm_state_show, fbmm_state_store);

static ssize_t fbmm_pid_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", cur_proc);
}

static ssize_t fbmm_pid_store(struct kobject *kobj,
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
static struct kobj_attribute fbmm_pid_attribute =
__ATTR(pid, 0644, fbmm_pid_show, fbmm_pid_store);

static ssize_t fbmm_dir_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", file_dir);
}

static ssize_t fbmm_dir_store(struct kobject *kobj,
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

	// Free the reference to the path so we can unmount the fs
	path_put(&p);

	return count;
}
static struct kobj_attribute fbmm_file_dir_attribute =
__ATTR(file_dir, 0644, fbmm_dir_show, fbmm_dir_store);

static ssize_t fbmm_stats_show(struct kobject *kobj,
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

static ssize_t fbmm_stats_store(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	file_create_time = 0;
	num_file_creates = 0;
	file_register_time = 0;
	num_file_registers = 0;
	return count;
}
static struct kobj_attribute fbmm_stats_attribute =
__ATTR(stats, 0644, fbmm_stats_show, fbmm_stats_store);

int fbmm_dax_pte_fault_size = 1;
static ssize_t fbmm_dax_pte_fault_size_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", fbmm_dax_pte_fault_size);
}

static ssize_t fbmm_dax_pte_fault_size_store(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int fault_size;
	int ret;

	ret = kstrtoint(buf, 0, &fault_size);

	if (ret != 0) {
		fbmm_dax_pte_fault_size = 1;
		return ret;
	}

	if (fault_size > 0)
		fbmm_dax_pte_fault_size = fault_size;
	else
		fbmm_dax_pte_fault_size = 1;

	return count;
}
static struct kobj_attribute fbmm_dax_pte_fault_size_attribute =
__ATTR(pte_fault_size, 0644, fbmm_dax_pte_fault_size_show, fbmm_dax_pte_fault_size_store);

int nt_huge_page_zero = 1;
static ssize_t nt_huge_page_zero_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", nt_huge_page_zero);
}

static ssize_t nt_huge_page_zero_store(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int val;
	int ret;

	ret = kstrtoint(buf, 0, &val);

	if (ret != 0) {
		nt_huge_page_zero = 1;
		return ret;
	}

	if (val == 0)
		nt_huge_page_zero = 0;
	else
		nt_huge_page_zero = 1;

	return count;
}
static struct kobj_attribute nt_huge_page_zero_attribute =
__ATTR(nt_huge_page_zero, 0644, nt_huge_page_zero_show, nt_huge_page_zero_store);

int fbmm_follow_page_mask_fix = 1;
static ssize_t fbmm_follow_page_mask_fix_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", fbmm_follow_page_mask_fix);
}

static ssize_t fbmm_follow_page_mask_fix_store(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int val;
	int ret;

	ret = kstrtoint(buf, 0, &val);

	if (ret != 0) {
		fbmm_follow_page_mask_fix = 1;
		return ret;
	}

	if (val == 0)
		fbmm_follow_page_mask_fix = 0;
	else
		fbmm_follow_page_mask_fix = 1;

	return count;
}
static struct kobj_attribute fbmm_follow_page_mask_fix_attribute =
__ATTR(follow_page_mask_fix, 0644, fbmm_follow_page_mask_fix_show, fbmm_follow_page_mask_fix_store);

int fbmm_pmem_write_zeroes = 1;
static ssize_t fbmm_pmem_write_zeroes_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", fbmm_pmem_write_zeroes);
}

static ssize_t fbmm_pmem_write_zeroes_store(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int val;
	int ret;

	ret = kstrtoint(buf, 0, &val);

	if (ret != 0) {
		fbmm_pmem_write_zeroes = 1;
		return ret;
	}

	if (val == 0)
		fbmm_pmem_write_zeroes = 0;
	else
		fbmm_pmem_write_zeroes = 1;

	return count;
}
static struct kobj_attribute fbmm_pmem_write_zeroes_attribute =
__ATTR(pmem_write_zeroes, 0644, fbmm_pmem_write_zeroes_show, fbmm_pmem_write_zeroes_store);

int fbmm_track_pfn_insert = 0;
static ssize_t fbmm_track_pfn_insert_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", fbmm_track_pfn_insert);
}

static ssize_t fbmm_track_pfn_insert_store(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int val;
	int ret;

	ret = kstrtoint(buf, 0, &val);

	if (ret != 0) {
		fbmm_track_pfn_insert = 0;
		return ret;
	}

	if (val == 0)
		fbmm_track_pfn_insert = 0;
	else
		fbmm_track_pfn_insert = 1;

	return count;
}
static struct kobj_attribute fbmm_track_pfn_insert_attribute =
__ATTR(track_pfn_insert, 0644, fbmm_track_pfn_insert_show, fbmm_track_pfn_insert_store);

int fbmm_mark_inode_dirty = 0;
static ssize_t fbmm_mark_inode_dirty_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", fbmm_mark_inode_dirty);
}

static ssize_t fbmm_mark_inode_dirty_store(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int val;
	int ret;

	ret = kstrtoint(buf, 0, &val);

	if (ret != 0) {
		fbmm_mark_inode_dirty = 0;
		return ret;
	}

	if (val == 0)
		fbmm_mark_inode_dirty = 0;
	else
		fbmm_mark_inode_dirty = 1;

	return count;
}
static struct kobj_attribute fbmm_mark_inode_dirty_attribute =
__ATTR(mark_inode_dirty, 0644, fbmm_mark_inode_dirty_show, fbmm_mark_inode_dirty_store);

static ssize_t fbmm_prealloc_map_populate_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", fbmm_prealloc_map_populate);
}

static ssize_t fbmm_prealloc_map_populate_store(struct kobject *kobj,
		struct kobj_attribute *attr,
		const char *buf, size_t count)
{
	int val;
	int ret;

	ret = kstrtoint(buf, 0, &val);

	if (ret != 0) {
		fbmm_prealloc_map_populate = 1;
		return ret;
	}

	if (val == 0)
		fbmm_prealloc_map_populate = 0;
	else
		fbmm_prealloc_map_populate = 1;

	return count;
}
static struct kobj_attribute fbmm_prealloc_map_populate_attribute =
__ATTR(prealloc_map_populate, 0644, fbmm_prealloc_map_populate_show, fbmm_prealloc_map_populate_store);

static struct attribute *file_based_mm_attr[] = {
	&fbmm_state_attribute.attr,
	&fbmm_pid_attribute.attr,
	&fbmm_file_dir_attribute.attr,
	&fbmm_stats_attribute.attr,
	&fbmm_dax_pte_fault_size_attribute.attr,
	&nt_huge_page_zero_attribute.attr,
	&fbmm_follow_page_mask_fix_attribute.attr,
	&fbmm_pmem_write_zeroes_attribute.attr,
	&fbmm_track_pfn_insert_attribute.attr,
	&fbmm_mark_inode_dirty_attribute.attr,
	&fbmm_prealloc_map_populate_attribute.attr,
	NULL,
};

static const struct attribute_group file_based_mm_attr_group = {
	.attrs = file_based_mm_attr,
};

///////////////////////////////////////////////////////////////////////////////
// Init
static int __init file_based_mm_init(void)
{
	struct kobject *fbmm_kobj;
	int err;

	memset(file_dir, 0, PATH_MAX);

	fbmm_kobj = kobject_create_and_add("fbmm", mm_kobj);
	if (unlikely(!fbmm_kobj)) {
		pr_err("failed to create the file based mm kobject\n");
		return -ENOMEM;
	}

	err = sysfs_create_group(fbmm_kobj, &file_based_mm_attr_group);
	if (err) {
		pr_err("failed to register the file based mm group\n");
		kobject_put(fbmm_kobj);
		return err;
	}

	return 0;
}
subsys_initcall(file_based_mm_init);
