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
#include <linux/maple_tree.h>
#include <linux/sched.h>
#include <linux/kthread.h>

enum file_based_mm_state {
	FBMM_OFF = 0,
	FBMM_SELECTED_PROCS = 1,
	FBMM_ALL = 2
};

// It takes time to create new files and create new VMAs for mappings
// with different files, so we want to create huge files that we can reuse
// for different calls to mmap
#define FBMM_DEFAULT_FILE_SIZE ((long)128 << 30)
struct fbmm_file {
	struct file *f;
	// The starting virtual address assigned to this file (inclusive)
	unsigned long va_start;
	// The ending virtual address assigned to this file (exclusive)
	unsigned long va_end;
};

struct fbmm_proc {
	pid_t pid;
	char *mnt_dir_str;
	struct path mnt_dir_path;
	// This file exists just to be passed to get_unmapped_area in mmap
	struct file *get_unmapped_area_file;
	struct maple_tree files_mt;
	bool in_work_queue;
	struct list_head prealloc_file_list;
	spinlock_t prealloc_file_lock;
	atomic_t num_prealloc_files;
	atomic_t refcount;
};


static enum file_based_mm_state fbmm_state = FBMM_OFF;
static DECLARE_RWSEM(fbmm_procs_sem);
// This is used to store the default fbmm mount directories for each proc.
// An entry for a pid exists in this tree iff the process of that pid is using FBMM.
static struct maple_tree fbmm_proc_mt = MTREE_INIT(fbmm_proc_mt, 0);

static DEFINE_SPINLOCK(stats_lock);
static u64 file_create_time = 0;
static u64 num_file_creates = 0;
static u64 file_register_time = 0;
static u64 num_file_registers = 0;
static u64 munmap_time = 0;
static u64 num_munmaps = 0;

static int fbmm_prealloc_map_populate = 1;

// Stuff for the fbmm_file_create_thread
static struct task_struct *fbmm_file_create_thread = NULL;
static DEFINE_SPINLOCK(fbmm_work_queue_lock);
static LIST_HEAD(fbmm_work_queue);

struct fbmm_file_create_order {
	struct fbmm_proc *proc;
	struct list_head node;
};

struct fbmm_prealloc_entry {
	struct file *file;
	struct list_head node;
};

///////////////////////////////////////////////////////////////////////////////
// struct fbmm_proc functions

static struct fbmm_proc *fbmm_create_new_proc(char *mnt_dir_str, pid_t pid) {
	const int OPEN_FLAGS = O_EXCL | O_TMPFILE | O_RDWR;
	const umode_t OPEN_MODE = S_IFREG | S_IRUSR | S_IWUSR;
	struct fbmm_proc *proc;

	proc = kmalloc(sizeof(struct fbmm_proc), GFP_KERNEL);
	if (!proc) {
		pr_err("fbmm_create_new_proc: not enough memory for proc\n");
		return NULL;
	}

	proc->mnt_dir_str = mnt_dir_str;
	kern_path(mnt_dir_str, LOOKUP_DIRECTORY | LOOKUP_FOLLOW, &proc->mnt_dir_path);
	proc->get_unmapped_area_file = file_open_root(&proc->mnt_dir_path, "", OPEN_FLAGS, OPEN_MODE);
	if (IS_ERR(proc->get_unmapped_area_file)) {
		pr_err("fbmm_create_new_proc: Could not create the get_unmapped_area_file\n");
	}
	proc->pid = pid;
	mt_init(&proc->files_mt);
	proc->in_work_queue = false;
	INIT_LIST_HEAD(&proc->prealloc_file_list);
	spin_lock_init(&proc->prealloc_file_lock);
	atomic_set(&proc->num_prealloc_files, 0);
	atomic_set(&proc->refcount, 1);

	return proc;
}

static void fbmm_get_proc(struct fbmm_proc *proc) {
	atomic_inc(&proc->refcount);
}

static void fbmm_put_proc(struct fbmm_proc *proc) {
	struct fbmm_prealloc_entry *entry, *tmp;

	// Only free the contents if the refcount becomes 0
	if (atomic_dec_return(&proc->refcount) == 0) {
		kfree(proc->mnt_dir_str);
		path_put(&proc->mnt_dir_path);

		list_for_each_entry_safe(entry, tmp, &proc->prealloc_file_list, node) {
			list_del(&entry->node);
			filp_close(entry->file, current->files);
			kfree(entry);
		}

		kfree(proc);
	}
}

///////////////////////////////////////////////////////////////////////////////
// File allocating functions
// TODO: This works per proc, but would probably be better for it to work
// per MFS

static int fbmm_prealloc_task(void *data) {
	const int OPEN_FLAGS = O_EXCL | O_TMPFILE | O_RDWR;
	const umode_t OPEN_MODE = S_IFREG | S_IRUSR | S_IWUSR;
	const int NUM_FILES_TO_CREATE = 10;
	struct fbmm_file_create_order *work_order;
	struct fbmm_prealloc_entry *prealloc_entry;
	struct fbmm_proc *proc;
	struct file *file;

    while (!kthread_should_stop()) {
		// Read the next work order if there is one
		spin_lock(&fbmm_work_queue_lock);
		if (list_empty(&fbmm_work_queue))
			goto sleep;

		work_order = list_first_entry(&fbmm_work_queue, struct fbmm_file_create_order, node);
		list_del(&work_order->node);
		spin_unlock(&fbmm_work_queue_lock);

		proc = work_order->proc;
		kfree(work_order);

		// Check if we already have a decent number of files
		if (atomic_read(&proc->num_prealloc_files) >= NUM_FILES_TO_CREATE / 2)
			goto put_proc;

		// Create the files
		for (int i = 0; i < NUM_FILES_TO_CREATE; i++) {
			file = file_open_root(&proc->mnt_dir_path, "", OPEN_FLAGS, OPEN_MODE);
			if (IS_ERR(file))
				goto put_proc;

			// Add the file to the proc's free list
			prealloc_entry = kmalloc(sizeof(struct fbmm_prealloc_entry), GFP_KERNEL);
			if (!prealloc_entry) {
				// Using "current_cred" here is a little weird because this is
				// a kernel thread, not the user proc that wants the file,
				// but that param is only used to call the flush callback, which
				// MFS's don't implement, so it should be fine.
				filp_close(file, current->files);
				goto put_proc;
			}
			prealloc_entry->file = file;

			spin_lock(&proc->prealloc_file_lock);
			list_add_tail(&prealloc_entry->node, &proc->prealloc_file_list);
			spin_unlock(&proc->prealloc_file_lock);
			atomic_inc(&proc->num_prealloc_files);
		}

put_proc:
		// A reference to proc is taken when a work order is put on the queue,
		// so we need to drop it when we leave.
		spin_lock(&proc->prealloc_file_lock);
		proc->in_work_queue = false;
		spin_unlock(&proc->prealloc_file_lock);
		fbmm_put_proc(proc);
sleep:
		// Go to sleep until there is more work to do
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}

	return 0;
}

static void fbmm_add_work_order(struct fbmm_proc *proc) {
	struct fbmm_file_create_order *work_order;

	if (!fbmm_file_create_thread)
		return;

	work_order = kmalloc(sizeof(struct fbmm_file_create_order), GFP_KERNEL);
	if (!work_order)
		return;

	spin_lock(&proc->prealloc_file_lock);
	if (proc->in_work_queue) {
		spin_unlock(&proc->prealloc_file_lock);
		return;
	}
	proc->in_work_queue = true;
	spin_unlock(&proc->prealloc_file_lock);

	work_order->proc = proc;
	fbmm_get_proc(proc);

	spin_lock(&fbmm_work_queue_lock);
	list_add_tail(&work_order->node, &fbmm_work_queue);
	spin_unlock(&fbmm_work_queue_lock);

	wake_up_process(fbmm_file_create_thread);
}

static struct file *fbmm_get_prealloc_file(struct fbmm_proc *proc) {
	const int RETRIES = 5;
	struct fbmm_prealloc_entry *prealloc_entry;
	struct file *file;
	int orig_num_prealloc_files;
	bool file_reserved = false;

	// Try to reserve a preallocated file
	for (int i = 0; i < RETRIES; i++) {
		orig_num_prealloc_files = atomic_read(&proc->num_prealloc_files);

		if (orig_num_prealloc_files == 0) {
			fbmm_add_work_order(proc);
			return NULL;
		}

		if (atomic_cmpxchg(&proc->num_prealloc_files,
					orig_num_prealloc_files,
					orig_num_prealloc_files - 1) == orig_num_prealloc_files)
		{
			file_reserved = true;
			break;
		}
	}

	// There is a lot of contention for the files, so fallback
	if (!file_reserved)
		return NULL;

	spin_lock(&proc->prealloc_file_lock);
	prealloc_entry = list_first_entry(&proc->prealloc_file_list,
		struct fbmm_prealloc_entry, node);
	list_del(&prealloc_entry->node);
	spin_unlock(&proc->prealloc_file_lock);

	file = prealloc_entry->file;
	kfree(prealloc_entry);

	// Should we sure up the number of files?
	if (atomic_read(&proc->num_prealloc_files) < 3)
		fbmm_add_work_order(proc);

	return file;
}

///////////////////////////////////////////////////////////////////////////////
// Helper functions

static void drop_fbmm_file(struct fbmm_file *file) {
	filp_close(file->f, current->files);
	fput(file->f);
	kfree(file);
}

///////////////////////////////////////////////////////////////////////////////
// External API functions

bool use_file_based_mm(pid_t pid) {
	if (fbmm_state == FBMM_OFF) {
		return false;
	} if (fbmm_state == FBMM_SELECTED_PROCS) {
		return mtree_load(&fbmm_proc_mt, pid) != NULL;
	} else if (fbmm_state == FBMM_ALL) {
		return true;
	}

	// Should never reach here
	return false;
}

unsigned long fbmm_get_unmapped_area(unsigned long addr, unsigned long len,
		unsigned long pgoff, unsigned long flags)
{
	struct fbmm_proc *proc;

	proc = mtree_load(&fbmm_proc_mt, current->tgid);
	if (!proc) {
		return -EINVAL;
	}

	return get_unmapped_area(proc->get_unmapped_area_file, addr, len, pgoff, flags);
}

struct file *fbmm_get_file(unsigned long addr, unsigned long len,
		unsigned long prot, int flags, bool mmap, unsigned long *pgoff) {
	struct file *f;
	struct fbmm_file *fbmm_file;
	struct fbmm_proc *proc;
	struct path *path;
	int open_flags = O_EXCL | O_TMPFILE;
	unsigned long truncate_len;
	umode_t open_mode = S_IFREG;
	s64 ret = 0;
	u64 start_time = rdtsc();
	u64 end_time;

	proc = mtree_load(&fbmm_proc_mt, current->tgid);
	if (!proc) {
		return NULL;
	}

	// Does a file exist that will already fit this mmap call?
	fbmm_file = mt_prev(&proc->files_mt, addr + 1, 0);
	if (fbmm_file) {
		// Just see if this mmap will fit inside the file.
		// We don't need to check if other mappings in the file
		// overlap because get_unmapped_area should have done that already.
		if (fbmm_file->va_start <= addr && addr + len <= fbmm_file->va_end) {
			f = fbmm_file->f;
			goto end;
		}
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
		return NULL;
	}

	// Try to get a preallocated file, and if that doesn't work
	// just make one
	f = NULL;//fbmm_get_prealloc_file(proc);
	if (!f) {
		path = &proc->mnt_dir_path;
		f = file_open_root(path, "", open_flags, open_mode);
		if (IS_ERR(f)) {
			return f;
		}
	}

	// Set the file to the correct size
	if (len < FBMM_DEFAULT_FILE_SIZE)
		truncate_len = FBMM_DEFAULT_FILE_SIZE;
	else
		truncate_len = len;
	ret = vfs_truncate(&f->f_path, truncate_len);
	if (ret) {
		filp_close(f, current->files);
		return (struct file *)ret;
	}

	// Create a new struct fbmm_file for this file
	fbmm_file = kmalloc(sizeof(struct fbmm_file), GFP_KERNEL);
	if (!fbmm_file) {
		filp_close(f, current->files);
		return NULL;
	}
	fbmm_file->f = f;
	if (mmap) {
		// Since VAs in the mmap region typically grow down,
		// this mapping will be the "end" of the file
		fbmm_file->va_end = addr + len;
		fbmm_file->va_start = fbmm_file->va_end - truncate_len;
	} else {
		// VAs in the heap region grow up
		fbmm_file->va_start = addr;
		fbmm_file->va_end = addr + truncate_len;
	}

	mtree_store(&proc->files_mt, fbmm_file->va_start, fbmm_file, GFP_KERNEL);

end:
	if (f && !IS_ERR(f)) {
		*pgoff = (addr - fbmm_file->va_start) >> PAGE_SHIFT;
	}
	end_time = rdtsc();
	spin_lock(&stats_lock);
	file_create_time += end_time - start_time;
	num_file_creates++;
	spin_unlock(&stats_lock);

	return f;
}

void fbmm_populate_file(unsigned long start, unsigned long len)
{
	struct fbmm_proc *proc;
	struct fbmm_file *file = NULL;
	loff_t offset;
	u64 start_time = rdtsc();
	u64 end_time;

	proc = mtree_load(&fbmm_proc_mt, current->tgid);
	// Create the proc data structure if it does not already exist
	if (!proc) {
		BUG();
	}

	file = mt_prev(&proc->files_mt, start, 0);
	if (!file || file->va_end <= start) {
		BUG();
	}

	offset = start - file->va_start;
	vfs_fallocate(file->f, 0, offset, len);

	end_time = rdtsc();
	spin_lock(&stats_lock);
	file_register_time += end_time - start_time;
	num_file_registers++;
	spin_unlock(&stats_lock);

	return;
}

int fbmm_munmap(pid_t pid, unsigned long start, unsigned long len) {
	struct fbmm_proc *proc = NULL;
	struct fbmm_file *fbmm_file = NULL;
	unsigned long end = start + len;
	unsigned long falloc_offset, falloc_len;
	int ret = 0;
	u64 start_time = rdtsc();
	u64 end_time;

	proc = mtree_load(&fbmm_proc_mt, pid);

	if (!proc)
		return 0;

	// a munmap call can span multiple memory ranges, so we might have to do this
	// multiple times
	while (start < end) {
		unsigned long next_start;

		// Finds the first mapping where file->va_start <= start, so we have to
		// check this file is actually within the range
		fbmm_file = mt_prev(&proc->files_mt, start + 1, 0);
		if (!fbmm_file || fbmm_file->va_end <= start)
			goto exit;

		next_start = fbmm_file->va_end;

		falloc_offset = start - fbmm_file->va_start;
		if (fbmm_file->va_end <= end)
			falloc_len = fbmm_file->va_end - start;
		else
			falloc_len = end - start;

		ret = vfs_fallocate(fbmm_file->f,
				FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
				falloc_offset, falloc_len);

		start = next_start;
	}

exit:
	end_time = rdtsc();
	spin_lock(&stats_lock);
	munmap_time += end_time - start_time;
	num_munmaps++;
	spin_unlock(&stats_lock);

	return ret;
}

void fbmm_check_exiting_proc(pid_t pid) {
	struct fbmm_proc *proc;
	struct fbmm_file *file;
	unsigned long index = 0;

	proc = mtree_erase(&fbmm_proc_mt, pid);

	if (!proc)
		return;

	mt_for_each(&proc->files_mt, file, index, ULONG_MAX) {
		drop_fbmm_file(file);
	}
	mtree_destroy(&proc->files_mt);

	fbmm_put_proc(proc);
}

// Make the default mmfs dir of the dst the same as src
int fbmm_copy_mnt_dir(pid_t src, pid_t dst) {
	struct fbmm_proc *proc;
	struct fbmm_proc *new_proc;
	char *buffer;
	char *src_dir;
	size_t len;

	// noop
	if (src == dst)
		return 0;

	// Does the src actually have a default mnt dir
	proc = mtree_load(&fbmm_proc_mt, src);
	if (!proc)
		return -1;

	src_dir = proc->mnt_dir_str;

	len = strnlen(src_dir, PATH_MAX);
	buffer = kmalloc(PATH_MAX + 1, GFP_KERNEL);
	strncpy(buffer, src_dir, len + 1);

	new_proc = fbmm_create_new_proc(buffer, dst);

	return mtree_store(&fbmm_proc_mt, dst, new_proc, GFP_KERNEL);
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

		if (!fbmm_file_create_thread && fbmm_state > FBMM_OFF)
			fbmm_file_create_thread = kthread_create(fbmm_prealloc_task, NULL, "FBMM File Create");
		return count;
	} else {
		fbmm_state = FBMM_OFF;
		return -EINVAL;
	}
}
static struct kobj_attribute fbmm_state_attribute =
__ATTR(state, 0644, fbmm_state_show, fbmm_state_store);

static ssize_t fbmm_stats_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
    u64 avg_create_time = 0;
    u64 avg_register_time = 0;
    u64 avg_munmap_time = 0;
    ssize_t count;

    if (num_file_creates != 0) {
        avg_create_time = file_create_time / num_file_creates;
    }
    if (num_file_registers != 0) {
        avg_register_time = file_register_time / num_file_registers;
    }
    if (num_munmaps != 0) {
        avg_munmap_time = munmap_time / num_munmaps;
    }

    count = sprintf(buf, "file create times: %lld %lld %lld\n", file_create_time,
        num_file_creates, avg_create_time);
    count += sprintf(&buf[count], "file register times: %lld %lld %lld\n", file_register_time,
        num_file_registers, avg_register_time);
    count += sprintf(&buf[count], "munmap times: %lld %lld %lld\n", munmap_time,
        num_munmaps, avg_munmap_time);

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
	munmap_time = 0;
	num_munmaps = 0;
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
// procfs files
extern inline struct task_struct *extern_get_proc_task(const struct inode *inode);

static ssize_t fbmm_mnt_dir_read(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos)
{
	struct task_struct *task = extern_get_proc_task(file_inode(file));
	char *buffer;
	struct fbmm_proc *proc;
	size_t len, ret;

	if (!task)
		return -ESRCH;

	buffer = kmalloc(PATH_MAX + 1, GFP_KERNEL);
	if (!buffer) {
		put_task_struct(task);
		return -ENOMEM;
	}

	// See if the selected task has an entry in the maple tree
	proc = mtree_load(&fbmm_proc_mt, task->tgid);
	if (proc)
		len = sprintf(buffer, "%s\n", proc->mnt_dir_str);
	else
		len = sprintf(buffer, "not enabled\n");

	ret = simple_read_from_buffer(ubuf, count, ppos, buffer, len);

	kfree(buffer);
	put_task_struct(task);

	return ret;
}

static ssize_t fbmm_mnt_dir_write(struct file *file, const char __user *ubuf,
        size_t count, loff_t *ppos)
{
	struct task_struct *task;
	struct path p;
	char *buffer;
	struct fbmm_proc *proc;
	bool clear_entry = true;
	int ret = 0;

	if (count > PATH_MAX) {
		return -ENOMEM;
	}

	buffer = kmalloc(count + 1, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	if (copy_from_user(buffer, ubuf, count)) {
		kfree(buffer);
		return -EFAULT;
	}
	buffer[count] = 0;

	// echo likes to put an extra \n at the end of the string
	// if it's there, remove it
	if (buffer[count - 1] == '\n')
		buffer[count - 1] = 0;

	task = extern_get_proc_task(file_inode(file));
	if (!task) {
		kfree(buffer);
		return -ESRCH;
	}

	// Check if the given path is actually a valid directory
	ret = kern_path(buffer, LOOKUP_DIRECTORY | LOOKUP_FOLLOW, &p);
	if (!ret)
		clear_entry = false;

	if (!clear_entry) {
		proc = mtree_load(&fbmm_proc_mt, task->tgid);

		if (!proc) {
			proc = fbmm_create_new_proc(buffer, task->tgid);
			ret = mtree_store(&fbmm_proc_mt, task->tgid, proc, GFP_KERNEL);
		} else {
			proc->mnt_dir_str = buffer;
			ret = kern_path(buffer, LOOKUP_DIRECTORY | LOOKUP_FOLLOW, &proc->mnt_dir_path);
		}

	} else {
		// We don't need the buffer we created anymore
		kfree(buffer);

		// If the previous entry stored a value, free it
		proc = mtree_erase(&fbmm_proc_mt, task->tgid);
		if (proc)
			fbmm_put_proc(proc);
	}

	put_task_struct(task);
	if (ret)
		return ret;
	return count;
}

const struct file_operations proc_fbmm_mnt_dir = {
	.read = fbmm_mnt_dir_read,
	.write = fbmm_mnt_dir_write,
	.llseek = default_llseek,
};


///////////////////////////////////////////////////////////////////////////////
// Init
static int __init file_based_mm_init(void)
{
	struct kobject *fbmm_kobj;
	int err;

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
