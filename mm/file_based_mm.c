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
#include <linux/pagemap.h>
#include <linux/mm.h>

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
	atomic_t refcount;
};

struct fbmm_cow_list_entry {
	struct list_head node;
	struct fbmm_file *file;
};

static enum file_based_mm_state fbmm_state = FBMM_OFF;

static DEFINE_SPINLOCK(stats_lock);
static u64 file_create_time = 0;
static u64 num_file_creates = 0;
static u64 file_register_time = 0;
static u64 num_file_registers = 0;
static u64 munmap_time = 0;
static u64 num_munmaps = 0;

static int fbmm_prealloc_map_populate = 1;

///////////////////////////////////////////////////////////////////////////////
// struct fbmm_proc functions

static struct fbmm_proc *fbmm_create_new_proc(char *mnt_dir_str) {
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
	mt_init(&proc->files_mt);
	atomic_set(&proc->refcount, 1);
	INIT_LIST_HEAD(&proc->cow_files);

	return proc;
}

static void fbmm_put_proc(struct fbmm_proc *proc) {
	// Only free the contents if the refcount becomes 0
	if (atomic_dec_return(&proc->refcount) == 0) {
		kfree(proc->mnt_dir_str);
		path_put(&proc->mnt_dir_path);

		kfree(proc);
	}
}

///////////////////////////////////////////////////////////////////////////////
// Helper functions

static void drop_fbmm_file(struct fbmm_file *file) {
	// Only free if this is the last proc dropping the file
	if (atomic_dec_return(&file->refcount) == 0) {
		vfs_fallocate(file->f,
				FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
				0, FBMM_DEFAULT_FILE_SIZE);
		filp_close(file->f, current->files);
		fput(file->f);
		kfree(file);
	}
}

static void get_fbmm_file(struct fbmm_file *file) {
	atomic_inc(&file->refcount);
}

static pmdval_t fbmm_alloc_pmd(struct vm_fault *vmf) {
	struct mm_struct *mm = vmf->vma->vm_mm;
	unsigned long address = vmf->address;
	pgd_t *pgd;
	p4d_t *p4d;

	pgd = pgd_offset(mm, address);
	p4d = p4d_alloc(mm, pgd, address);
	if (!p4d)
		return VM_FAULT_OOM;

	vmf->pud = pud_alloc(mm, p4d, address);
	if (!vmf->pud)
		return VM_FAULT_OOM;

	vmf->pmd = pmd_alloc(mm, vmf->pud, address);
	if (!vmf->pmd)
		return VM_FAULT_OOM;

	vmf->orig_pmd = pmdp_get_lockless(vmf->pmd);

	return pmd_val(*vmf->pmd);
}

///////////////////////////////////////////////////////////////////////////////
// External API functions
inline bool is_vm_fbmm_page(struct vm_area_struct *vma) {
    return !!(vma->vm_flags & VM_FBMM);
}

int fbmm_fault(struct vm_area_struct *vma, unsigned long address, unsigned int flags) {
	struct vm_fault vmf = {
		.vma = vma,
		.address = address & PAGE_MASK,
		.real_address = address,
		.flags = flags,
		.pgoff = linear_page_index(vma, address),
		.gfp_mask = mapping_gfp_mask(vma->vm_file->f_mapping) | __GFP_FS | __GFP_IO,
		//.gfp_mask = __get_fault_gfp_mask(vma),
	};

	if (fbmm_alloc_pmd(&vmf) == VM_FAULT_OOM)
		return VM_FAULT_OOM;

	return vma->vm_ops->fault(&vmf);
}

bool fbmm_enabled() {
	return fbmm_state != FBMM_OFF;
}

bool use_file_based_mm(struct task_struct *tsk) {
	if (fbmm_state == FBMM_OFF) {
		return false;
	} if (fbmm_state == FBMM_SELECTED_PROCS) {
		return tsk->fbmm_proc != NULL;
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

	proc = current->fbmm_proc;
	if (!proc) {
		return -EINVAL;
	}

	return get_unmapped_area(proc->get_unmapped_area_file, addr, len, pgoff, flags);
}

struct file *fbmm_get_file(struct task_struct *tsk, unsigned long addr, unsigned long len,
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

	proc = tsk->fbmm_proc;
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
	} else {
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
	atomic_set(&fbmm_file->refcount, 1);
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

	proc = current->fbmm_proc;
	// Create the proc data structure if it does not already exist
	if (!proc) {
		return;
	}

	file = mt_prev(&proc->files_mt, start, 0);
	if (!file || file->va_end <= start) {
		return;
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

int fbmm_munmap(struct task_struct *tsk, unsigned long start, unsigned long len) {
	struct fbmm_proc *proc = NULL;
	struct fbmm_file *fbmm_file = NULL;
	struct fbmm_file *prev_file = NULL;
	unsigned long end = start + len;
	unsigned long falloc_start_offset, falloc_end_offset, falloc_len;
	int ret = 0;
	u64 start_time = rdtsc();
	u64 end_time;

	proc = tsk->fbmm_proc;
	if (!proc)
		return 0;

	// Finds the last (by va_start) mapping where file->va_start <= start, so we have to
	// check this file is actually within the range
	fbmm_file = mt_prev(&proc->files_mt, start + 1, 0);
	if (!fbmm_file || fbmm_file->va_end <= start)
		goto exit;

	// Since the ranges overlap, we have to keep going backwards until we
	// the first mapping where file->va_start <= start and file->va_end > start
	while (1) {
		prev_file = mt_prev(&proc->files_mt, fbmm_file->va_start, 0);
		if (!prev_file || prev_file->va_end <= start)
			break;
		fbmm_file = prev_file;
	}

	// a munmap call can span multiple memory ranges, so we might have to do this
	// multiple times
	while (fbmm_file) {
		// Calculate the offset from the start of the file where
		// we should start freeing
		if (start > fbmm_file->va_start)
			falloc_start_offset = start - fbmm_file->va_start;
		else
			falloc_start_offset = 0;

		// Calculate the offset from the start of the file where
		// we should stop freeing
		if (fbmm_file->va_end <= end)
			falloc_end_offset = fbmm_file->va_end - fbmm_file->va_start;
		else
			falloc_end_offset = end - fbmm_file->va_start;

		BUG_ON(falloc_start_offset > falloc_end_offset);
		falloc_len = falloc_end_offset - falloc_start_offset;

		/* 
		 * Because shared mappings via fork are hard, only fallocate
		 * if there is only one proc using this file.
		 * It would be nice to be able to free the memory if all procs sharing
		 * the file have unmapped it, but that would require tracking usage
		 * at a page granularity.
		 */
		if (atomic_read(&fbmm_file->refcount) == 1) {
			ret = vfs_fallocate(fbmm_file->f,
					FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
					falloc_start_offset, falloc_len);
		}

		fbmm_file = mt_next(&proc->files_mt, fbmm_file->va_start, ULONG_MAX);
		if (!fbmm_file || fbmm_file->va_end <= start)
			break;
	}

exit:
	end_time = rdtsc();
	spin_lock(&stats_lock);
	munmap_time += end_time - start_time;
	num_munmaps++;
	spin_unlock(&stats_lock);

	return ret;
}

void fbmm_exit(struct task_struct *tsk) {
	struct fbmm_proc *proc;
	struct fbmm_file *file;
	struct fbmm_cow_list_entry *cow_entry, *tmp;
	unsigned long index = 0;

	if (tsk->tgid != tsk->pid)
		return;

	proc = tsk->fbmm_proc;
	if (!proc)
		return;

	mt_for_each(&proc->files_mt, file, index, ULONG_MAX) {
		drop_fbmm_file(file);
	}
	mtree_destroy(&proc->files_mt);

	list_for_each_entry_safe(cow_entry, tmp, &proc->cow_files, node) {
		list_del(&cow_entry->node);

		drop_fbmm_file(cow_entry->file);
		kfree(cow_entry);
	}

	fbmm_put_proc(proc);
}

int fbmm_copy(struct task_struct *src_tsk, struct task_struct *dst_tsk) {
	struct fbmm_proc *proc;
	struct fbmm_cow_list_entry *src_cow, *dst_cow;
	char *buffer;
	char *src_dir;
	size_t len;

	// Does the src actually have a default mnt dir
	proc = src_tsk->fbmm_proc;
	if (!proc)
		return -1;

	// Make a new fbmm_proc with the same mnt dir
	src_dir = proc->mnt_dir_str;

	len = strnlen(src_dir, PATH_MAX);
	buffer = kmalloc(PATH_MAX + 1, GFP_KERNEL);
	strncpy(buffer, src_dir, len + 1);

	dst_tsk->fbmm_proc = fbmm_create_new_proc(buffer);
    if (!dst_tsk->fbmm_proc) {
        return -1;
    }

	// If the source has CoW files, they may also be CoW files in the destination
	// so we need to copy that too.
	list_for_each_entry(src_cow, &proc->cow_files, node) {
		dst_cow = kmalloc(sizeof(struct fbmm_cow_list_entry), GFP_KERNEL);
		if (!dst_cow) {
			pr_err("fbmm_copy: Could not allocate dst_cow!\n");
			return -1;
		}

		get_fbmm_file(src_cow->file);
		dst_cow->file = src_cow->file;

		list_add(&dst_cow->node, &dst_tsk->fbmm_proc->cow_files);
	}

	return 0;
}

/*
 * fbmm_add_cow_file() - 
 */
void fbmm_add_cow_file(struct task_struct *new_tsk, struct task_struct *old_tsk,
		struct file *file, unsigned long start)
{
	struct fbmm_proc *new_proc;
	struct fbmm_proc *old_proc;
	struct fbmm_file *fbmm_file;
	struct fbmm_cow_list_entry *cow_entry;
	unsigned long search_start = start + 1;

	new_proc = new_tsk->fbmm_proc;
	old_proc = old_tsk->fbmm_proc;
	if (!new_proc) {
		pr_err("fbmm_add_cow_file: new_proc not valid!\n");
		return;
	}
	if (!old_proc) {
		pr_err("fbmm_add_cow_file: old_proc not valid!\n");
		return;
	}

	// Find the fbmm_file that corresponds with the struct file
	// fbmm files can overlap, so make sure to find the one that corresponds
	// to this file
	do {
		fbmm_file = mt_prev(&old_proc->files_mt, search_start, 0);
		if (!fbmm_file || fbmm_file->va_end <= start) {
			pr_err("fbmm_add_cow_file: Could not find fbmm_file\n");
			return;
		}
		search_start = fbmm_file->va_start;
	} while (fbmm_file->f != file);

	cow_entry = kmalloc(sizeof(struct fbmm_cow_list_entry), GFP_KERNEL);
	if (!cow_entry) {
		pr_err("fbmm_add_cow_file: Could not allocate cow_entry!\n");
		return;
	}

	get_fbmm_file(fbmm_file);
	cow_entry->file = fbmm_file;

	list_add(&cow_entry->node, &new_proc->cow_files);
}
///////////////////////////////////////////////////////////////////////////////
// MFS Helper Functions

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
	proc = task->fbmm_proc;
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
	if (!ret) {
		path_put(&p);
		proc = task->fbmm_proc;

		if (!proc) {
			proc = fbmm_create_new_proc(buffer);
			task->fbmm_proc = proc;
			if (!proc)
				ret = -ENOMEM;
		} else {
			proc->mnt_dir_str = buffer;
			ret = kern_path(buffer, LOOKUP_DIRECTORY | LOOKUP_FOLLOW, &proc->mnt_dir_path);
		}

	} else {
		// We don't need the buffer we created anymore
		kfree(buffer);

		// If the previous entry stored a value, free it
		proc = task->fbmm_proc;
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
