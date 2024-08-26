// SPDX-License-Identifier: GPL-2.0-only
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

#include "proc/internal.h"

enum file_based_mm_state {
	FBMM_OFF = 0,
	FBMM_ON = 1,
};

#define FBMM_DEFAULT_FILE_SIZE (128L << 30)
struct fbmm_file {
	struct file *f;
	/* The starting virtual address assigned to this file (inclusive) */
	unsigned long va_start;
	/* The ending virtual address assigned to this file (exclusive) */
	unsigned long va_end;
	atomic_t refcount;
};

struct fbmm_cow_list_entry {
	struct list_head node;
	struct fbmm_file *file;
};

static enum file_based_mm_state fbmm_state = FBMM_OFF;

const int GUA_OPEN_FLAGS = O_EXCL | O_TMPFILE | O_RDWR;
const umode_t GUA_OPEN_MODE = S_IFREG | 0600;

static struct fbmm_info *fbmm_create_new_info(char *mnt_dir_str)
{
	struct fbmm_info *info;

	info = kmalloc(sizeof(struct fbmm_info), GFP_KERNEL);
	if (!info)
		return NULL;

	info->mnt_dir_str = mnt_dir_str;
	kern_path(mnt_dir_str, LOOKUP_DIRECTORY | LOOKUP_FOLLOW, &info->mnt_dir_path);
	info->get_unmapped_area_file = file_open_root(&info->mnt_dir_path, "",
		GUA_OPEN_FLAGS, GUA_OPEN_MODE);
	if (IS_ERR(info->get_unmapped_area_file))
		return NULL;
	mt_init(&info->files_mt);
	INIT_LIST_HEAD(&info->cow_files);

	return info;
}

static void drop_fbmm_file(struct fbmm_file *file)
{
	if (atomic_dec_return(&file->refcount) == 0) {
		fput(file->f);
		kfree(file);
	}
}

static void get_fbmm_file(struct fbmm_file *file)
{
	atomic_inc(&file->refcount);
}

static pmdval_t fbmm_alloc_pmd(struct vm_fault *vmf)
{
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

inline bool is_vm_fbmm_page(struct vm_area_struct *vma)
{
	return !!(vma->vm_flags & VM_FBMM);
}

int fbmm_fault(struct vm_area_struct *vma, unsigned long address, unsigned int flags)
{
	struct vm_fault vmf = {
		.vma = vma,
		.address = address & PAGE_MASK,
		.real_address = address,
		.flags = flags,
		.pgoff = linear_page_index(vma, address),
		.gfp_mask = mapping_gfp_mask(vma->vm_file->f_mapping) | __GFP_FS | __GFP_IO,
	};

	if (fbmm_alloc_pmd(&vmf) == VM_FAULT_OOM)
		return VM_FAULT_OOM;

	return vma->vm_ops->fault(&vmf);
}

bool use_file_based_mm(struct task_struct *tsk)
{
	if (fbmm_state == FBMM_OFF)
		return false;
	else
		return tsk->fbmm_info && tsk->fbmm_info->mnt_dir_str;
}

unsigned long fbmm_get_unmapped_area(unsigned long addr, unsigned long len,
		unsigned long pgoff, unsigned long flags)
{
	struct fbmm_info *info;

	info = current->fbmm_info;
	if (!info)
		return -EINVAL;

	return get_unmapped_area(info->get_unmapped_area_file, addr, len, pgoff, flags);
}

struct file *fbmm_get_file(struct task_struct *tsk, unsigned long addr, unsigned long len,
		unsigned long prot, int flags, bool topdown, unsigned long *pgoff)
{
	struct file *f;
	struct fbmm_file *fbmm_file;
	struct fbmm_info *info;
	struct path *path;
	int open_flags = O_EXCL | O_TMPFILE;
	unsigned long truncate_len;
	umode_t open_mode = S_IFREG;
	s64 ret = 0;

	info = tsk->fbmm_info;
	if (!info)
		return NULL;

	/* Does a file exist that will already fit this mmap call? */
	fbmm_file = mt_prev(&info->files_mt, addr + 1, 0);
	if (fbmm_file) {
		/*
		 * Just see if this mmap will fit inside the file.
		 * We don't need to check if other mappings in the file overlap
		 * because get_unmapped_area should have done that already.
		 */
		if (fbmm_file->va_start <= addr && addr + len <= fbmm_file->va_end) {
			f = fbmm_file->f;
			goto end;
		}
	}

	/* Determine what flags to use for the call to open */
	if (prot & PROT_EXEC)
		open_mode |= 0100;

	if ((prot & (PROT_READ | PROT_WRITE)) == (PROT_READ | PROT_WRITE)) {
		open_flags |= O_RDWR;
		open_mode |= 0600;
	} else if (prot & PROT_WRITE) {
		open_flags |= O_WRONLY;
		open_mode |= 0200;
	} else if (prot & PROT_READ) {
		/* It doesn't make sense for anon memory to be read only */
		return NULL;
	}

	path = &info->mnt_dir_path;
	f = file_open_root(path, "", open_flags, open_mode);
	if (IS_ERR(f))
		return f;

	/*
	 * It takes time to create new files and create new VMAs for mappings
	 * with different files, so we want to create huge files that we can reuse
	 * for different calls to mmap
	 */
	if (len < FBMM_DEFAULT_FILE_SIZE)
		truncate_len = FBMM_DEFAULT_FILE_SIZE;
	else
		truncate_len = len;
	ret = vfs_truncate(&f->f_path, truncate_len);
	if (ret) {
		filp_close(f, current->files);
		return (struct file *)ret;
	}

	fbmm_file = kmalloc(sizeof(struct fbmm_file), GFP_KERNEL);
	if (!fbmm_file) {
		filp_close(f, current->files);
		return NULL;
	}
	fbmm_file->f = f;
	atomic_set(&fbmm_file->refcount, 1);
	if (topdown) {
		/*
		 * Since VAs in this region grow down, this mapping will be the
		 * "end" of the file
		 */
		fbmm_file->va_end = addr + len;
		fbmm_file->va_start = fbmm_file->va_end - truncate_len;
	} else {
		fbmm_file->va_start = addr;
		fbmm_file->va_end = addr + truncate_len;
	}

	mtree_store(&info->files_mt, fbmm_file->va_start, fbmm_file, GFP_KERNEL);

end:
	if (f && !IS_ERR(f))
		*pgoff = (addr - fbmm_file->va_start) >> PAGE_SHIFT;

	return f;
}

void fbmm_populate_file(unsigned long start, unsigned long len)
{
	struct fbmm_info *info;
	struct fbmm_file *file = NULL;
	loff_t offset;

	info = current->fbmm_info;
	if (!info)
		return;

	file = mt_prev(&info->files_mt, start, 0);
	if (!file || file->va_end <= start)
		return;

	offset = start - file->va_start;
	vfs_fallocate(file->f, 0, offset, len);
}

int fbmm_munmap(struct task_struct *tsk, unsigned long start, unsigned long len)
{
	struct fbmm_info *info = NULL;
	struct fbmm_file *fbmm_file = NULL;
	struct fbmm_file *prev_file = NULL;
	unsigned long end = start + len;
	unsigned long falloc_start_offset, falloc_end_offset, falloc_len;
	int ret = 0;

	info = tsk->fbmm_info;
	if (!info)
		return 0;

	/*
	 * Finds the last (by va_start) mapping where file->va_start <= start, so we have to
	 * check this file is actually within the range
	 */
	fbmm_file = mt_prev(&info->files_mt, start + 1, 0);
	if (!fbmm_file || fbmm_file->va_end <= start)
		goto exit;

	/*
	 * Since the ranges overlap, we have to keep going backwards until we
	 * the first mapping where file->va_start <= start and file->va_end > start
	 */
	while (1) {
		prev_file = mt_prev(&info->files_mt, fbmm_file->va_start, 0);
		if (!prev_file || prev_file->va_end <= start)
			break;
		fbmm_file = prev_file;
	}

	/*
	 * A munmap call can span multiple memory ranges, so we might have to do this
	 * multiple times
	 */
	while (fbmm_file) {
		if (start > fbmm_file->va_start)
			falloc_start_offset = start - fbmm_file->va_start;
		else
			falloc_start_offset = 0;

		if (fbmm_file->va_end <= end)
			falloc_end_offset = fbmm_file->va_end - fbmm_file->va_start;
		else
			falloc_end_offset = end - fbmm_file->va_start;

		falloc_len = falloc_end_offset - falloc_start_offset;

		/*
		 * Because shared mappings via fork are hard, only punch a hole if there
		 * is only one proc using this file.
		 * It would be nice to be able to free the memory if all procs sharing
		 * the file have unmapped it, but that would require tracking usage at
		 * a page granularity.
		 */
		if (atomic_read(&fbmm_file->refcount) == 1) {
			ret = vfs_fallocate(fbmm_file->f,
					FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
					falloc_start_offset, falloc_len);
		}

		fbmm_file = mt_next(&info->files_mt, fbmm_file->va_start, ULONG_MAX);
		if (!fbmm_file || fbmm_file->va_end <= start)
			break;
	}

exit:
	return ret;
}

void fbmm_exit(struct task_struct *tsk)
{
	struct fbmm_info *info;
	struct fbmm_file *file;
	unsigned long index = 0;

	if (tsk->tgid != tsk->pid)
		return;

	info = tsk->fbmm_info;
	if (!info)
		return;

	mt_for_each(&info->files_mt, file, index, ULONG_MAX) {
		drop_fbmm_file(file);
	}
	mtree_destroy(&info->files_mt);

	fbmm_clear_cow_files(tsk);

	if (info->mnt_dir_str) {
		path_put(&info->mnt_dir_path);
		fput(info->get_unmapped_area_file);
		kfree(info->mnt_dir_str);
	}
	kfree(info);
}

int fbmm_copy(struct task_struct *src_tsk, struct task_struct *dst_tsk, u64 clone_flags)
{
	struct fbmm_info *info;
	struct fbmm_cow_list_entry *src_cow, *dst_cow;
	char *buffer;
	char *src_dir;

	/* If this new task is just a thread, not a new process, just copy fbmm info */
	if (clone_flags & CLONE_THREAD) {
		dst_tsk->fbmm_info = src_tsk->fbmm_info;
		return 0;
	}

	/* Does the src actually have a default mnt dir */
	if (!use_file_based_mm(src_tsk)) {
		dst_tsk->fbmm_info = NULL;
		return 0;
	}
	info = src_tsk->fbmm_info;

	/* Make a new fbmm_info with the same mnt dir */
	src_dir = info->mnt_dir_str;

	buffer = kstrndup(src_dir, PATH_MAX, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	dst_tsk->fbmm_info = fbmm_create_new_info(buffer);
	if (!dst_tsk->fbmm_info)
		return -ENOMEM;

	/*
	 * If the source has CoW files, they may also be CoW files in the destination
	 * so we need to copy that too
	 */
	list_for_each_entry(src_cow, &info->cow_files, node) {
		dst_cow = kmalloc(sizeof(struct fbmm_cow_list_entry), GFP_KERNEL);
		if (!dst_cow)
			return -ENOMEM;

		get_fbmm_file(src_cow->file);
		dst_cow->file = src_cow->file;

		list_add(&dst_cow->node, &dst_tsk->fbmm_info->cow_files);
	}

	return 0;
}

int fbmm_add_cow_file(struct task_struct *new_tsk, struct task_struct *old_tsk,
		struct file *file, unsigned long start)
{
	struct fbmm_info *new_info;
	struct fbmm_info *old_info;
	struct fbmm_file *fbmm_file;
	struct fbmm_cow_list_entry *cow_entry;
	unsigned long search_start = start + 1;

	new_info = new_tsk->fbmm_info;
	old_info = old_tsk->fbmm_info;
	if (!new_info || !old_info)
		return -EINVAL;

	/*
	 * Find the fbmm_file that corresponds with the struct file.
	 * fbmm files can overlap, so make sure to find the one that corresponds
	 * to this file
	 */
	do {
		fbmm_file = mt_prev(&old_info->files_mt, search_start, 0);
		if (!fbmm_file || fbmm_file->va_end <= start) {
			/* Could not find the corressponding fbmm file */
			return -ENOMEM;
		}
		search_start = fbmm_file->va_start;
	} while (fbmm_file->f != file);

	cow_entry = kmalloc(sizeof(struct fbmm_cow_list_entry), GFP_KERNEL);
	if (!cow_entry)
		return -ENOMEM;

	get_fbmm_file(fbmm_file);
	cow_entry->file = fbmm_file;

	list_add(&cow_entry->node, &new_info->cow_files);
	return 0;
}

void fbmm_clear_cow_files(struct task_struct *tsk)
{
	struct fbmm_info *info;
	struct fbmm_cow_list_entry *cow_entry, *tmp;

	info = tsk->fbmm_info;
	if (!info)
		return;

	list_for_each_entry_safe(cow_entry, tmp, &info->cow_files, node) {
		list_del(&cow_entry->node);

		drop_fbmm_file(cow_entry->file);
		kfree(cow_entry);
	}
}

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
	} else if (state == 0) {
		fbmm_state = FBMM_OFF;
	} else {
		fbmm_state = FBMM_ON;
	}
	return count;
}
static struct kobj_attribute fbmm_state_attribute =
__ATTR(state, 0644, fbmm_state_show, fbmm_state_store);

static struct attribute *file_based_mm_attr[] = {
	&fbmm_state_attribute.attr,
	NULL,
};

static const struct attribute_group file_based_mm_attr_group = {
	.attrs = file_based_mm_attr,
};

static ssize_t fbmm_mnt_dir_read(struct file *file, char __user *ubuf,
		size_t count, loff_t *ppos)
{
	struct task_struct *task = get_proc_task(file_inode(file));
	char *buffer;
	struct fbmm_info *info;
	size_t len, ret;

	if (!task)
		return -ESRCH;

	buffer = kmalloc(PATH_MAX + 1, GFP_KERNEL);
	if (!buffer) {
		put_task_struct(task);
		return -ENOMEM;
	}

	info = task->fbmm_info;
	if (info && info->mnt_dir_str)
		len = sprintf(buffer, "%s\n", info->mnt_dir_str);
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
	struct fbmm_info *info;
	int ret = 0;

	if (count > PATH_MAX)
		return -ENOMEM;

	buffer = kmalloc(count + 1, GFP_KERNEL);
	if (!buffer)
		return -ENOMEM;

	if (copy_from_user(buffer, ubuf, count)) {
		kfree(buffer);
		return -EFAULT;
	}
	buffer[count] = 0;

	/*
	 * echo likes to put an extra \n at the end of the string
	 * if it's there, remove it
	 */
	if (buffer[count - 1] == '\n')
		buffer[count - 1] = 0;

	task = get_proc_task(file_inode(file));
	if (!task) {
		kfree(buffer);
		return -ESRCH;
	}

	/* Check if the given path is actually a valid directory */
	ret = kern_path(buffer, LOOKUP_DIRECTORY | LOOKUP_FOLLOW, &p);
	if (!ret) {
		path_put(&p);
		info = task->fbmm_info;

		if (!info) {
			info = fbmm_create_new_info(buffer);
			task->fbmm_info = info;
			if (!info)
				ret = -ENOMEM;
		} else {
			/*
			 * Cleanup the old directory info, but keep the fbmm files
			 * stuff because the application may still be using them
			 */
			if (info->mnt_dir_str) {
				path_put(&info->mnt_dir_path);
				fput(info->get_unmapped_area_file);
				kfree(info->mnt_dir_str);
			}

			info->mnt_dir_str = buffer;
			ret = kern_path(buffer, LOOKUP_DIRECTORY | LOOKUP_FOLLOW,
				&info->mnt_dir_path);
			if (ret)
				goto end;

			fput(info->get_unmapped_area_file);
			info->get_unmapped_area_file = file_open_root(&info->mnt_dir_path, "",
				GUA_OPEN_FLAGS, GUA_OPEN_MODE);
			if (IS_ERR(info->get_unmapped_area_file))
				ret = PTR_ERR(info->get_unmapped_area_file);
		}
	} else {
		kfree(buffer);

		info = task->fbmm_info;
		if (info && info->mnt_dir_str) {
			kfree(info->mnt_dir_str);
			path_put(&info->mnt_dir_path);
			fput(info->get_unmapped_area_file);
			info->mnt_dir_str = NULL;
		}
	}

end:
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


static int __init file_based_mm_init(void)
{
	struct kobject *fbmm_kobj;
	int err;

	fbmm_kobj = kobject_create_and_add("fbmm", mm_kobj);
	if (unlikely(!fbmm_kobj)) {
		pr_warn("failed to create the fbmm kobject\n");
		return -ENOMEM;
	}

	err = sysfs_create_group(fbmm_kobj, &file_based_mm_attr_group);
	if (err) {
		pr_warn("failed to register the fbmm group\n");
		kobject_put(fbmm_kobj);
		return err;
	}

	return 0;
}
subsys_initcall(file_based_mm_init);
