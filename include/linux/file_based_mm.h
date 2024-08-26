/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _FILE_BASED_MM_H_
#define _FILE_BASED_MM_H_

#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/maple_tree.h>

struct fbmm_info {
	char *mnt_dir_str;
	struct path mnt_dir_path;
	/* This file exists just to be passed to get_unmapped_area in mmap */
	struct file *get_unmapped_area_file;
	struct maple_tree files_mt;
	struct list_head cow_files;
};


#ifdef CONFIG_FILE_BASED_MM
extern const struct file_operations proc_fbmm_mnt_dir;

bool use_file_based_mm(struct task_struct *task);

bool is_vm_fbmm_page(struct vm_area_struct *vma);
int fbmm_fault(struct vm_area_struct *vma, unsigned long address, unsigned int flags);
unsigned long fbmm_get_unmapped_area(unsigned long addr, unsigned long len, unsigned long pgoff,
	unsigned long flags);
struct file *fbmm_get_file(struct task_struct *tsk, unsigned long addr, unsigned long len,
	unsigned long prot, int flags, bool topdown, unsigned long *pgoff);
void fbmm_populate_file(unsigned long start, unsigned long len);
int fbmm_munmap(struct task_struct *tsk, unsigned long start, unsigned long len);
void fbmm_exit(struct task_struct *tsk);
int fbmm_copy(struct task_struct *src_tsk, struct task_struct *dst_tsk, u64 clone_flags);
int fbmm_add_cow_file(struct task_struct *new_tsk, struct task_struct *old_tsk,
	struct file *file, unsigned long start);
void fbmm_clear_cow_files(struct task_struct *tsk);

/* FBMM helper functions for MFSs */
int fbmm_swapout_folio(struct folio *folio);
int fbmm_writepage(struct page *page, struct writeback_control *wbc);
struct page *fbmm_read_swap_entry(struct vm_fault *vmf, swp_entry_t entry, unsigned long pgoff,
	struct page *page);
int fbmm_copy_page_range(struct vm_area_struct *dst, struct vm_area_struct *src);

#else /* CONFIG_FILE_BASED_MM */

static inline bool is_vm_fbmm_page(struct vm_area_struct *vma)
{
	return 0;
}

static inline bool use_file_based_mm(struct task_struct *tsk)
{
	return false;
}

static inline int fbmm_fault(struct vm_area_struct *vma, unsigned long address, unsigned int flags)
{
	return 0;
}

static inline unsigned long fbmm_get_unmapped_area(unsigned long addr, unsigned long len,
		unsigned long pgoff, unsigned long flags)
{
	return 0;
}

static inline struct file *fbmm_get_file(struct task_struct *tsk, unsigned long addr,
		unsigned long len, unsigned long prot, int flags, bool topdown,
		unsigned long *pgoff)
{
	return NULL;
}

static inline void fbmm_populate_file(unsigned long start, unsigned long len) {}

static inline int fbmm_munmap(struct task_struct *tsk, unsigned long start, unsigned long len)
{
	return 0;
}

static inline void fbmm_exit(struct task_struct *tsk) {}

static inline int fbmm_copy(struct task_struct *src_tsk, struct task_struct *dst_tsk,
		u64 clone_flags)
{
	return 0;
}

static inline int fbmm_add_cow_file(struct task_struct *new_tsk, struct task_struct *old_tsk,
	struct file *file, unsigned long start) {
	return 0;
}

static inline void fbmm_clear_cow_files(struct task_struct *tsk) {}
#endif /* CONFIG_FILE_BASED_MM */

#endif /* __FILE_BASED_MM_H */
