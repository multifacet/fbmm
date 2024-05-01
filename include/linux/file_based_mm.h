#ifndef _FILE_BASED_MM_H_
#define _FILE_BASED_MM_H_

#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/fs.h>
#include <linux/maple_tree.h>

struct fbmm_proc {
	char *mnt_dir_str;
	struct path mnt_dir_path;
	// This file exists just to be passed to get_unmapped_area in mmap
	struct file *get_unmapped_area_file;
	struct maple_tree files_mt;
	struct list_head cow_files;
	atomic_t refcount;
};


#ifdef CONFIG_FILE_BASED_MM
extern const struct file_operations proc_fbmm_mnt_dir;

bool use_file_based_mm(struct task_struct *task);
bool fbmm_enabled(void);

bool is_vm_fbmm_page(struct vm_area_struct *vma);
int fbmm_fault(struct vm_area_struct *vma, unsigned long address, unsigned int flags);
unsigned long fbmm_get_unmapped_area(unsigned long addr, unsigned long len, unsigned long pgoff, unsigned long flags);
struct file *fbmm_get_file(struct task_struct *tsk,unsigned long addr, unsigned long len,
	unsigned long prot, int flags, bool mmap, unsigned long *pgoff);
void fbmm_populate_file(unsigned long start, unsigned long len);
int fbmm_munmap(struct task_struct *tsk, unsigned long start, unsigned long len);
void fbmm_exit(struct task_struct *tsk);
int fbmm_copy(struct task_struct *src_tsk, struct task_struct *dst_tsk);
void fbmm_add_cow_file(struct task_struct *new_tsk, struct task_struct *old_tsk,
	struct file *file, unsigned long start);

// FBMM Helper functions for MFSs
bool fbmm_swapout_folio(struct folio *folio);
int fbmm_writepage(struct page *page, struct writeback_control *wbc);
struct page *fbmm_read_swap_entry(struct vm_fault *vmf, swp_entry_t entry, unsigned long pgoff, struct page *page);
int fbmm_copy_page_range(struct vm_area_struct *dst, struct vm_area_struct *src);

#else //CONFIG_FILE_BASED_MM

inline bool is_vm_fbmm_page(struct vm_area_struct *vma) {
    return 0;
}

inline bool use_file_based_mm(pid_t pid) {
	return false;
}

int fbmm_fault(struct vm_area_struct *vma, unsigned long address, unsigned int flags) {
    return 0;
}

unsigned long fbmm_get_unmapped_area(unsigned long addr, unsigned long len, unsigned long pgoff, unsigned long flags) {
	return 0;
}

inline struct file *fbmm_get_file(struct task_struct *tsk, unsigned long addr, unsigned long len, unsigned long prot,
        int flags, bool mmap, unsigned long *pgoff) {
	return NULL;
}

inline void fbmm_populate_file(unsigned long start, unsigned long len)
{}

inline int fbmm_munmap(struct task_struct *tsk, unsigned long start, unsigned long len) {
	return 0;
}

inline void fbmm_exit(struct task_struct *tsk) {}

int fbmm_copy(struct task_struct *tsk, struct task_struct *tsk) {
	return 0;
}

void fbmm_add_cow_file(struct task_struct *new_tsk, struct task_struct *old_tsk,
	struct file *file, unsigned long start) {

}
#endif //CONFIG_FILE_BASED_MM

#endif //__FILE_BASED_MM_H
