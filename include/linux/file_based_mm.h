#ifndef _FILE_BASED_MM_H_
#define _FILE_BASED_MM_H_

#include <linux/types.h>
#include <linux/fs.h>

#ifdef CONFIG_FILE_BASED_MM

extern const struct file_operations proc_fbmm_mnt_dir;

bool use_file_based_mm(pid_t pid);

bool is_vm_fbmm_page(struct vm_area_struct *vma);
int fbmm_fault(struct vm_area_struct *vma, unsigned long address, unsigned int flags);
unsigned long fbmm_get_unmapped_area(unsigned long addr, unsigned long len, unsigned long pgoff, unsigned long flags);
struct file *fbmm_get_file(unsigned long addr, unsigned long len, unsigned long prot, int flags, bool mmap, unsigned long *pgoff);
void fbmm_populate_file(unsigned long start, unsigned long len);
int fbmm_munmap(pid_t pid, unsigned long start, unsigned long len);
void fbmm_check_exiting_proc(pid_t pid);
int fbmm_copy_mnt_dir(pid_t src, pid_t dst);

// FBMM Helper functions for MFSs
bool fbmm_swapout_folio(struct folio *folio);
int fbmm_writepage(struct page *page, struct writeback_control *wbc);
struct page *fbmm_read_swap_entry(struct vm_fault *vmf, swp_entry_t entry, unsigned long pgoff, struct page *page);

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

inline struct file *fbmm_get_file(unsigned long addr, unsigned long len, unsigned long prot, int flags, bool mmap, unsigned long *pgoff) {
	return NULL;
}

inline void fbmm_populate_file(unsigned long start, unsigned long len)
{}

inline int fbmm_munmap(pid_t pid, unsigned long start, unsigned long len) {
	return 0;
}

inline void fbmm_check_exiting_proc(pid_t pid) {}

int fbmm_copy_mnt_dir(pid_t src, pid_t dst) {
	return 0;
}

#endif //CONFIG_FILE_BASED_MM

#endif //__FILE_BASED_MM_H
