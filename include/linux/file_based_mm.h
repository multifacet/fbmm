#ifndef _FILE_BASED_MM_H_
#define _FILE_BASED_MM_H_

#include <linux/types.h>
#include <linux/fs.h>

#ifdef CONFIG_FILE_BASED_MM

extern const struct file_operations proc_fbmm_mnt_dir;

bool use_file_based_mm(pid_t pid);

struct file *fbmm_create_new_file(unsigned long len, unsigned long prot, int flags);
void fbmm_register_file(pid_t pid, struct file *f, unsigned long start,
		unsigned long len);
int fbmm_munmap(pid_t pid, unsigned long start, unsigned long len);
void fbmm_check_exiting_proc(pid_t pid);
int fbmm_copy_mnt_dir(pid_t src, pid_t dst);

#else //CONFIG_FILE_BASED_MM

inline bool use_file_based_mm(pid_t pid) {
	return false;
}

inline struct file *fbmm_create_new_file(unsigned long len, unsigned long prot, int flags) {
	return NULL;
}

inline void fbmm_register_file(pid_t pid, struct file *f, unsigned long start,
		unsigned long len)
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
