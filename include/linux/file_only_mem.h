#ifndef _FILE_ONLY_MEM_H_
#define _FILE_ONLY_MEM_H_

#include <linux/types.h>
#include <linux/fs.h>

#ifdef CONFIG_FILE_ONLY_MEM

bool use_file_only_mem(pid_t pid);

struct file *fom_create_new_file(unsigned long len,	unsigned long prot, int flags);
void fom_register_file(pid_t pid, struct file *f, unsigned long start,
		unsigned long len);
int fom_munmap(pid_t pid, unsigned long start, unsigned long len);
void fom_check_exiting_proc(pid_t pid);

#else //CONFIG_FILE_ONLY_MEM

inline bool use_file_only_mem(pid_t pid) {
	return false;
}

inline struct file *fom_create_new_file(unsigned long len, unsigned long prot, int flags) {
	return NULL;
}

inline void fom_register_file(pid_t pid, struct file *f, unsigned long start,
		unsigned long len)
{}

inline int fom_munmap(pid_t pid, unsigned long start, unsigned long len) {
	return 0;
}

inline void fom_check_exiting_proc(pid_t pid) {}

#endif //CONFIG_FILE_ONLY_MEM

#endif //__FILE_ONLY_MEM_H
