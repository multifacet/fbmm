#ifndef _FILE_ONLY_MEM_H_
#define _FILE_ONLY_MEM_H_

#include <linux/types.h>
#include <linux/fs.h>

#ifdef CONFIG_FILE_ONLY_MEM

bool use_file_only_mem(pid_t pid);

struct file *create_new_fom_file(unsigned long start, unsigned long len,
	unsigned long prot, pid_t pid);
void fom_check_exiting_proc(pid_t pid);

#else //CONFIG_FILE_ONLY_MEM

inline bool use_file_only_mem(pid_t pid) {
	return false;
}

inline struct file *create_new_fom_file(unsigned long start, unsigned long len,
	unsigned long prot, pid_t pid) {
	return NULL;
}

inline void fom_check_exiting_proc(pid_t pid) {}

#endif //CONFIG_FILE_ONLY_MEM

#endif //__FILE_ONLY_MEM_H
