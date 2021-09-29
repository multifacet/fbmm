#ifndef _FILE_ONLY_MEM_H_
#define _FILE_ONLY_MEM_H_

#include <linux/types.h>

#ifdef CONFIG_FILE_ONLY_MEM

bool use_file_only_mem(pid_t pid);

#else //CONFIG_FILE_ONLY_MEM

inline bool use_file_only_mem(pid_t pid) {
	return false;
}

#endif //CONFIG_FILE_ONLY_MEM

#endif //__FILE_ONLY_MEM_H
