#ifndef BASIC_MMFS_H
#define BASIC_MMFS_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/maple_tree.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

struct basicmmfs_sb_info {
    spinlock_t lock;
    struct list_head free_list;
    struct list_head active_list;
    u64 num_pages;
    u64 free_pages;
};

struct basicmmfs_inode_info {
    // Maple tree mapping the page offset to the folio mapped to that offset
    // Used to hold preallocated pages that haven't been mapped yet
    struct maple_tree falloc_mt;
    // The first virtual address this file is associated with.
    u64 file_va_start;
};

#endif //BASIC_MMFS_H
