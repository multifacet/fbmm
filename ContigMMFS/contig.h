#ifndef CONTIG_MMFS_H
#define CONTIG_MMFS_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/maple_tree.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

struct contigmmfs_sb_info {
    spinlock_t lock;
    struct list_head active_list;
    u64 num_pages;
};

struct contigmmfs_inode_info {
    // Maple tree mapping the page offset to the folio mapped to that offset
    struct maple_tree mt;
};
#endif //CONTIG_MMFS_H
