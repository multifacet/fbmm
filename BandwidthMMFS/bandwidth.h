#ifndef BANDWIDTH_MMFS_H
#define BANDWIDTH_MMFS_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/maple_tree.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

struct bwmmfs_sb_info {
    u64 num_pages;
};

struct bwmmfs_inode_info {
    struct maple_tree mt;
};
#endif //CONTIG_MMFS_H
