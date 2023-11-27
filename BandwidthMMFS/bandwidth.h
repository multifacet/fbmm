#ifndef BANDWIDTH_MMFS_H
#define BANDWIDTH_MMFS_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/maple_tree.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/sched.h>

struct bwmmfs_node_weights {
    int nid;
    u32 weight;
    struct list_head list;
};

struct bwmmfs_sb_info {
    u64 num_pages;
    u32 total_weight;
    struct list_head node_list;
};

struct bwmmfs_inode_info {
    atomic_t alloc_count;
    struct maple_tree mt;
};
#endif //CONTIG_MMFS_H
