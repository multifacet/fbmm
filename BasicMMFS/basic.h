#ifndef BASIC_MMFS_H
#define BASIC_MMFS_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/maple_tree.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/kobject.h>

struct basicmmfs_sb_info {
    spinlock_t lock;
    struct list_head free_list;
    struct list_head active_list;
    u64 num_pages;
    u64 free_pages;
    u64 max_pages;
    int id;
    struct kobject kobj;
};

struct basicmmfs_inode_info {
    // Maple tree mapping the page offset to the folio mapped to that offset
    struct maple_tree mt;
};

extern const struct attribute_group basicmmfs_attr_group;
extern const struct kobj_type basicmmfs_kobj_ktype;
#endif //BASIC_MMFS_H
