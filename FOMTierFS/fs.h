#ifndef FOMTIERFS_FS_H
#define FOMTIERFS_FS_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

enum fomtierfs_mem_type {
    FAST_MEM = 0,
    SLOW_MEM = 1,
};

struct fomtierfs_page {
    u64 page_num; // The physical page number within the device
    u64 page_offset; // The page offset within the file
    struct inode *inode; // If the file is allocated, the inode it belongs to. Else null.
    enum fomtierfs_mem_type type; // Whether this page is in fast or slow mem
    struct list_head list; // Linked List to connect pages in the free/active list
    struct rb_node node; // RB Tree keyed by page_offset used by inodes to keep track of their pages
};

struct fomtierfs_page_map {
    u64 page_offset; // File Offset / Page Size
    struct fomtierfs_page *page; // The physical page mapped to the offset
    struct rb_node node;
};

struct fomtierfs_dev_info {
    struct block_device *bdev;
    struct dax_device *daxdev;
    void* virt_addr; // Kernel's virtual address to dax device
    struct list_head free_list;
    struct list_head active_list;
    u64 num_pages;
    u64 free_pages;
    u64 active_pages;
    spinlock_t lock;
};

struct fomtierfs_sb_info {
    struct fomtierfs_dev_info mem[2];
    struct task_struct *migrate_task;
    bool alloc_fast;
};

struct fomtierfs_inode_info {
    struct rb_root page_maps; // Mapping of offset page to dax page
    rwlock_t map_lock;
};

struct fomtierfs_sb_info *FTFS_SB(struct super_block *sb);

struct fomtierfs_inode_info *FTFS_I(struct inode *inode);

struct fomtierfs_page *fomtierfs_find_page(struct rb_root *root, u64 offset);
bool fomtierfs_insert_page(struct rb_root *root, struct fomtierfs_page *page);
#endif // FOMTIERFS_FS_H
