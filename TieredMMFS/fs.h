#ifndef FOMTIERFS_FS_H
#define FOMTIERFS_FS_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

/**
 * TieredMMFS Lock Priority (from highest priority to lowest):
 *  1) tieredmmfs_dev_info.lock
 *  2) tieredmmfs_page.lock
 *      2a) Pages from the fast device
 *      2b) Pages from the slow device
 *  3) tieredmmfs_inode_info.map_lock
 */

enum tieredmmfs_mem_type {
    FAST_MEM = 0,
    SLOW_MEM = 1,
};

struct tieredmmfs_page {
    u64 page_num; // The physical page number within the device
    u64 page_offset; // The page offset within the file
    // If we are using huge pages, but an allocation only uses base pages,
    // this represents the number of base pages in this page
    u16 num_base_pages;
    struct inode *inode; // If the file is allocated, the inode it belongs to. Else null.
    bool last_accessed; // Whether the accessed bit was set last time it was checked
    enum tieredmmfs_mem_type type; // Whether this page is in fast or slow mem
    spinlock_t lock; // Lock that protects the fields of this struct above it.
    // Linked List to connect pages in the free/active list. Protected by tieredmmfs_dev_info.lock
    struct list_head list;
    // RB Tree keyed by page_offset used by inodes to keep track of their pages. Protected by tieredmmfs_inode_info.map_lock
    struct rb_node node;
};

struct tieredmmfs_dev_info {
    struct block_device *bdev;
    struct dax_device *daxdev;
    void* virt_addr; // Kernel's virtual address to dax device
    pfn_t pfn; // The pfn of the first page of the device
    struct list_head free_list;
    struct list_head active_list;
    u64 num_pages;
    u64 free_pages;
    u64 active_pages;
    spinlock_t lock;
};

struct tieredmmfs_sb_info {
    struct tieredmmfs_dev_info mem[2];
    struct task_struct *promote_task;
    struct task_struct *demote_task;
    // Start demotion if fast_mem has less than demotion_watermark% of memory free
    u64 demotion_watermark;
    // Stop allocating from fast_mem if it has less than alloc_watermark% of memory free
    u64 alloc_watermark;
    // The pagesize to work with
    unsigned long page_size;
    unsigned char page_shift;
};

struct tieredmmfs_inode_info {
    struct rb_root page_maps; // Mapping of offset page to dax page
    rwlock_t map_lock;
};

struct tieredmmfs_context_info {
    char *slow_dev_name;
    bool base_pages;
};

struct tieredmmfs_sb_info *FTFS_SB(struct super_block *sb);

struct tieredmmfs_inode_info *FTFS_I(struct inode *inode);

struct tieredmmfs_page *tieredmmfs_find_page(struct rb_root *root, u64 offset);
bool tieredmmfs_insert_page(struct rb_root *root, struct tieredmmfs_page *page);
void tieredmmfs_replace_page(struct rb_root *root, struct tieredmmfs_page *new_page);
#endif // FOMTIERFS_FS_H
