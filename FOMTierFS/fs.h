#ifndef FOMTIERFS_FS_H
#define FOMTIERFS_FS_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/rbtree.h>

enum fomtierfs_mem_type {
    FAST_MEM = 0,
    SLOW_MEM = 1,
};

struct fomtierfs_page {
    u64 page_num;
    enum fomtierfs_mem_type type;
    struct list_head list;
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
    u64 num_pages;
    u64 free_pages;
};

struct fomtierfs_sb_info {
    struct fomtierfs_dev_info mem[2];
    bool alloc_fast;
};

struct fomtierfs_inode_info {
    struct rb_root page_maps; // Mapping of offset page to dax page
};

struct fomtierfs_sb_info *FTFS_SB(struct super_block *sb);

struct fomtierfs_inode_info *FTFS_I(struct inode *inode);

struct fomtierfs_page_map *fomtierfs_find_map(struct rb_root *root, u64 offset);
bool fomtierfs_insert_mapping(struct rb_root *root, struct fomtierfs_page_map *map);
#endif // FOMTIERFS_FS_H
