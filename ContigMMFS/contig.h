#ifndef CONTIG_MMFS_H
#define CONTIG_MMFS_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/maple_tree.h>
#include <linux/spinlock.h>
#include <linux/sched.h>

struct contigmmfs_sb_info {
    u64 num_pages;
};

// A file is composed of a series of contiguous sets of pages
// This struct has the virtual address range of this contiguous set.
struct contigmmfs_contig_alloc {
    u64 va_start;
    u64 va_end;
    struct folio *folio;
    struct list_head *node;
};

struct contigmmfs_inode_info {
    struct maple_tree mt;
    u64 va_start;
    struct mm_struct *mm;
};
#endif //CONTIG_MMFS_H
