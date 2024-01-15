#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/gfp.h>
#include <linux/fs_context.h>
#include <linux/fs_parser.h>
#include <linux/pagemap.h>
#include <linux/statfs.h>
#include <linux/module.h>
#include <linux/rmap.h>
#include <linux/string.h>
#include <linux/falloc.h>
#include <linux/badger_trap.h>

#include "contig.h"

static const struct super_operations contigmmfs_ops;
static const struct inode_operations contigmmfs_dir_inode_operations;

struct contigmmfs_sb_info *CMMFS_SB(struct super_block *sb)
{
    return sb->s_fs_info;
}

struct contigmmfs_inode_info *CMMFS_I(struct inode *inode)
{
    return inode->i_private;
}

static vm_fault_t contigmmfs_fault(struct vm_fault *vmf)
{
    struct vm_area_struct *vma = vmf->vma;
    struct inode *inode = vma->vm_file->f_inode;
    struct contigmmfs_inode_info *inode_info;
    struct contigmmfs_sb_info *sbi;
    struct contigmmfs_contig_alloc *region;
    struct page *page;
    pte_t entry;

    inode_info = CMMFS_I(inode);
    sbi = CMMFS_SB(inode->i_sb);

    // Get the contiguous region that this fault belongs to
    region = mt_prev(&inode_info->mt, vmf->address + 1, 0);
    if (!region || region->va_start > vmf->address || region->va_end <= vmf->address)
        return VM_FAULT_OOM;

    page = folio_page(region->folio, ((vmf->address - region->va_start) >> PAGE_SHIFT));

    // For now, do nothing if the pte already exists
    if (vmf->pte) {
        return VM_FAULT_NOPAGE;
    }

    if (pte_alloc(vma->vm_mm, vmf->pmd))
        return VM_FAULT_OOM;

    vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd, vmf->address, &vmf->ptl);
    if (!pte_none(*vmf->pte)) {
        goto unlock;
    }

    // Construct the pte entry
    entry = mk_pte(page, vma->vm_page_prot);
    entry = pte_mkyoung(entry);
    if (vma->vm_flags & VM_WRITE) {
        entry = pte_mkwrite(pte_mkdirty(entry));
    }

	if(vma->vm_mm && (vma->vm_mm->badger_trap_en==1) && (!(vmf->flags & FAULT_FLAG_INSTRUCTION))) {
        entry = pte_mkreserve(entry);
    }

    page_add_file_rmap(page, vma, false);
    percpu_counter_inc(&vma->vm_mm->rss_stat[MM_FILEPAGES]);
    set_pte_at(vma->vm_mm, vmf->address, vmf->pte, entry);
    folio_get(region->folio);

unlock:
    pte_unmap_unlock(vmf->pte, vmf->ptl);
    return VM_FAULT_NOPAGE;
}

static struct vm_operations_struct contigmmfs_vm_ops = {
    .fault = contigmmfs_fault,
    .page_mkwrite = contigmmfs_fault,
    .pfn_mkwrite = contigmmfs_fault,
};

static int contigmmfs_mmap(struct file *file, struct vm_area_struct *vma)
{
    int nid = numa_node_id();
    pg_data_t *pgdat = NODE_DATA(nid);
    struct zone *zone = &pgdat->node_zones[ZONE_NORMAL];
    struct inode *inode = file->f_inode;
    struct contigmmfs_inode_info *inode_info = CMMFS_I(inode);
    struct contigmmfs_sb_info *sbi = CMMFS_SB(inode->i_sb);
    struct contigmmfs_contig_alloc *region = NULL;
    struct range_tlb_entry *tlb_entry = NULL;
    struct folio *new_folio = NULL;
    u64 pages_to_alloc = (vma->vm_end - vma->vm_start) >> PAGE_SHIFT;
    u64 current_va = vma->vm_start;

    inode_info->va_start = vma->vm_start - (vma->vm_pgoff << PAGE_SHIFT);

    while(pages_to_alloc > 0) {
        u64 folio_size;

        region = NULL;
        new_folio = NULL;
        // Using algorithm from redundant memory mapping paper
        for (int order = MAX_ORDER - 1; order >= 0; order--) {
            bool enough_in_order = false;

            // Make sure we aren't allocating more than we need
            if (pages_to_alloc < (1 << order))
                continue;
            // Go to the next order if there is nothing in this one
            for (int j = order; j < MAX_ORDER; j++) {
                if (zone->free_area[j].nr_free > 0) {
                    enough_in_order = true;
                    break;
                }
            }
            if (!enough_in_order)
                continue;

            new_folio = folio_alloc(GFP_HIGHUSER | __GFP_ZERO, order);

            // If the allocation was unsuccsessful, try again with the next order,
            // otherwise, use this new folio
            if (new_folio)
                break;
        }

        // If a folio could not be allocated, clean up and return an error
        if (!new_folio)
            goto err;

        region = kzalloc(sizeof(struct contigmmfs_contig_alloc), GFP_KERNEL);
        if (!region)
            goto err;

        folio_size = folio_nr_pages(new_folio);
        region->va_start = current_va;
        region->va_end = current_va + (folio_size << PAGE_SHIFT);
        region->folio = new_folio;

        if(mtree_store(&inode_info->mt, current_va, region, GFP_KERNEL))
            goto err;

        // If badger trap is being used, add the ranges to the mm's list
        if (vma->vm_mm && vma->vm_mm->badger_trap_en && folio_size >= 8) {
            inode_info->mm = vma->vm_mm;
            tlb_entry = kzalloc(sizeof(struct range_tlb_entry), GFP_KERNEL);
            // I'm being lazy here without the error checking, but it's
            // *probably* fine
            tlb_entry->range_start = region->va_start;
            tlb_entry->range_end = region->va_end;
            spin_lock(&vma->vm_mm->range_tlb_lock);
            mtree_store(&vma->vm_mm->all_ranges, tlb_entry->range_start, tlb_entry, GFP_KERNEL);
            spin_unlock(&vma->vm_mm->range_tlb_lock);
        }

        // TODO: It would probably be good to setup the page tables here,
        // but it's easier if we just let the page fault handler to 90% of the
        // work then do the rest in the page fault callback

        pages_to_alloc -= folio_size;
        current_va += folio_size << PAGE_SHIFT;
        sbi->num_pages += folio_size;
    }

    file_accessed(file);
    vma->vm_ops = &contigmmfs_vm_ops;
    vma->vm_flags |= VM_MIXEDMAP | VM_DONTEXPAND;

    return 0;
err:
    if (region)
        kfree(region);
    if (new_folio)
        folio_put(new_folio);

    return -ENOMEM;
}

static long contigmmfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
    struct inode *inode = file->f_inode;
    struct contigmmfs_sb_info *sbi = CMMFS_SB(inode->i_sb);
    struct contigmmfs_inode_info *inode_info = CMMFS_I(inode);
    struct contigmmfs_contig_alloc *region = NULL;
    struct contigmmfs_contig_alloc *next_region = NULL;
    struct range_tlb_entry *tlb_entry;
    u64 start_addr = inode_info->va_start + offset;
    u64 end_addr = start_addr + len;

    if (!(mode & FALLOC_FL_PUNCH_HOLE))
        return 0;

    // Get the region with the lowest va_start that overlaps with the unmap region
    region = mt_prev(&inode_info->mt, start_addr + 1, 0);
    if (!region || region->va_end <= start_addr) {
        // Ok, the start of the munmap range isn't mapped, but maybe the end is?
        region = mt_next(&inode_info->mt, start_addr, ULONG_MAX);
        if (!region || region->va_start >= end_addr)
            return 0;
        start_addr = region->va_start;
    }

    // Free each region in the range
    while (region && start_addr < end_addr) {
        // I don't know what to do if the unmap range straddles a folio region,
        // so just punt on that for now
        if (region->va_start < start_addr || region->va_end > end_addr)
            break;

        mtree_erase(&inode_info->mt, region->va_start);
        sbi->num_pages -= folio_nr_pages(region->folio);
        folio_put(region->folio);

        // Clear the range tlb as necessary
        if (inode_info->mm && inode_info->mm->badger_trap_en && folio_nr_pages(region->folio) >= 8) {
            tlb_entry = mtree_erase(&inode_info->mm->all_ranges, region->va_start);

            if (tlb_entry)
                kfree(tlb_entry);
        }

        next_region = mt_next(&inode_info->mt, region->va_start, ULONG_MAX);
        kfree(region);

        region = next_region;
        if (region)
            start_addr = region->va_start;
    }

    return 0;
}

const struct file_operations contigmmfs_file_operations = {
    .mmap = contigmmfs_mmap,
    .mmap_supported_flags = MAP_SYNC,
    .fsync = noop_fsync,
    .splice_read = generic_file_splice_read,
    .splice_write = iter_file_splice_write,
    .llseek = generic_file_llseek,
    .get_unmapped_area = thp_get_unmapped_area,
    .fallocate = contigmmfs_fallocate,
};

const struct inode_operations contigmmfs_file_inode_operations = {
    .setattr = simple_setattr,
    .getattr = simple_getattr,
};

const struct address_space_operations contigmmfs_aops = {
    .direct_IO = noop_direct_IO,
    .dirty_folio = noop_dirty_folio,
};

struct inode *contigmmfs_get_inode(struct super_block *sb,
                const struct inode *dir, umode_t mode, dev_t dev)
{
    struct inode *inode = new_inode(sb);
    struct contigmmfs_inode_info *info;

    if (!inode)
        return NULL;

    info = kzalloc(sizeof(struct contigmmfs_inode_info), GFP_KERNEL);
    if (!info) {
        pr_err("ContigMMFS: Failure allocating inode");
        return NULL;
    }
    mt_init(&info->mt);
    info->va_start = 0;
    info->mm = NULL;

    inode->i_ino = get_next_ino();
    inode_init_owner(&init_user_ns, inode, dir, mode);
    inode->i_mapping->a_ops = &contigmmfs_aops;
    inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
    inode->i_flags |= S_DAX;
    inode->i_private = info;
    switch (mode &S_IFMT) {
        case S_IFREG:
            inode->i_op = &contigmmfs_file_inode_operations;
            inode->i_fop = &contigmmfs_file_operations;
            break;
        case S_IFDIR:
            inode->i_op = &contigmmfs_dir_inode_operations;
            inode->i_fop = &simple_dir_operations;

            /* Directory inodes start off with i_nlink == 2 (for "." entry) */
            inc_nlink(inode);
            break;
        default:
            return NULL;
    }

    return inode;
}

static int contigmmfs_mknod(struct user_namespace *mnt_userns, struct inode *dir,
            struct dentry *dentry, umode_t mode, dev_t dev)
{
    struct inode *inode = contigmmfs_get_inode(dir->i_sb, dir, mode, dev);
    int error = -ENOSPC;

    if (inode) {
        d_instantiate(dentry, inode);
        dget(dentry);
        error = 0;
        dir->i_mtime = dir->i_ctime = current_time(dir);
    }

    return error;
}

static int contigmmfs_mkdir(struct user_namespace *mnt_userns, struct inode *dir,
            struct dentry *dentry, umode_t mode)
{
    return -EINVAL;
}

static int contigmmfs_create(struct user_namespace *mnt_userns, struct inode *dir,
            struct dentry *dentry, umode_t mode, bool excl)
{
    return contigmmfs_mknod(&init_user_ns, dir, dentry, 0777 | S_IFREG, 0);
}

static int contigmmfs_symlink(struct user_namespace *mnt_userns, struct inode *dir,
            struct dentry *dentry, const char *symname)
{
    return -EINVAL;
}

static int contigmmfs_tmpfile(struct user_namespace *mnt_userns,
            struct inode*dir, struct file *file, umode_t mode)
{
    struct inode *inode;

    inode = contigmmfs_get_inode(dir->i_sb, dir, mode, 0);
    if (!inode)
        return -ENOSPC;
    d_tmpfile(file, inode);
    return finish_open_simple(file, 0);
}

static const struct inode_operations contigmmfs_dir_inode_operations = {
    .create     = contigmmfs_create,
    .lookup     = simple_lookup,
    .link       = simple_link,
    .unlink     = simple_unlink,
    .symlink    = contigmmfs_symlink,
    .mkdir      = contigmmfs_mkdir,
    .rmdir      = simple_rmdir,
    .mknod      = contigmmfs_mknod,
    .rename     = simple_rename,
    .tmpfile    = contigmmfs_tmpfile,
};

static int contigmmfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    struct super_block *sb = dentry->d_sb;
    struct contigmmfs_sb_info *sbi = CMMFS_SB(sb);

    buf->f_type = sb->s_magic;
    buf->f_bsize = PAGE_SIZE;
    buf->f_blocks = sbi->num_pages;
    buf->f_bfree = buf->f_bavail = 0;
    buf->f_files = LONG_MAX;
    buf->f_ffree = LONG_MAX;
    buf->f_namelen = 255;

    return 0;
}

static void contigmmfs_free_inode(struct inode *inode)
{
    struct contigmmfs_sb_info *sbi = CMMFS_SB(inode->i_sb);
    struct contigmmfs_inode_info *inode_info = CMMFS_I(inode);
    struct contigmmfs_contig_alloc *region;
    unsigned long index = 0;

    // Release all of the pages associated with the file
    mt_for_each(&inode_info->mt, region, index, ULONG_MAX) {
        sbi->num_pages -= folio_nr_pages(region->folio);
        folio_put(region->folio);
        kfree(region);
    }

    mtree_destroy(&inode_info->mt);
    kfree(inode_info);
}

static int contigmmfs_show_options(struct seq_file *m, struct dentry *root)
{
    return 0;
}

static const struct super_operations contigmmfs_ops = {
    .statfs = contigmmfs_statfs,
    .free_inode = contigmmfs_free_inode,
    .drop_inode = generic_delete_inode,
    .show_options = contigmmfs_show_options,
};

static int contigmmfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
    struct inode *inode;
    struct contigmmfs_sb_info *sbi = kzalloc(sizeof(struct contigmmfs_sb_info), GFP_KERNEL);

    if (!sbi) {
        return -ENOMEM;
    }

    sb->s_fs_info = sbi;
    sb->s_maxbytes = MAX_LFS_FILESIZE;
    sb->s_magic = 0xDEADBEEF;
    sb->s_op = &contigmmfs_ops;
    sb->s_time_gran = 1;
    sb->s_blocksize = PAGE_SIZE;
    sb->s_blocksize_bits = PAGE_SHIFT;

    sbi->num_pages = 0;

    inode = contigmmfs_get_inode(sb, NULL, S_IFDIR | 0755, 0);
    sb->s_root = d_make_root(inode);
    if (!sb->s_root) {
        kfree(sbi);
        return -ENOMEM;
    }

    return 0;
}

static int contigmmfs_get_tree(struct fs_context *fc)
{
    return get_tree_nodev(fc, contigmmfs_fill_super);
}

enum contigmmfs_param {
    Opt_maxsize,
};

const struct fs_parameter_spec contigmmfs_fs_parameters[] = {
    fsparam_u64("maxsize", Opt_maxsize),
};

static int contigmmfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
    return 0;
}

static void contigmmfs_free_fc(struct fs_context *fc)
{
}

static const struct fs_context_operations contigmmfs_context_ops = {
    .free = contigmmfs_free_fc,
    .parse_param = contigmmfs_parse_param,
    .get_tree = contigmmfs_get_tree,
};

int contigmmfs_init_fs_context(struct fs_context *fc)
{
    fc->ops = &contigmmfs_context_ops;

    return 0;
}

static void contigmmfs_kill_sb(struct super_block *sb)
{
    struct contigmmfs_sb_info *sbi = CMMFS_SB(sb);

    kfree(sbi);
    kill_litter_super(sb);
}

static struct file_system_type contigmmfs_fs_type = {
    .owner = THIS_MODULE,
    .name = "ContigMMFS",
    .init_fs_context = contigmmfs_init_fs_context,
    .parameters = contigmmfs_fs_parameters,
    .kill_sb = contigmmfs_kill_sb,
    .fs_flags = FS_USERNS_MOUNT,
};

int __init init_module(void)
{
    printk(KERN_INFO "Starting ContigMMFS");
    register_filesystem(&contigmmfs_fs_type);

    return 0;
}

void cleanup_module(void)
{
    printk(KERN_INFO "Removing ContigMMFS");
    unregister_filesystem(&contigmmfs_fs_type);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bijan Tabatabai");
