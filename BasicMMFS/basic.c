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

#include "basic.h"

static const struct super_operations basicmmfs_ops;
static const struct inode_operations basicmmfs_dir_inode_operations;

struct basicmmfs_sb_info *BMMFS_SB(struct super_block *sb)
{
    return sb->s_fs_info;
}

struct basicmmfs_inode_info *BMMFS_I(struct inode *inode)
{
    return inode->i_private;
}

// Allocate a base page and assign it to the inode at the given page offset
// Takes the sbi->lock.
// Returns the allocated page if there is one, else NULL
struct page *basicmmfs_alloc_page(struct basicmmfs_inode_info *inode_info, struct basicmmfs_sb_info *sbi,
        u64 page_offset)
{
    u8 *kaddr;
    struct page *page = NULL;

    spin_lock(&sbi->lock);

    // First, do we have any free pages available?
    if (sbi->free_pages == 0) {
        // TODO: when swapping is added, add a mechanism to get more pages if
        // we have fewer total pages than the max allowed
        goto unlock;
    }

    // Take a page from the free list
    page = list_first_entry(&sbi->free_list, struct page, lru);
    list_del(&page->lru);
    sbi->free_pages--;
    get_page(page);

    // Clear the page outside of the critical section
    spin_unlock(&sbi->lock);

    kaddr = kmap(page);
    memset(kaddr, 0, PAGE_SIZE);
    kunmap(page);

    spin_lock(&sbi->lock);

    // Add the page to the active list
    list_add(&page->lru, &sbi->active_list);

    mtree_store(&inode_info->mt, page_offset, page, GFP_KERNEL);

unlock:
    spin_unlock(&sbi->lock);
    return page;
}

void basicmmfs_return_page(struct page *page, struct basicmmfs_sb_info *sbi)
{
    spin_lock(&sbi->lock);

    list_del(&page->lru);
    // Don't need to put page here for being unmapped
    // that seems to have been handled by the unmapping code?

    // Add the page back to the free list
    list_add_tail(&page->lru, &sbi->free_list);
    sbi->free_pages++;

    spin_unlock(&sbi->lock);
}

void basicmmfs_free_range(struct inode *inode, loff_t offset, loff_t len)
{
    struct basicmmfs_sb_info *sbi = BMMFS_SB(inode->i_sb);
    struct basicmmfs_inode_info *inode_info = BMMFS_I(inode);
    struct page *page;
    u64 page_offset = offset >> PAGE_SHIFT;
    u64 num_pages = len >> PAGE_SHIFT;

    for (int i = page_offset; i < page_offset + num_pages; i++) {
        page = mtree_erase(&inode_info->mt, i);
        // Check if something actually existed at this index
        if (!page)
            continue;

        basicmmfs_return_page(page, sbi);
    }
}

static vm_fault_t basicmmfs_fault(struct vm_fault *vmf)
{
    struct vm_area_struct *vma = vmf->vma;
    struct inode *inode = vma->vm_file->f_inode;
    struct basicmmfs_inode_info *inode_info;
    struct basicmmfs_sb_info *sbi;
    struct page *page;
    u64 pgoff = ((vmf->address - vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;
    vm_fault_t ret = 0;
    pte_t entry;

    inode_info = BMMFS_I(inode);
    sbi = BMMFS_SB(inode->i_sb);

    // Get the page if it already allocated
    page = mtree_load(&inode_info->mt, pgoff);

    // For now, do nothing if the pte already exists.
    // TODO: I'm not sure if this is right...
    if (vmf->pte) {
        vmf->page = page;
        return 0;
    }

    if (pte_alloc(vma->vm_mm, vmf->pmd))
        return VM_FAULT_OOM;

    vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd, vmf->address, &vmf->ptl);
    if (!pte_none(*vmf->pte)) {
        goto unlock;
    }

    // Try to allocate the page if it hasn't been already (e.g. from fallocate)
    if (!page) {
        page = basicmmfs_alloc_page(inode_info, sbi, pgoff);
        if (!page) {
            ret = VM_FAULT_OOM;
            goto unlock;
        }
    }


    // Construct the pte entry
    entry = mk_pte(page, vma->vm_page_prot);
    entry = pte_mkyoung(entry);
    if (vma->vm_flags & VM_WRITE) {
        entry = pte_mkwrite(pte_mkdirty(entry));
    }

    page_add_file_rmap(page, vma, false);
    percpu_counter_inc(&vma->vm_mm->rss_stat[MM_FILEPAGES]);
    set_pte_at(vma->vm_mm, vmf->address, vmf->pte, entry);

    // No need to invalidate - it was non-present before
    update_mmu_cache(vma, vmf->address, vmf->pte);
    vmf->page = page;
    get_page(page);
    ret = VM_FAULT_NOPAGE;

unlock:
    pte_unmap_unlock(vmf->pte, vmf->ptl);
    return ret;
}

static struct vm_operations_struct basicmmfs_vm_ops = {
    .fault = basicmmfs_fault,
    .page_mkwrite = basicmmfs_fault,
    .pfn_mkwrite = basicmmfs_fault,
};

static int basicmmfs_mmap(struct file *file, struct vm_area_struct *vma)
{
    file_accessed(file);
    vma->vm_ops = &basicmmfs_vm_ops;

    return 0;
}

static long basicmmfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
    struct inode *inode = file_inode(file);
    struct basicmmfs_sb_info *sbi = BMMFS_SB(inode->i_sb);
    struct basicmmfs_inode_info *inode_info = BMMFS_I(inode);
    struct page *page;
    loff_t off;

    if (mode & FALLOC_FL_PUNCH_HOLE) {
        basicmmfs_free_range(inode, offset, len);
        return 0;
    } else if (mode != 0) {
        return -EOPNOTSUPP;
    }

    // Allocate and add mappings for the desired range
    for (off = offset; off < offset + len; off += PAGE_SIZE) {
        page = basicmmfs_alloc_page(inode_info, sbi, off >> PAGE_SHIFT);
        if (!page) {
            return -ENOMEM;
        }
    }

    return 0;
}

const struct file_operations basicmmfs_file_operations = {
    .mmap		= basicmmfs_mmap,
    .mmap_supported_flags = MAP_SYNC,
    .fsync		= noop_fsync,
    .splice_read	= generic_file_splice_read,
    .splice_write	= iter_file_splice_write,
    .llseek		= generic_file_llseek,
    .get_unmapped_area	= generic_get_unmapped_area_topdown,
    .fallocate = basicmmfs_fallocate,
};

const struct inode_operations basicmmfs_file_inode_operations = {
	.setattr	= simple_setattr,
	.getattr	= simple_getattr,
};

const struct address_space_operations basicmmfs_aops = {
    .direct_IO = noop_direct_IO,
    .dirty_folio = noop_dirty_folio,
};

struct inode *basicmmfs_get_inode(struct super_block *sb,
                const struct inode *dir, umode_t mode, dev_t dev)
{
    struct inode *inode = new_inode(sb);
    struct basicmmfs_inode_info *info;

    if (!inode)
        return NULL;

    info = kzalloc(sizeof(struct basicmmfs_inode_info), GFP_KERNEL);
    if (!info) {
        pr_err("BasicMMFS: Failure allocating inode");
        return NULL;
    }
    mt_init(&info->mt);

    inode->i_ino = get_next_ino();
    inode_init_owner(&init_user_ns, inode, dir, mode);
    inode->i_mapping->a_ops = &basicmmfs_aops;
    inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
    inode->i_flags |= S_DAX;
    inode->i_private = info;
    switch (mode & S_IFMT) {
        case S_IFREG:
            inode->i_op = &basicmmfs_file_inode_operations;
            inode->i_fop = &basicmmfs_file_operations;
            break;
        case S_IFDIR:
            inode->i_op = &basicmmfs_dir_inode_operations;
            inode->i_fop = &simple_dir_operations;

            /* Directory inodes start off with i_nlink == 2 (for "." entry) */
            inc_nlink(inode);
            break;
        default:
            return NULL;
    }

    return inode;
}

static int basicmmfs_mknod(struct user_namespace *mnt_userns, struct inode *dir,
            struct dentry *dentry, umode_t mode, dev_t dev)
{
    struct inode *inode = basicmmfs_get_inode(dir->i_sb, dir, mode, dev);
    int error = -ENOSPC;

    if (inode) {
        d_instantiate(dentry, inode);
        dget(dentry); /* Extra count - pin the dentry in core */
        error = 0;
        dir->i_mtime = dir->i_ctime = current_time(dir);
    }

    return error;
}

static int basicmmfs_mkdir(struct user_namespace *mnt_userns, struct inode *dir,
            struct dentry *dentry, umode_t mode)
{
    return -EINVAL;
}

static int basicmmfs_create(struct user_namespace *mnt_userns, struct inode *dir,
            struct dentry *dentry, umode_t mode, bool excl)
{
    // TODO: Replace 0777 with mode and see if anything breaks
    return basicmmfs_mknod(&init_user_ns, dir, dentry, 0777 | S_IFREG, 0);
}

static int basicmmfs_symlink(struct user_namespace *mnt_userns, struct inode *dir,
            struct dentry *dentry, const char *symname)
{
    return -EINVAL;
}

static int basicmmfs_tmpfile(struct user_namespace *mnt_userns,
            struct inode *dir, struct file *file, umode_t mode)
{
    struct inode *inode;

    inode = basicmmfs_get_inode(dir->i_sb, dir, mode, 0);
    if (!inode)
        return -ENOSPC;
    d_tmpfile(file, inode);
    return finish_open_simple(file, 0);
}

static const struct inode_operations basicmmfs_dir_inode_operations = {
    .create     = basicmmfs_create,
    .lookup     = simple_lookup,
    .link       = simple_link,
    .unlink     = simple_unlink,
    .symlink    = basicmmfs_symlink,
    .mkdir      = basicmmfs_mkdir,
    .rmdir      = simple_rmdir,
    .mknod      = basicmmfs_mknod,
    .rename     = simple_rename,
    .tmpfile    = basicmmfs_tmpfile,
};

static int basicmmfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    struct super_block *sb = dentry->d_sb;
    struct basicmmfs_sb_info *sbi = BMMFS_SB(sb);

    buf->f_type = sb->s_magic;
    buf->f_bsize = PAGE_SIZE;
    buf->f_blocks = sbi->num_pages;
    buf->f_bfree = buf->f_bavail = sbi->free_pages;
    buf->f_files = LONG_MAX;
    buf->f_ffree = LONG_MAX;
    buf->f_namelen = 255;

    return 0;
}

static void basicmmfs_free_inode(struct inode *inode)
{
    struct basicmmfs_sb_info *sbi = BMMFS_SB(inode->i_sb);
    struct basicmmfs_inode_info *inode_info = BMMFS_I(inode);
    struct page *page;
    unsigned long index = 0;

    mt_for_each(&inode_info->mt, page, index, ULONG_MAX) {
        basicmmfs_return_page(page, sbi);
    }

    mtree_destroy(&inode_info->mt);
    kfree(inode_info);
}

static int basicmmfs_show_options(struct seq_file *m, struct dentry *root)
{
    return 0;
}

static const struct super_operations basicmmfs_ops = {
    .statfs = basicmmfs_statfs,
    .free_inode = basicmmfs_free_inode,
    .drop_inode = generic_delete_inode,
    .show_options = basicmmfs_show_options,
};

static int basicmmfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
    struct inode *inode;
    struct basicmmfs_sb_info *sbi = kzalloc(sizeof(struct basicmmfs_sb_info), GFP_KERNEL);
    u64 nr_pages = *(u64*)fc->fs_private;
    u64 alloc_size = 1024;

    if (!sbi) {
        return -ENOMEM;
    }

    sb->s_fs_info = sbi;
    sb->s_maxbytes = MAX_LFS_FILESIZE;
    sb->s_magic = 0xDEADBEEF;
    sb->s_op = &basicmmfs_ops;
    sb->s_time_gran = 1;
    sb->s_blocksize = PAGE_SIZE;
    sb->s_blocksize_bits = PAGE_SHIFT;

    spin_lock_init(&sbi->lock);
    INIT_LIST_HEAD(&sbi->free_list);
    INIT_LIST_HEAD(&sbi->active_list);
    sbi->num_pages = 0;
    // TODO: Get the number of pages to request from a mount arg
    // Might need to be GFP_HIGHUSER?
    // TODO: Make this actually allocate nr_pages instead of the nearest multiple
    // of alloc_size greater than nr_pages
    for (int i = 0; i < nr_pages / alloc_size; i++) {
        sbi->num_pages += alloc_pages_bulk_list(GFP_HIGHUSER, alloc_size, &sbi->free_list);
    }
    sbi->free_pages = sbi->num_pages;

    inode = basicmmfs_get_inode(sb, NULL, S_IFDIR | 0755, 0);
    sb->s_root = d_make_root(inode);
    if (!sb->s_root) {
        kfree(sbi);
        return -ENOMEM;
    }

    return 0;
}

static int basicmmfs_get_tree(struct fs_context *fc)
{
    return get_tree_nodev(fc, basicmmfs_fill_super);
}

enum basicmmfs_param {
    Opt_numpages,
};

const struct fs_parameter_spec basicmmfs_fs_parameters[] = {
    fsparam_u64("numpages", Opt_numpages),
	{},
};

static int basicmmfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
    struct fs_parse_result result;
    u64 *num_pages = (u64*)fc->fs_private;
    int opt;

    opt = fs_parse(fc, basicmmfs_fs_parameters, param, &result);
	if (opt < 0) {
		/*
		 * We might like to report bad mount options here;
		 * but traditionally ramfs has ignored all mount options,
		 * and as it is used as a !CONFIG_SHMEM simple substitute
		 * for tmpfs, better continue to ignore other mount options.
		 */
		if (opt == -ENOPARAM)
			opt = 0;
		return opt;
	}

    switch(opt) {
	case Opt_numpages:
		*num_pages = result.uint_64;
		break;
	};

    return 0;
}

static void basicmmfs_free_fc(struct fs_context *fc)
{
	kfree(fc->fs_private);
}

static const struct fs_context_operations basicmmfs_context_ops = {
    .free = basicmmfs_free_fc,
    .parse_param = basicmmfs_parse_param,
    .get_tree = basicmmfs_get_tree,
};

int basicmmfs_init_fs_context(struct fs_context *fc)
{
    fc->ops = &basicmmfs_context_ops;

    fc->fs_private = kzalloc(sizeof(u64), GFP_KERNEL);
	// Set a default number of pages to use
	*(u64*)fc->fs_private = 128 * 1024;
    return 0;
}

static void basicmmfs_kill_sb(struct super_block *sb)
{
    struct basicmmfs_sb_info *sbi = BMMFS_SB(sb);
    struct page *page, *tmp;

    // Is it necessary to lock here since this is happening when
    // it's being unmounted.
    // It probably doesn't hurt
    spin_lock(&sbi->lock);

    // Return the pages we took to the kernel.
    // All the pages should be in the free list at this point
    list_for_each_entry_safe(page, tmp, &sbi->free_list, lru) {
        list_del(&page->lru);
        put_page(page);
    }

    spin_unlock(&sbi->lock);

    kfree(sbi);

    kill_litter_super(sb);
}

static struct file_system_type basicmmfs_fs_type = {
    .owner = THIS_MODULE,
    .name = "BasicMMFS",
    .init_fs_context = basicmmfs_init_fs_context,
    .parameters = basicmmfs_fs_parameters,
    .kill_sb = basicmmfs_kill_sb,
    .fs_flags = FS_USERNS_MOUNT,
};

int __init init_module(void)
{
    printk(KERN_INFO "Starting BasicMMFS");
    register_filesystem(&basicmmfs_fs_type);

    return 0;
}

void cleanup_module(void)
{
    printk(KERN_INFO "Removing BasicMMFS");
    unregister_filesystem(&basicmmfs_fs_type);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bijan Tabatabai");
