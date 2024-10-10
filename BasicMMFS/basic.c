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
#include <linux/pagewalk.h>
#include <linux/file_based_mm.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/pagevec.h>

#include <asm/tlbflush.h>

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
    u64 pages_added;
    u64 alloc_size = 64;
    struct page *page = NULL;

    spin_lock(&sbi->lock);

    // First, do we have any free pages available?
    if (sbi->free_pages == 0) {
        // Try to allocate more pages if we can
        alloc_size = min(alloc_size, sbi->max_pages - sbi->num_pages);
        if (alloc_size == 0)
            goto unlock;

        pages_added = alloc_pages_bulk_list(GFP_HIGHUSER, alloc_size, &sbi->free_list);

        if (pages_added == 0)
            goto unlock;

        sbi->num_pages += pages_added;
        sbi->free_pages += pages_added;
    }

    // Take a page from the free list
    page = list_first_entry(&sbi->free_list, struct page, lru);
    list_del(&page->lru);
    sbi->free_pages--;

    // Clear the page outside of the critical section
    spin_unlock(&sbi->lock);

    kaddr = kmap(page);
    memset(kaddr, 0, PAGE_SIZE);
    kunmap(page);

    spin_lock(&sbi->lock);

    // Add the page to the active list
    list_add(&page->lru, &sbi->active_list);

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

int basicmmfs_free_pte(pte_t *pte, unsigned long addr, unsigned long next,
		struct mm_walk *walk)
{
    struct basicmmfs_sb_info *sbi = walk->private;
    unsigned long pfn;
    struct page *page;

    // just the pte_none check is probably enough, but check pte_present to be safe
    if (!pte) {
        goto end;
    }
    if (pte_none(*pte) || !pte_present(*pte)) {
        goto end;
    }

    pfn = pte_pfn(*pte);

    if (!pfn_valid(pfn))
        goto end;

    page = pfn_to_page(pfn);
    basicmmfs_return_page(page, sbi);

end:
    return 0;
}

void basicmmfs_free_range(struct inode *inode, u64 offset, loff_t len)
{
    struct basicmmfs_sb_info *sbi = BMMFS_SB(inode->i_sb);
    struct basicmmfs_inode_info *inode_info = BMMFS_I(inode);
    struct address_space *mapping = inode_info->mapping;
    struct folio_batch fbatch;
    int i;
    pgoff_t cur_offset = offset;
    pgoff_t end_offset = offset + len;

    folio_batch_init(&fbatch);
    while (cur_offset < end_offset) {
        filemap_get_folios(mapping, &cur_offset, end_offset, &fbatch);

        for (i = 0; i < fbatch.nr; i++) {
            basicmmfs_return_page(folio_page(fbatch.folios[i], 0), sbi);
        }

        folio_batch_release(&fbatch);
    }
}

static vm_fault_t basicmmfs_fault(struct vm_fault *vmf)
{
    struct vm_area_struct *vma = vmf->vma;
    struct address_space *mapping = vma->vm_file->f_mapping;
    struct inode *inode = vma->vm_file->f_inode;
    struct basicmmfs_inode_info *inode_info;
    struct basicmmfs_sb_info *sbi;
    struct page *page = NULL;
    bool new_page = false;
    bool swap_page = false;
    bool cow_fault = false;
    u64 pgoff = ((vmf->address - vma->vm_start) >> PAGE_SHIFT) + vma->vm_pgoff;
    vm_fault_t ret = 0;
    pte_t entry;

    inode_info = BMMFS_I(inode);
    sbi = BMMFS_SB(inode->i_sb);

    if (!vmf->pte) {
        if (pte_alloc(vma->vm_mm, vmf->pmd))
            return VM_FAULT_OOM;
    }

    vmf->pte = pte_offset_map(vmf->pmd, vmf->address);
    vmf->orig_pte = *vmf->pte;
    if (!pte_none(vmf->orig_pte) && pte_present(vmf->orig_pte)) {
        if (!(vmf->flags & FAULT_FLAG_WRITE)) {
            // It looks like the PTE is already populated,
            // so maybe two threads raced to first fault.
            ret = VM_FAULT_NOPAGE;
            goto unmap;
        }

        cow_fault = true;
    }

    // Get the page if it already allocated
    page = mtree_erase(&inode_info->falloc_mt, pgoff);

    // Try to allocate the page if it hasn't been already (e.g. from fallocate)
    if (!page) {
        page = basicmmfs_alloc_page(inode_info, sbi, pgoff);
        new_page = true;
        if (!page) {
            ret = VM_FAULT_OOM;
            goto unmap;
        }
    }

    if (!pte_none(vmf->orig_pte) && !pte_present(vmf->orig_pte)) {
        // Swapped out page
        struct page *ret_page;
        swp_entry_t swp_entry = pte_to_swp_entry(vmf->orig_pte);
        swap_page = true;

        ret_page = fbmm_read_swap_entry(vmf, swp_entry, pgoff, page);
        if (page != ret_page) {
            // A physical page was already being used for this virt page
            // or there was an error, so we can return the page we allocated.
            basicmmfs_return_page(page, sbi);
            page = ret_page;
            new_page = false;
        }
        if (!page) {
            pr_err("Error swapping in page! %lx\n", vmf->address);
            goto unmap;
        }
    }

    vmf->ptl = pte_lockptr(vma->vm_mm, vmf->pmd);
    spin_lock(vmf->ptl);
    // Check if some other thread faulted here
    if (!pte_same(vmf->orig_pte, *vmf->pte)) {
        if (new_page) {
            basicmmfs_return_page(page, sbi);
        }
        goto unlock;
    }

    // Handle COW fault
    if (cow_fault) {
        u8 *src_kaddr, *dst_kaddr;
        struct page *old_page;
        unsigned long old_pfn;

        old_pfn = pte_pfn(vmf->orig_pte);
        old_page = pfn_to_page(old_pfn);

        lock_page(old_page);

        // If there's more than one reference to this page, we need to copy it.
        // Otherwise, we can just reuse it
        if (page_mapcount(old_page) > 1) {
            // Actually copy the page
            src_kaddr = kmap(old_page);
            dst_kaddr = kmap(page);
            memcpy(dst_kaddr, src_kaddr, PAGE_SIZE);
            kunmap(page);
            kunmap(old_page);

        } else {
            basicmmfs_return_page(page, sbi);
            page = old_page;
        }
        // Drop a reference to old_page even if we are going to keep it
        // because the reference will be increased at the end of the fault
        put_page(old_page);
        // Decrease the filepage count for the same reason
        percpu_counter_dec(&vma->vm_mm->rss_stat[MM_FILEPAGES]);
        page_remove_rmap(old_page, vma, false);

        /**
         * If we are copying a page for the process that originally faulted the
         * page, we have to replace the mapping
         */
        if (mapping == page_folio(old_page)->mapping) {
            if (old_page != page)
                replace_page_cache_folio(page_folio(old_page), page_folio(page));
            new_page = false;
        }

        unlock_page(old_page);
    }

    if (new_page || swap_page)
        __filemap_add_folio(mapping, page_folio(page), pgoff, GFP_KERNEL, NULL);

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
    flush_tlb_page(vma, vmf->address);
    ret = VM_FAULT_NOPAGE;

unlock:
    spin_unlock(vmf->ptl);
unmap:
    pte_unmap(vmf->pte);
    return ret;
}

static struct vm_operations_struct basicmmfs_vm_ops = {
    .fault = basicmmfs_fault,
    .page_mkwrite = basicmmfs_fault,
    .pfn_mkwrite = basicmmfs_fault,
};

static int basicmmfs_mmap(struct file *file, struct vm_area_struct *vma)
{
    struct inode *inode = file_inode(file);
    struct basicmmfs_inode_info *inode_info = BMMFS_I(inode);
    file_accessed(file);
    vma->vm_ops = &basicmmfs_vm_ops;

    inode_info->file_va_start = vma->vm_start - (vma->vm_pgoff << PAGE_SHIFT);
    inode_info->mapping = file->f_mapping;

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
        mtree_store(&inode_info->falloc_mt, off >> PAGE_SHIFT, page, GFP_KERNEL);
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
    .writepage = fbmm_writepage,
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
    mt_init(&info->falloc_mt);
    info->file_va_start = 0;

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

#define FBMM_DEFAULT_FILE_SIZE ((long)128 << 30)
static void basicmmfs_free_inode(struct inode *inode)
{
    struct basicmmfs_sb_info *sbi = BMMFS_SB(inode->i_sb);
    struct basicmmfs_inode_info *inode_info = BMMFS_I(inode);
    struct page *page;
    unsigned long index = 0;

    mt_for_each(&inode_info->falloc_mt, page, index, ULONG_MAX) {
        basicmmfs_return_page(page, sbi);
    }

    mtree_destroy(&inode_info->falloc_mt);
    kfree(inode_info);
}

static int basicmmfs_show_options(struct seq_file *m, struct dentry *root)
{
    return 0;
}

#define BASICMMFS_MAX_PAGEOUT 512
static long basicmmfs_nr_cached_objects(struct super_block *sb, struct shrink_control *sc)
{
    struct basicmmfs_sb_info *sbi = BMMFS_SB(sb);
    long nr = 0;

    spin_lock(&sbi->lock);
    if (sbi->free_pages > 0)
        nr = sbi->free_pages;
    else
        nr = max(sbi->num_pages - sbi->free_pages, (u64)BASICMMFS_MAX_PAGEOUT);
    spin_unlock(&sbi->lock);

    return nr;
}

static long basicmmfs_free_cached_objects(struct super_block *sb, struct shrink_control *sc)
{
    LIST_HEAD(folio_list);
    LIST_HEAD(fail_list);
    struct basicmmfs_sb_info *sbi = BMMFS_SB(sb);
    struct page *page;
    u64 i, num_scanned;

    if (sbi->free_pages > 0) {
        spin_lock(&sbi->lock);
        for (i = 0; i < sc->nr_to_scan && i < sbi->free_pages; i++) {
            page = list_first_entry(&sbi->free_list, struct page, lru);
            list_del(&page->lru);
            put_page(page);
        }

        sbi->num_pages -= i;
        sbi->free_pages -= i;
        spin_unlock(&sbi->lock);
    } else if (sbi->num_pages > 0) {
        spin_lock(&sbi->lock);
        for (i = 0; i < sc->nr_to_scan && sbi->num_pages > 0; i++) {
            page = list_first_entry(&sbi->active_list, struct page, lru);
            list_move(&page->lru, &folio_list);
            sbi->num_pages--;
        }
        spin_unlock(&sbi->lock);

        num_scanned = i;
        for (i = 0; i < num_scanned && !list_empty(&folio_list); i++) {
            page = list_first_entry(&folio_list, struct page, lru);
            list_del(&page->lru);
            if (!fbmm_swapout_folio(page_folio(page))) {
                pr_err("swapout err\n");
                list_add_tail(&page->lru, &fail_list);
            } else {
                put_page(page);
            }
        }

        spin_lock(&sbi->lock);
        while (!list_empty(&fail_list)) {
            page = list_first_entry(&fail_list, struct page, lru);
            list_del(&page->lru);
            list_add_tail(&page->lru, &sbi->active_list);
            sbi->num_pages++;
        }
        spin_unlock(&sbi->lock);

    }

    sc->nr_scanned = i;
    return i;
}

static const struct super_operations basicmmfs_ops = {
    .statfs = basicmmfs_statfs,
    .free_inode = basicmmfs_free_inode,
    .drop_inode = generic_delete_inode,
    .show_options = basicmmfs_show_options,
    .nr_cached_objects = basicmmfs_nr_cached_objects,
    .free_cached_objects = basicmmfs_free_cached_objects,
    .copy_page_range = fbmm_copy_page_range,
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
    sbi->max_pages = nr_pages;
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
