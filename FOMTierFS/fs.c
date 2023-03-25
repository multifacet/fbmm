#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/pagemap.h>
#include <linux/fs_parser.h>
#include <linux/fs_context.h>
#include <linux/fs.h>
#include <linux/iomap.h>
#include <linux/gfp.h>
#include <linux/pfn_t.h>
#include <linux/list.h>
#include <linux/iomap.h>
#include <linux/dax.h>
#include <linux/mman.h>
#include <linux/statfs.h>
#include <linux/kobject.h>

#include "fs.h"

// A lot of the boilerplate here is taken from the ramfs code

static const struct super_operations fomtierfs_ops;
static const struct inode_operations fomtierfs_dir_inode_operations;

// This is a copy of the sb_info struct. It should only be used in sysfs files
static struct fomtierfs_sb_info *sysfs_sb_info = NULL;

struct fomtierfs_sb_info *FTFS_SB(struct super_block *sb)
{
    return sb->s_fs_info;
}

struct fomtierfs_inode_info *FTFS_I(struct inode *inode)
{
    return inode->i_private;
}

static int fomtierfs_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
                unsigned flags, struct iomap *iomap, struct iomap *srcmap)
{
    struct fomtierfs_sb_info *sbi = FTFS_SB(inode->i_sb);
    struct fomtierfs_inode_info *inode_info = FTFS_I(inode);
    struct fomtierfs_dev_info *prim, *sec;
    struct fomtierfs_page_map *mapping;
    struct fomtierfs_page *page;
    u64 page_offset;
    u64 page_shift;

    page_shift = inode->i_sb->s_blocksize_bits;
    // Calculate the "page" the offset belongs to
    page_offset = offset >> page_shift;

    iomap->flags = 0;
    iomap->offset = offset;
    iomap->length = length;

    mapping = fomtierfs_find_map(&inode_info->page_maps, page_offset);

    if (!mapping) {
        mapping = kzalloc(sizeof(struct fomtierfs_page_map), GFP_KERNEL);
        if (!mapping) {
            pr_err("FOMTierFS: Error allocating new mapping");
            return -ENOMEM;
        }

        // Decide which device to allocate from
        if (sbi->alloc_fast) {
            prim = &sbi->mem[FAST_MEM];
            sec = &sbi->mem[SLOW_MEM];
        } else {
            prim = &sbi->mem[SLOW_MEM];
            sec = &sbi->mem[FAST_MEM];
        }
        sbi->alloc_fast = !sbi->alloc_fast;

        // A mapping does not exist for this offset, so allocate one from the free list.
        if (list_empty(&prim->free_list)) {
            if (!list_empty(&sec->free_list)) {
                prim = sec;
            } else {
                pr_err("FOMTierFS: No more entries in the free list");
                kfree(mapping);
                return -ENOMEM;
            }
        }
        page = list_first_entry(&prim->free_list, struct fomtierfs_page, list);
        list_del(&page->list);
        prim->free_pages--;

        // Save this new mapping
        mapping->page_offset = page_offset;
        mapping->page = page;
        if (!fomtierfs_insert_mapping(&inode_info->page_maps, mapping)) {
            BUG();
        }

        iomap->flags |= IOMAP_F_NEW;
        iomap->type = IOMAP_MAPPED;
        iomap->addr = page->page_num << page_shift;
        iomap->bdev = prim->bdev;
        iomap->dax_dev = prim->daxdev;
    } else {
        // There is already a page allocated for this offset, so just use that
        iomap->type = IOMAP_MAPPED;
        iomap->addr = mapping->page->page_num << page_shift;
        iomap->bdev = sbi->mem[mapping->page->type].bdev;
        iomap->dax_dev = sbi->mem[mapping->page->type].daxdev;
    }

    return 0;
}

static int fomtierfs_iomap_end(struct inode *inode, loff_t offset, loff_t length,
                ssize_t written, unsigned flags, struct iomap *iomap)
{
    return 0;
}

const struct iomap_ops fomtierfs_iomap_ops = {
    .iomap_begin = fomtierfs_iomap_begin,
    .iomap_end = fomtierfs_iomap_end,
};

static vm_fault_t fomtierfs_fault(struct vm_fault *vmf)
{
    vm_fault_t result = 0;
    pfn_t pfn;
    int error;

    result = dax_iomap_fault(vmf, PE_SIZE_PTE, &pfn, &error, &fomtierfs_iomap_ops);

    return result;
}

static struct vm_operations_struct fomtierfs_vm_ops = {
    .fault = fomtierfs_fault,
    .page_mkwrite = fomtierfs_fault,
    .pfn_mkwrite = fomtierfs_fault,
};

static int fomtierfs_mmap(struct file *file, struct vm_area_struct *vma)
{
    file_accessed(file); // TODO: probably don't need this
    vma->vm_ops = &fomtierfs_vm_ops;
    vma->vm_flags |= VM_MIXEDMAP | VM_HUGEPAGE;

    return 0;
}

static unsigned long fomtierfs_mmu_get_unmapped_area(struct file *file,
		unsigned long addr, unsigned long len, unsigned long pgoff,
		unsigned long flags)
{
	return current->mm->get_unmapped_area(file, addr, len, pgoff, flags);
}

const struct file_operations fomtierfs_file_operations = {
	.mmap		= fomtierfs_mmap,
    .mmap_supported_flags = MAP_SYNC,
	.fsync		= noop_fsync,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.llseek		= generic_file_llseek,
	.get_unmapped_area	= fomtierfs_mmu_get_unmapped_area,
};

const struct inode_operations fomtierfs_file_inode_operations = {
	.setattr	= simple_setattr,
	.getattr	= simple_getattr,
};

const struct address_space_operations fomtierfs_aops = {
    .direct_IO = noop_direct_IO,
    .set_page_dirty = __set_page_dirty_no_writeback,
    .invalidatepage = noop_invalidatepage,
};

struct inode *fomtierfs_get_inode(struct super_block *sb,
                const struct inode *dir, umode_t mode, dev_t dev)
{
    struct inode *inode = new_inode(sb);
    struct fomtierfs_inode_info *info;

    if (!inode)
        return NULL;

    info = kzalloc(sizeof(struct fomtierfs_inode_info), GFP_KERNEL);
    if (!info) {
        pr_err("FOMTierFS: Failure allocating FOMTierFS inode");
        return NULL;
    }
    info->page_maps = RB_ROOT;

    inode->i_ino = get_next_ino();
    inode_init_owner(&init_user_ns, inode, dir, mode);
    inode->i_mapping->a_ops = &fomtierfs_aops;
    inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
    inode->i_flags |= S_DAX;
    inode->i_private = info;
    switch (mode & S_IFMT) {
        case S_IFREG:
            inode->i_op = &fomtierfs_file_inode_operations;
            inode->i_fop = &fomtierfs_file_operations;
            break;
        case S_IFDIR:
            inode->i_op = &fomtierfs_dir_inode_operations;
            inode->i_fop = &simple_dir_operations;

            /* Directory inodes start off with i_nlink == 2 (for "." entry) */
            inc_nlink(inode);
            break;
        default:
            return NULL;
    }

    return inode;
}

static int
fomtierfs_mknod(struct user_namespace *mnt_userns, struct inode *dir,
        struct dentry *dentry, umode_t mode, dev_t dev)
{
    struct inode * inode = fomtierfs_get_inode(dir->i_sb, dir, mode, dev);
    int error = -ENOSPC;

    if (inode) {
        d_instantiate(dentry, inode);
        dget(dentry); /* Extra count - pin the dentry in core */
        error = 0;
        dir->i_mtime = dir->i_ctime = current_time(dir);
    }

    return error;
}

static int fomtierfs_mkdir(struct user_namespace *mnt_userns, struct inode *dir,
                struct dentry *dentry, umode_t mode)
{
    return -EINVAL;
}

static int fomtierfs_create(struct user_namespace *mnt_userns, struct inode *dir,
                struct dentry *dentry, umode_t mode, bool excl)
{
    return fomtierfs_mknod(&init_user_ns, dir, dentry, 0777 | S_IFREG, 0);
}

static int fomtierfs_symlink(struct user_namespace *mnt_userns, struct inode *dir,
                struct dentry *dentry, const char *symname)
{
    return -EINVAL;
}

static int fomtierfs_tmpfile(struct user_namespace *mnt_userns,
            struct inode *dir, struct dentry *dentry, umode_t mode)
{
    struct inode *inode;

    inode = fomtierfs_get_inode(dir->i_sb, dir, mode, 0);
    if (!inode)
        return -ENOSPC;
    d_tmpfile(dentry, inode);
    return 0;
}

static const struct inode_operations fomtierfs_dir_inode_operations = {
	.create		= fomtierfs_create,
	.lookup		= simple_lookup,
	.link		= simple_link,
	.unlink		= simple_unlink,
	.symlink	= fomtierfs_symlink,
	.mkdir		= fomtierfs_mkdir,
	.rmdir		= simple_rmdir,
	.mknod		= fomtierfs_mknod,
	.rename		= simple_rename,
	.tmpfile	= fomtierfs_tmpfile,
};

static int fomtierfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    struct super_block *sb = dentry->d_sb;
    struct fomtierfs_sb_info *sbi = FTFS_SB(sb);

    buf->f_type = sb->s_magic;
    buf->f_bsize = PAGE_SIZE;
    buf->f_blocks = sbi->mem[FAST_MEM].num_pages + sbi->mem[SLOW_MEM].num_pages;
    buf->f_bfree = buf->f_bavail = sbi->mem[FAST_MEM].free_pages + sbi->mem[SLOW_MEM].num_pages;
    buf->f_files = LONG_MAX;
    buf->f_ffree = LONG_MAX;
    buf->f_namelen = 255;

    return 0;
}

static void fomtierfs_free_inode(struct inode *inode) {
    struct fomtierfs_sb_info *sbi = FTFS_SB(inode->i_sb);
    struct fomtierfs_inode_info *inode_info = FTFS_I(inode);
    struct rb_node *node = inode_info->page_maps.rb_node;
    struct fomtierfs_page_map *mapping;
    struct fomtierfs_page *page;

    // Free each mapping in the inode, and place each page back into the free list
    while (node) {
        mapping = container_of(node, struct fomtierfs_page_map, node);

        rb_erase(node, &inode_info->page_maps);

        page = mapping->page;

        list_add_tail(&page->list, &sbi->mem[page->type].free_list);
        sbi->mem[page->type].free_pages++;

        kfree(mapping);

        node = inode_info->page_maps.rb_node;
    }

}

static int fomtierfs_show_options(struct seq_file *m, struct dentry *root)
{
    return 0;
}

static const struct super_operations fomtierfs_ops = {
	.statfs		= fomtierfs_statfs,
    .free_inode = fomtierfs_free_inode,
	.drop_inode	= generic_delete_inode,
	.show_options	= fomtierfs_show_options,
};

enum fomtierfs_param {
    Opt_slowmem, Opt_source
};

const struct fs_parameter_spec fomtierfs_fs_parameters[] = {
    fsparam_string("slowmem", Opt_slowmem),
    fsparam_string("source", Opt_source),
    {},
};

static int fomtierfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
    struct fs_parse_result result;
    int opt;

    opt = fs_parse(fc, fomtierfs_fs_parameters, param, &result);
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
    case Opt_slowmem:
        fc->fs_private = kstrdup(param->string, GFP_KERNEL);
        break;
    case Opt_source:
        fc->source = kstrdup(param->string, GFP_KERNEL);
        break;
    default:
        pr_err("FOMTierFS: unrecognized option %s", param->key);
        break;
    }

    return 0;
}

static int fomtierfs_populate_dev_info(struct fomtierfs_dev_info *di, struct block_device *bdev, enum fomtierfs_mem_type type)
{
    int ret = 0;
    long i;
    long num_pages;
    pfn_t _pfn;
    struct fomtierfs_page *tmp;
    struct fomtierfs_page *cursor, *temp;

    di->bdev = bdev;
    di->daxdev = fs_dax_get_by_bdev(bdev);

    // Determine how many pages are in the device
    num_pages = dax_direct_access(di->daxdev, 0, LONG_MAX / PAGE_SIZE,
                    &di->virt_addr, &_pfn);
    if (num_pages <= 0) {
        pr_err("FOMTierFS: Determining device size failed");
        return -EIO;
    }

    di->num_pages = num_pages;
    di->free_pages = num_pages;

    INIT_LIST_HEAD(&di->free_list);
    for (i = 0; i < num_pages; i++) {
        struct fomtierfs_page *page = kzalloc(sizeof(struct fomtierfs_page), GFP_KERNEL);
        if (!page) {
            ret = -ENOMEM;
            goto err;
        }

        page->page_num = i;
        page->type = type;
        list_add(&page->list, &di->free_list);
    }

    i = 0;
    list_for_each_entry(tmp, &di->free_list, list) {
        i++;
    }

    return 0;

err:
    // Free all of the entries we've put in the list so far
    list_for_each_entry_safe(cursor, temp, &di->free_list, list) {
        list_del(&cursor->list);
        kfree(cursor);
    }

    return ret;
}

static int fomtierfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
    struct inode *inode;
    struct block_device *slow_dev;
    struct fomtierfs_sb_info *sbi = kzalloc(sizeof(struct fomtierfs_sb_info), GFP_KERNEL);
    char *slow_dev_name = fc->fs_private;
    int ret;

    sb->s_fs_info = sbi;
    sb->s_maxbytes = MAX_LFS_FILESIZE;
    sb->s_blocksize = PAGE_SIZE;
    sb->s_blocksize_bits = PAGE_SHIFT;
    sb->s_magic = 0xDEADBEEF;
    sb->s_op = &fomtierfs_ops;
    sb->s_time_gran = 1;
    if(!sb_set_blocksize(sb, PAGE_SIZE)) {
        pr_err("FOMTierFS: error setting blocksize");
    }

    // Populate the device information for the fast and slow mem
    ret = fomtierfs_populate_dev_info(&sbi->mem[FAST_MEM], sb->s_bdev, FAST_MEM);
    if (ret != 0) {
        pr_err("FOMTierFS: Error populating fast mem device information");
        kfree(sbi);
        return ret;
    }

    slow_dev = blkdev_get_by_path(slow_dev_name, FMODE_READ|FMODE_WRITE|FMODE_EXCL, sbi);
    if (IS_ERR(slow_dev)) {
        ret = PTR_ERR(slow_dev);
        pr_err("FOMTierFS: Error opening slow mem device %s %d", slow_dev_name, ret);
        kfree(sbi);
        return ret;
    }
    ret = fomtierfs_populate_dev_info(&sbi->mem[SLOW_MEM], slow_dev, SLOW_MEM);
    if (ret != 0) {
        pr_err("FOMTierFS: Error populating slow mem device information");
        kfree(sbi);
        return ret;
    }

    inode = fomtierfs_get_inode(sb, NULL, S_IFDIR | 0777, 0);
    sb->s_root = d_make_root(inode);
    if (!sb->s_root) {
        kfree(sbi);
        return -ENOMEM;
    }

    sbi->alloc_fast = true;
    fc->s_fs_info = sbi;
    sysfs_sb_info = sbi;

    return 0;
}

static int fomtierfs_get_tree(struct fs_context *fc)
{
    return get_tree_bdev(fc, fomtierfs_fill_super);
}

static void fomtierfs_free_fc(struct fs_context *fc)
{
}

static const struct fs_context_operations fomtierfs_context_ops = {
	.free		= fomtierfs_free_fc,
	.parse_param	= fomtierfs_parse_param,
	.get_tree	= fomtierfs_get_tree,
};

int fomtierfs_init_fs_context(struct fs_context *fc)
{
    fc->ops = &fomtierfs_context_ops;
    return 0;
}

static void fomtierfs_kill_sb(struct super_block *sb)
{
    kill_litter_super(sb);
}

static struct file_system_type fomtierfs_fs_type = {
    .owner = THIS_MODULE,
    .name = "FOMTierFS",
    .init_fs_context = fomtierfs_init_fs_context,
    .parameters = fomtierfs_fs_parameters,
    .kill_sb = fomtierfs_kill_sb,
    .fs_flags = FS_USERNS_MOUNT | FS_REQUIRES_DEV,
};

static ssize_t usage_show(struct kobject *kobj,
        struct kobj_attribute *attr, char *buf)
{
    // I'd prefet to tie the sb info to the sysfs file, but I can't find a way to do that,
    // so I'm just using a cached pointer to it in a global variable
    if (sysfs_sb_info) {
        return sprintf(buf,
            "fast total: %lld\tfree: %lld\n"
            "slow total: %lld\tfree: %lld\n",
            sysfs_sb_info->mem[FAST_MEM].num_pages,
            sysfs_sb_info->mem[FAST_MEM].free_pages,
            sysfs_sb_info->mem[SLOW_MEM].num_pages,
            sysfs_sb_info->mem[SLOW_MEM].free_pages);
    } else {
        return sprintf(buf, "Not mounted");
    }
}

static ssize_t usage_store(struct kobject *kobj,
        struct kobj_attribute *attr,
        const char *buf, size_t count)
{
    return -EINVAL;
}
static struct kobj_attribute usage_attr =
__ATTR(stats, 0444, usage_show, usage_store);

static struct attribute *fomtierfs_attr[] = {
    &usage_attr.attr,
    NULL,
};

static const struct attribute_group fomtierfs_attr_group = {
    .attrs = fomtierfs_attr,
};

int __init init_module(void)
{
    struct kobject *fomtierfs_kobj;
    int err;

    printk(KERN_INFO "Starting FOMTierFS");
    register_filesystem(&fomtierfs_fs_type);

    fomtierfs_kobj = kobject_create_and_add("fomtierfs", fs_kobj);
    if (unlikely(!fomtierfs_kobj)) {
        pr_err("Failed to create fomtierfs kobj\n");
        return -ENOMEM;
    }

    err = sysfs_create_group(fomtierfs_kobj, &fomtierfs_attr_group);
    if (err) {
        pr_err("Failed to register fomtierfs group\n");
        kobject_put(fomtierfs_kobj);
        return err;
    }
    return 0;
}

void cleanup_module(void)
{
    printk(KERN_ERR "Removing FOMTierFS");
    unregister_filesystem(&fomtierfs_fs_type);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bijan Tabatabai");
