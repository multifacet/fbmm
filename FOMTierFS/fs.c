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

// A lot of the boilerplate here is taken from the ramfs code

static const struct super_operations fomtierfs_ops;
static const struct inode_operations fomtierfs_dir_inode_operations;

struct fomtierfs_sb_info {
    struct dax_device *daxdev;
};

static int fomtierfs_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
                unsigned flags, struct iomap *iomap, struct iomap *srcmap)
{
    struct fomtierfs_sb_info *sb_info = inode->i_sb->s_fs_info;
    static u64 paddr = 0;

    iomap->flags = 0;
    iomap->bdev = inode->i_sb->s_bdev;
    iomap->dax_dev = sb_info->daxdev;
    iomap->offset = offset;
    iomap->length = length;
    if (paddr > offset) {
        iomap->type = IOMAP_MAPPED;
        iomap->addr = offset;
    } else {
        iomap->flags |= IOMAP_F_NEW;
        iomap->type = IOMAP_MAPPED;
        iomap->addr = paddr;
        paddr += length;
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
    pr_err("Bijan: vma flags: %lx\n", vma->vm_flags);
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

static int fomtierfs_writepages(struct address_space *mapping,
                                struct writeback_control *wbc)
{
    struct fomtierfs_sb_info *sbi = mapping->host->i_sb->s_fs_info;

    return dax_writeback_mapping_range(mapping, sbi->daxdev, wbc);
}

const struct address_space_operations fomtierfs_aops = {
    .writepages = fomtierfs_writepages,
    .direct_IO = noop_direct_IO,
    .set_page_dirty = __set_page_dirty_no_writeback,
    .invalidatepage = noop_invalidatepage,
};

struct inode *fomtierfs_get_inode(struct super_block *sb,
                const struct inode *dir, umode_t mode, dev_t dev)
{
    struct inode *inode = new_inode(sb);

    if (!inode)
        return NULL;

    inode->i_ino = get_next_ino();
    inode_init_owner(&init_user_ns, inode, dir, mode);
    inode->i_mapping->a_ops = &fomtierfs_aops;
    inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
    inode->i_flags |= S_DAX;
    pr_err("Bijan: Get Inode %x\n", inode->i_flags);
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

static int fomtierfs_show_options(struct seq_file *m, struct dentry *root)
{
    return 0;
}

static const struct super_operations fomtierfs_ops = {
	.statfs		= simple_statfs,
	.drop_inode	= generic_delete_inode,
	.show_options	= fomtierfs_show_options,
};

const struct fs_parameter_spec fomtierfs_fs_parameters[] = {
    {}
};

static int fomtierfs_fill_super(struct super_block *sb, void *data, int silent)
{
    struct inode *inode;
    struct dax_device *dax_dev = fs_dax_get_by_bdev(sb->s_bdev);
    struct fomtierfs_sb_info *sbi = kzalloc(sizeof(struct fomtierfs_sb_info), GFP_KERNEL);

    sbi->daxdev = dax_dev;

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

    inode = fomtierfs_get_inode(sb, NULL, S_IFDIR | 0777, 0);
    sb->s_root = d_make_root(inode);
    if (!sb->s_root)
        return -ENOMEM;

    return 0;
}

static struct dentry *fomtierfs_mount(struct file_system_type *fs_type, int flags,
                const char *dev_name, void *data)
{
    return mount_bdev(fs_type, flags, dev_name, data, fomtierfs_fill_super);
}

static void fomtierfs_kill_sb(struct super_block *sb)
{
    kill_litter_super(sb);
}

static struct file_system_type fomtierfs_fs_type = {
    .owner = THIS_MODULE,
    .name = "FOMTierFS",
    .mount = fomtierfs_mount,
    .parameters = fomtierfs_fs_parameters,
    .kill_sb = fomtierfs_kill_sb,
    .fs_flags = FS_USERNS_MOUNT | FS_REQUIRES_DEV,
};

int __init init_module(void)
{
    printk(KERN_INFO "Starting FOMTierFS");
    register_filesystem(&fomtierfs_fs_type);
    return 0;
}

void cleanup_module(void)
{
    printk(KERN_ERR "Removing FOMTierFS");
    unregister_filesystem(&fomtierfs_fs_type);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bijan Tabatabai");
