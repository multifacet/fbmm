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

#include "bandwidth.h"

static const struct super_operations bwmmfs_ops;
static const struct inode_operations bwmmfs_dir_inode_operations;

struct bwmmfs_sb_info *BWMMFS_SB(struct super_block *sb)
{
    return sb->s_fs_info;
}

struct bwmmfs_inode_info *BWMMFS_I(struct inode *inode)
{
    return inode->i_private;
}

static vm_fault_t bwmmfs_fault(struct vm_fault *vmf)
{
    return VM_FAULT_OOM;
}

static struct vm_operations_struct bwmmfs_vm_ops = {
    .fault = bwmmfs_fault,
    .page_mkwrite = bwmmfs_fault,
    .pfn_mkwrite = bwmmfs_fault,
};

static int bwmmfs_mmap(struct file *file, struct vm_area_struct *vma)
{
    file_accessed(file);
    vma->vm_ops = &bwmmfs_vm_ops;
    vma->vm_flags |= VM_MIXEDMAP | VM_HUGEPAGE;

    return 0;
}

static long bwmmfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
    return -EINVAL;
}

const struct file_operations bwmmfs_file_operations = {
    .mmap = bwmmfs_mmap,
    .mmap_supported_flags = MAP_SYNC,
    .fsync = noop_fsync,
    .splice_read = generic_file_splice_read,
    .splice_write = iter_file_splice_write,
    .llseek = generic_file_llseek,
    .get_unmapped_area = thp_get_unmapped_area,
    .fallocate = bwmmfs_fallocate,
};

const struct inode_operations bwmmfs_file_inode_operations = {
    .setattr = simple_setattr,
    .getattr = simple_getattr,
};

const struct address_space_operations bwmmfs_aops = {
    .direct_IO = noop_direct_IO,
    .dirty_folio = noop_dirty_folio,
};

struct inode *bwmmfs_get_inode(struct super_block *sb,
                const struct inode *dir, umode_t mode, dev_t dev)
{
    struct inode *inode = new_inode(sb);
    struct bwmmfs_inode_info *info;

    if (!inode)
        return NULL;

    info = kzalloc(sizeof(struct bwmmfs_inode_info), GFP_KERNEL);
    if (!info) {
        pr_err("ContigMMFS: Failure allocating inode");
        return NULL;
    }
    mt_init(&info->mt);

    inode->i_ino = get_next_ino();
    inode_init_owner(&init_user_ns, inode, dir, mode);
    inode->i_mapping->a_ops = &bwmmfs_aops;
    inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
    inode->i_flags |= S_DAX;
    inode->i_private = info;
    switch (mode &S_IFMT) {
        case S_IFREG:
            inode->i_op = &bwmmfs_file_inode_operations;
            inode->i_fop = &bwmmfs_file_operations;
            break;
        case S_IFDIR:
            inode->i_op = &bwmmfs_dir_inode_operations;
            inode->i_fop = &simple_dir_operations;

            /* Directory inodes start off with i_nlink == 2 (for "." entry) */
            inc_nlink(inode);
            break;
        default:
            return NULL;
    }

    return inode;
}

static int bwmmfs_mknod(struct user_namespace *mnt_userns, struct inode *dir,
            struct dentry *dentry, umode_t mode, dev_t dev)
{
    struct inode *inode = bwmmfs_get_inode(dir->i_sb, dir, mode, dev);
    int error = -ENOSPC;

    if (inode) {
        d_instantiate(dentry, inode);
        dget(dentry);
        error = 0;
        dir->i_mtime = dir->i_ctime = current_time(dir);
    }

    return error;
}

static int bwmmfs_mkdir(struct user_namespace *mnt_userns, struct inode *dir,
            struct dentry *dentry, umode_t mode)
{
    return -EINVAL;
}

static int bwmmfs_create(struct user_namespace *mnt_userns, struct inode *dir,
            struct dentry *dentry, umode_t mode, bool excl)
{
    return bwmmfs_mknod(&init_user_ns, dir, dentry, 0777 | S_IFREG, 0);
}

static int bwmmfs_symlink(struct user_namespace *mnt_userns, struct inode *dir,
            struct dentry *dentry, const char *symname)
{
    return -EINVAL;
}

static int bwmmfs_tmpfile(struct user_namespace *mnt_userns,
            struct inode*dir, struct file *file, umode_t mode)
{
    struct inode *inode;

    inode = bwmmfs_get_inode(dir->i_sb, dir, mode, 0);
    if (!inode)
        return -ENOSPC;
    d_tmpfile(file, inode);
    return finish_open_simple(file, 0);
}

static const struct inode_operations bwmmfs_dir_inode_operations = {
    .create     = bwmmfs_create,
    .lookup     = simple_lookup,
    .link       = simple_link,
    .unlink     = simple_unlink,
    .symlink    = bwmmfs_symlink,
    .mkdir      = bwmmfs_mkdir,
    .rmdir      = simple_rmdir,
    .mknod      = bwmmfs_mknod,
    .rename     = simple_rename,
    .tmpfile    = bwmmfs_tmpfile,
};

static int bwmmfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
    struct super_block *sb = dentry->d_sb;
    struct bwmmfs_sb_info *sbi = BWMMFS_SB(sb);

    buf->f_type = sb->s_magic;
    buf->f_bsize = PAGE_SIZE;
    buf->f_blocks = sbi->num_pages;
    buf->f_bfree = buf->f_bavail = 0;
    buf->f_files = LONG_MAX;
    buf->f_ffree = LONG_MAX;
    buf->f_namelen = 255;

    return 0;
}

static void bwmmfs_free_inode(struct inode *inode)
{
}

static int bwmmfs_show_options(struct seq_file *m, struct dentry *root)
{
    return 0;
}

static const struct super_operations bwmmfs_ops = {
    .statfs = bwmmfs_statfs,
    .free_inode = bwmmfs_free_inode,
    .drop_inode = generic_delete_inode,
    .show_options = bwmmfs_show_options,
};

static int bwmmfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
    struct inode *inode;
    struct bwmmfs_sb_info *sbi = kzalloc(sizeof(struct bwmmfs_sb_info), GFP_KERNEL);

    if (!sbi) {
        return -ENOMEM;
    }

    sb->s_fs_info = sbi;
    sb->s_maxbytes = MAX_LFS_FILESIZE;
    sb->s_magic = 0xDEADBEEF;
    sb->s_op = &bwmmfs_ops;
    sb->s_time_gran = 1;
    sb->s_blocksize = PAGE_SIZE;
    sb->s_blocksize_bits = PAGE_SHIFT;

    sbi->num_pages = 0;

    inode = bwmmfs_get_inode(sb, NULL, S_IFDIR | 0755, 0);
    sb->s_root = d_make_root(inode);
    if (!sb->s_root) {
        kfree(sbi);
        return -ENOMEM;
    }

    return 0;
}

static int bwmmfs_get_tree(struct fs_context *fc)
{
    return get_tree_nodev(fc, bwmmfs_fill_super);
}

enum bwmmfs_param {
    Opt_maxsize,
};

const struct fs_parameter_spec bwmmfs_fs_parameters[] = {
    fsparam_u64("maxsize", Opt_maxsize),
};

static int bwmmfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
    return 0;
}

static void bwmmfs_free_fc(struct fs_context *fc)
{
}

static const struct fs_context_operations bwmmfs_context_ops = {
    .free = bwmmfs_free_fc,
    .parse_param = bwmmfs_parse_param,
    .get_tree = bwmmfs_get_tree,
};

int bwmmfs_init_fs_context(struct fs_context *fc)
{
    fc->ops = &bwmmfs_context_ops;

    return 0;
}

static void bwmmfs_kill_sb(struct super_block *sb)
{
    struct bwmmfs_sb_info *sbi = BWMMFS_SB(sb);

    kfree(sbi);
    kill_litter_super(sb);
}

static struct file_system_type bwmmfs_fs_type = {
    .owner = THIS_MODULE,
    .name = "BandwidthMMFS",
    .init_fs_context = bwmmfs_init_fs_context,
    .parameters = bwmmfs_fs_parameters,
    .kill_sb = bwmmfs_kill_sb,
    .fs_flags = FS_USERNS_MOUNT,
};

int __init init_module(void)
{
    printk(KERN_INFO "Starting BandwidthMMFS\n");
    register_filesystem(&bwmmfs_fs_type);

    return 0;
}

void cleanup_module(void)
{
    printk(KERN_INFO "Removing BandwidthMMFS");
    unregister_filesystem(&bwmmfs_fs_type);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bijan Tabatabai");
