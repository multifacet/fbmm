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
    return VM_FAULT_OOM;
}

static struct vm_operations_struct contigmmfs_vm_ops = {
    .fault = contigmmfs_fault,
    .page_mkwrite = contigmmfs_fault,
    .pfn_mkwrite = contigmmfs_fault,
};

static int contigmmfs_mmap(struct file *file, struct vm_area_struct *vma)
{
    file_accessed(file);
    vma->vm_ops = &contigmmfs_vm_ops;
    vma->vm_flags |= VM_MIXEDMAP;

    return 0;
}

static long contigmmfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
    return -EOPNOTSUPP;
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
    //TODO
    return 0;
}

static void contigmmfs_free_inode(struct inode *inode)
{
    struct contigmmfs_inode_info *inode_info = CMMFS_I(inode);

    //TODO

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

    spin_lock_init(&sbi->lock);
    INIT_LIST_HEAD(&sbi->active_list);
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
