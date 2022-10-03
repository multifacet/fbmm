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

// A lot of the boilerplate here is taken from the ramfs code

static const struct super_operations fomtierfs_ops;
static const struct inode_operations fomtierfs_dir_inode_operations;

static vm_fault_t fomtierfs_fault(struct vm_fault *vmf)
{
    vm_fault_t result = 0;
    pte_t entry;

    if (vmf->flags & FAULT_FLAG_MKWRITE) {
        entry = pte_mkwrite(vmf->orig_pte);

    } else {
        struct page *page = alloc_pages(__GFP_ZERO | GFP_USER | GFP_ATOMIC, 0);
        if (!page)
            return VM_FAULT_OOM;

        entry = mk_pte(page, vmf->vma->vm_page_prot);
        if (vmf->flags & FAULT_FLAG_WRITE) {
            entry = pte_mkwrite(entry);
        }

        get_page(page);
        vmf->page = page;

    }
    vmf->pte = pte_offset_map_lock(vmf->vma->vm_mm, vmf->pmd, vmf->address, &vmf->ptl);

    set_pte_at(vmf->vma->vm_mm, vmf->address, vmf->pte, entry);
    pte_unmap_unlock(vmf->pte, vmf->ptl);

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

    return 0;
}

static unsigned long fomtierfs_mmu_get_unmapped_area(struct file *file,
		unsigned long addr, unsigned long len, unsigned long pgoff,
		unsigned long flags)
{
	return current->mm->get_unmapped_area(file, addr, len, pgoff, flags);
}

const struct file_operations fomtierfs_file_operations = {
	.read_iter	= generic_file_read_iter,
	.write_iter	= generic_file_write_iter,
	.mmap		= fomtierfs_mmap,
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

struct inode *fomtierfs_get_inode(struct super_block *sb,
                const struct inode *dir, umode_t mode, dev_t dev)
{
    struct inode *inode = new_inode(sb);

    if (!inode)
        return NULL;

    inode->i_ino = get_next_ino();
    inode_init_owner(&init_user_ns, inode, dir, mode);
    inode->i_mapping->a_ops = &ram_aops;
    mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
    mapping_set_unevictable(inode->i_mapping);
    inode->i_atime = inode->i_mtime = inode->i_ctime = current_time(inode);
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

static int fomtierfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
    return 0;
}

static int fomtierfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
    struct inode *inode;

    sb->s_maxbytes = MAX_LFS_FILESIZE;
    sb->s_blocksize = PAGE_SIZE;
    sb->s_blocksize_bits = PAGE_SHIFT;
    sb->s_magic = 0xDEADBEEF;
    sb->s_op = &fomtierfs_ops;
    sb->s_time_gran = 1;

    inode = fomtierfs_get_inode(sb, NULL, S_IFDIR | 0777, 0);
    sb->s_root = d_make_root(inode);
    if (!sb->s_root)
        return -ENOMEM;

    return 0;
}

static int fomtierfs_get_tree(struct fs_context *fc)
{
    return get_tree_nodev(fc, fomtierfs_fill_super);
}

static void fomtierfs_free_fc(struct fs_context *fc) {}

static const struct fs_context_operations fomtierfs_context_ops = {
    .free = fomtierfs_free_fc,
    .parse_param = fomtierfs_parse_param,
    .get_tree = fomtierfs_get_tree,
};

int fomtierfs_init_fs_context(struct fs_context *fc)
{
    fc->s_fs_info = NULL;
    fc->ops = &fomtierfs_context_ops;
    return 0;
}

static void fomtierfs_kill_sb(struct super_block *sb)
{
    kill_litter_super(sb);
}

static struct file_system_type fomtierfs_fs_type = {
    .name = "FOMTierFS",
    .init_fs_context = fomtierfs_init_fs_context,
    .parameters = fomtierfs_fs_parameters,
    .kill_sb = fomtierfs_kill_sb,
    .fs_flags = FS_USERNS_MOUNT,
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
