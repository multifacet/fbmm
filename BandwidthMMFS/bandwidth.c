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

// Count of how many times a bwmmfs has been mounted.
// Used to index the sysfs directories for the mount
static atomic_t mount_count = ATOMIC_INIT(0);
static struct kobj_attribute node_weight_attr;

struct bwmmfs_sb_info *BWMMFS_SB(struct super_block *sb)
{
    return sb->s_fs_info;
}

struct bwmmfs_inode_info *BWMMFS_I(struct inode *inode)
{
    return inode->i_private;
}

static struct page *bwmmfs_alloc_page(struct bwmmfs_sb_info *sbi, struct bwmmfs_inode_info *inode_info)
{
    int weight_count = 0;
    int current_count;
    struct bwmmfs_node_weights *node_weight;
    int nid = NUMA_NO_NODE;

    down_read(&sbi->weights_lock);
    current_count = atomic_inc_return(&inode_info->alloc_count) % sbi->total_weight;
    list_for_each_entry(node_weight, &sbi->node_list, list) {
        weight_count += node_weight->weight;
        if (current_count < weight_count) {
            nid = node_weight->nid;
            break;
        }
    }
    up_read(&sbi->weights_lock);

    if (nid == NUMA_NO_NODE)
        BUG();

    return alloc_pages_node(nid, GFP_HIGHUSER | __GFP_ZERO, 0);
}

static vm_fault_t bwmmfs_fault(struct vm_fault *vmf)
{
    struct vm_area_struct *vma = vmf->vma;
    struct inode *inode = vma->vm_file->f_inode;
    struct bwmmfs_inode_info * inode_info;
    struct bwmmfs_sb_info *sbi;
    struct page *page;
    loff_t offset = vmf->address - vma->vm_start + (vma->vm_pgoff << PAGE_SHIFT);
    pte_t entry;

    inode_info = BWMMFS_I(inode);
    sbi = BWMMFS_SB(inode->i_sb);

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

    page = mtree_load(&inode_info->mt, offset);
    if (!page) {
        page = bwmmfs_alloc_page(sbi, inode_info);
        if (!page) {
            pte_unmap_unlock(vmf->pte, vmf->ptl);
            return VM_FAULT_OOM;
        }
        sbi->num_pages++;

        mtree_store(&inode_info->mt, offset, page, GFP_KERNEL);
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
    get_page(page);

unlock:
    pte_unmap_unlock(vmf->pte, vmf->ptl);
    return VM_FAULT_NOPAGE;
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

    return 0;
}

static long bwmmfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
    struct inode *inode = file_inode(file);
    struct bwmmfs_inode_info *inode_info = BWMMFS_I(inode);
    struct bwmmfs_sb_info *sbi = BWMMFS_SB(inode->i_sb);
    struct page *page;
    loff_t off;

    if (mode != 0) {
        return -EOPNOTSUPP;
    }

    // Allocate and add mappings for the desired range
    for (off = offset; off < offset + len; off += PAGE_SIZE) {
        page = bwmmfs_alloc_page(sbi, inode_info);
        if (!page) {
            return -ENOMEM;
        }


        mtree_store(&inode_info->mt, off, page, GFP_KERNEL);
    }

    return 0;
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
    atomic_set(&info->alloc_count, 0);

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
    struct bwmmfs_sb_info *sbi = BWMMFS_SB(inode->i_sb);
    struct bwmmfs_inode_info *inode_info = BWMMFS_I(inode);
    struct page *page;
    unsigned long index = 0;

    // Release all of the pages associated with the file
    mt_for_each(&inode_info->mt, page, index, ULONG_MAX) {
        sbi->num_pages--;
        put_page(page);
    }

    mtree_destroy(&inode_info->mt);
    kfree(inode_info);
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

// Basically taken from dynamic_kobj_type in /lib/kobject.c
static void kfree_wrapper(struct kobject *kobj) {
    kfree(kobj);
}
static const struct kobj_type bwmmfs_kobj_dyn_type = {
    .release = kfree_wrapper,
    .sysfs_ops = &kobj_sysfs_ops,
};

static const struct kobj_type bwmmfs_kobj_type = {
    .sysfs_ops = &kobj_sysfs_ops,
};

static int bwmmfs_fill_super(struct super_block *sb, struct fs_context *fc)
{
    struct inode *inode;
    struct bwmmfs_sb_info *sbi = kzalloc(sizeof(struct bwmmfs_sb_info), GFP_KERNEL);
    int mount_id;
    int err;
    int nid;

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
    INIT_LIST_HEAD(&sbi->node_list);
    init_rwsem(&sbi->weights_lock);

    //Setup the sysfs interface for setting the node weights
    mount_id = atomic_inc_return(&mount_count);
    kobject_init(&sbi->sysfs_kobj, &bwmmfs_kobj_type);
    err = kobject_add(&sbi->sysfs_kobj, fs_kobj, "bwmmfs%d", mount_id);
    if (err) {
        pr_err("Failed to create bwmmfs kobj\n");
        return err;
    }

    // Setup the directory for each NUMA node and set default weight values
    sbi->total_weight = 0;
    for_each_node(nid) {
        struct kobject *node_kobj;
        struct bwmmfs_node_weights *weight;

        node_kobj = kzalloc(sizeof(struct kobject), GFP_KERNEL);
        kobject_init(node_kobj, &bwmmfs_kobj_dyn_type);
        err = kobject_add(node_kobj, &sbi->sysfs_kobj, "node%d", nid);
        if (err) {
            pr_err("Failed to create kobject for node %d\n", nid);
            kobject_put(node_kobj);
            continue;
        }

        err = sysfs_create_file(node_kobj, &node_weight_attr.attr);
        if (err) {
            pr_err("Failed to add node weight file for node %d\n", nid);
            kobject_put(node_kobj);
            continue;
        }

        weight = kzalloc(sizeof(struct bwmmfs_node_weights), GFP_KERNEL);
        if (!weight)
            return -ENOMEM;

        weight->nid = nid;
        weight->weight = 1;
        sbi->total_weight++;
        list_add(&weight->list, &sbi->node_list);
    }

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

// Sysfs functions
static int get_nid_from_kobj(struct kobject *kobj, int *nid)
{
    const char *nid_str;
    int err;

    // Tease out the nid from kobj
    // The name is of the form "node%d", so skip past "node"
    nid_str = &kobj->name[4];
    err = kstrtoint(nid_str, 10, nid);
    return err;
}

static ssize_t node_weight_show(struct kobject *kobj, struct kobj_attribute *attr,
        char *buf)
{
    struct bwmmfs_sb_info *sbi = container_of(kobj->parent, struct bwmmfs_sb_info, sysfs_kobj);
    struct bwmmfs_node_weights *weight;
    int nid;
    int err;

    err = get_nid_from_kobj(kobj, &nid);
    if (err) {
        pr_err("Error parsing nid from %s\n", kobj->name);
        return err;
    }

    list_for_each_entry(weight, &sbi->node_list, list) {
        if (nid == weight->nid)
            return sprintf(buf, "%d\n", weight->weight);
    }

    return sprintf(buf, "Not found!\n");
}

static ssize_t node_weight_store(struct kobject *kobj, struct kobj_attribute *attr,
        const char *buf, size_t count)
{
    struct bwmmfs_sb_info *sbi = container_of(kobj->parent, struct bwmmfs_sb_info, sysfs_kobj);
    struct bwmmfs_node_weights *weight;
    int nid;
    u32 new_weight;
    int err;

    err = get_nid_from_kobj(kobj, &nid);
    if (err) {
        pr_err("Error parsing nid from %s\n", kobj->name);
        return err;
    }

    err = kstrtouint(buf, 10, &new_weight);
    if (err) {
        pr_err("Error parsing new weight from %s\n", buf);
        return err;
    }

    // We have to reset the total weight
    down_write(&sbi->weights_lock);
    sbi->total_weight = 0;
    list_for_each_entry(weight, &sbi->node_list, list) {
        if (nid == weight->nid)
            weight->weight = new_weight;

        sbi->total_weight += weight->weight;
    }
    up_write(&sbi->weights_lock);

    return count;
}


static struct kobj_attribute node_weight_attr =
__ATTR(weight, 0644, node_weight_show, node_weight_store);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Bijan Tabatabai");
