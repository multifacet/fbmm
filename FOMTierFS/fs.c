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
#include <linux/falloc.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/hugetlb.h>

#include <asm/tlbflush.h>

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

static inline void fomtierfs_nt_zero(void *kaddr)
{
	__asm__ (
		"push %%rax;"
		"push %%rcx;"
		"push %%rdi;"
		"movq   %0, %%rdi;"
		"xorq    %%rax, %%rax;"
		"movl    $4096/64, %%ecx;"
		".p2align 4;"
		"1:;"
		"decl    %%ecx;"
		"movnti  %%rax,(%%rdi);"
		"movnti  %%rax,0x8(%%rdi);"
		"movnti  %%rax,0x10(%%rdi);"
		"movnti  %%rax,0x18(%%rdi);"
		"movnti  %%rax,0x20(%%rdi);"
		"movnti  %%rax,0x28(%%rdi);"
		"movnti  %%rax,0x30(%%rdi);"
		"movnti  %%rax,0x38(%%rdi);"
		"leaq    64(%%rdi),%%rdi;"
		"jnz     1b;"
		"nop;"
		"pop %%rdi;"
		"pop %%rcx;"
		"pop %%rax;"
		: /* output */
		: "a" (kaddr)
	);
}

static inline void fomtierfs_nt_copy(void *to, void *from)
{
	__asm__ (
		"push %%rax;"
		"push %%rcx;"
		"push %%rdi;"
		"movq    %0, %%rdi;"
		"movq    %1, %%rax;"
		"movl    $4096/64, %%ecx;"
		".p2align 4;"
		"1:;"
		"decl    %%ecx;"
        "movq    (%%rax), %%rbx;"
		"movnti  %%rbx,(%%rdi);"
        "movq    0x8(%%rax), %%rbx;"
		"movnti  %%rbx,0x8(%%rdi);"
        "movq    0x10(%%rax), %%rbx;"
		"movnti  %%rbx,0x10(%%rdi);"
        "movq    0x18(%%rax), %%rbx;"
		"movnti  %%rbx,0x18(%%rdi);"
        "movq    0x20(%%rax), %%rbx;"
		"movnti  %%rbx,0x20(%%rdi);"
        "movq    0x28(%%rax), %%rbx;"
		"movnti  %%rbx,0x28(%%rdi);"
        "movq    0x30(%%rax), %%rbx;"
		"movnti  %%rbx,0x30(%%rdi);"
        "movq    0x38(%%rax), %%rbx;"
		"movnti  %%rbx,0x38(%%rdi);"
		"leaq    64(%%rdi),%%rdi;"
        "leaq    64(%%rax),%%rax;"
		"jnz     1b;"
		"nop;"
		"pop %%rdi;"
		"pop %%rcx;"
		"pop %%rax;"
		: /* output */
		: "r" (to), "r" (from)
        : "%rax", "%rdi", "%ecx", "%rbx"
	);
}

struct fomtierfs_page *fomtierfs_alloc_page(struct inode *inode, struct fomtierfs_sb_info *sbi, u64 page_offset)
{
    struct fomtierfs_page *page;
    struct fomtierfs_dev_info *prim, *sec;
    void* virt_addr;
    int i;

    // If the free memory in fast mem is greater than the alloc watermark,
    // alloc from fast mem, otherwise alloc from slow mem
    if (sbi->mem[FAST_MEM].free_pages > sbi->alloc_watermark) {
        prim = &sbi->mem[FAST_MEM];
        sec = &sbi->mem[SLOW_MEM];
    } else {
        prim = &sbi->mem[SLOW_MEM];
        sec = &sbi->mem[FAST_MEM];
    }

    // Try to allocate from the desired free list, otherwise try the other
    if (list_empty(&prim->free_list)) {
        if (!list_empty(&sec->free_list)) {
            prim = sec;
        } else {
            pr_err("FOMTierFS: No more entries in the free list");
            return NULL;
        }
    }

    spin_lock(&prim->lock);

    // Take a page from the free list
    page = list_first_entry(&prim->free_list, struct fomtierfs_page, list);
    list_del(&page->list);
    prim->free_pages--;

    spin_lock(&page->lock);
    page->page_offset = page_offset;
    page->num_base_pages = 0;
    page->inode = inode;
    page->last_accessed = true;
    spin_unlock(&page->lock);

    // Add the page to the active list
    list_add(&page->list, &prim->active_list);
    prim->active_pages++;

    spin_unlock(&prim->lock);

    virt_addr = prim->virt_addr + (page->page_num << sbi->page_shift);
    for (i = 0; i < sbi->page_size / PAGE_SIZE; i++)
        fomtierfs_nt_zero(virt_addr + (i << PAGE_SHIFT));

    return page;
}

void fomtierfs_return_page(struct fomtierfs_sb_info *sbi, struct fomtierfs_page *page)
{
    struct fomtierfs_dev_info *dev;

    dev = &sbi->mem[page->type];

    spin_lock(&dev->lock);

    // Remove the page from the active list
    list_del(&page->list);
    dev->active_pages--;

    spin_lock(&page->lock);
    page->page_offset = 0;
    page->num_base_pages = 0;
    page->inode = NULL;
    spin_unlock(&page->lock);

    // Add the page to the end of the free list
    list_add_tail(&page->list, &dev->free_list);
    dev->free_pages++;

    spin_unlock(&dev->lock);
}

static long fomtierfs_free_range(struct inode *inode, loff_t offset, loff_t len)
{
    struct fomtierfs_sb_info *sbi = FTFS_SB(inode->i_sb);
    struct fomtierfs_inode_info *inode_info = FTFS_I(inode);
    struct rb_node *node, *next_node;
    struct fomtierfs_page *page;
    u64 page_offset = offset >> sbi->page_shift;
    u64 num_pages = len >> sbi->page_shift;

    write_lock(&inode_info->map_lock);
    // TODO: Change this to instead of needing the page at the offset,
    // just find the first mapping with an offset >= the requested offset.
    page = fomtierfs_find_page(&inode_info->page_maps, offset);
    if (!page) {
        return 0;
    }
    node = &page->node;

    while(page->page_offset < page_offset + num_pages) {
        next_node = rb_next(node);
        rb_erase(node, &inode_info->page_maps);

        // fomtierfs_return_page take the fomtierfs_dev_info.lock and fomtierfs_page.lock
        // which have higher priority than inode_info->map_lock, so we have to give it up
        write_unlock(&inode_info->map_lock);

        fomtierfs_return_page(sbi, page);

        if (!next_node)
            break;

        // take back the map_lock
        write_lock(&inode_info->map_lock);

        node = next_node;
        page = container_of(node, struct fomtierfs_page, node);
    }

    write_unlock(&inode_info->map_lock);

    return 0;
}

static pmd_t *fomtierfs_find_pmd(struct vm_area_struct *vma, u64 address)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;

    if (address >= vma->vm_end)
        return NULL;

    pgd = pgd_offset(vma->vm_mm, address);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return NULL;

    p4d = p4d_offset(pgd, address);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return NULL;

    pud = pud_offset(p4d, address);
    if (pud_none(*pud) || pud_bad(*pud))
        return NULL;

    pmd = pmd_offset(pud, address);

    return pmd;
}

// The locks for to_page and from_page should be taken.
// The inode_info->map_lock should be taken in write mode
static void migrate_page(struct fomtierfs_sb_info *sbi, struct fomtierfs_inode_info *inode_info,
        struct fomtierfs_page *to_page, struct fomtierfs_page *from_page,
        struct vm_area_struct *vma, unsigned long virt_addr, pmd_t *pmdp)
{
    struct fomtierfs_dev_info *to_dev, *from_dev;
    void *to_addr, *from_addr;
    bool writeable = false;
    int i;
    pmd_t pmd;
    pte_t *ptep;
    pte_t pte;
    u64 new_pfn;

    to_dev = &sbi->mem[to_page->type];
    from_dev = &sbi->mem[from_page->type];

    // Start by write protecting the page we're copying.
    // If the application faults on this page, we hold the inode write lock,
    // so the fault should stall in iomap_begin until we're done copying.
    if (pmd_huge(*pmdp)) {
        writeable = pmd_write(*pmdp);
        pmd = pmd_wrprotect(*pmdp);
        set_pmd_at(vma->vm_mm, virt_addr, pmdp, pmd);
    } else {
        for(i = 0; i < from_page->num_base_pages; i++) {
            ptep = pte_offset_kernel(pmdp, virt_addr + (i << PAGE_SHIFT));
            if (!ptep || !pte_present(*ptep))
                continue;

            writeable = writeable || pte_write(*ptep);
            pte = pte_wrprotect(*ptep);
            set_pte_at(vma->vm_mm, virt_addr, ptep, pte);
        }
    }
    flush_tlb_range(vma, virt_addr, virt_addr + sbi->page_size);

    // Copy the page
    to_addr = to_dev->virt_addr + (to_page->page_num << sbi->page_shift);
    from_addr = from_dev->virt_addr + (from_page->page_num << sbi->page_shift);
    for (i = 0; i < sbi->page_size / PAGE_SIZE; i++) {
        u64 off = i << PAGE_SHIFT;
        fomtierfs_nt_copy(to_addr + off, from_addr + off);
    }

    // Copy the metadata
    to_page->page_offset = from_page->page_offset;
    to_page->num_base_pages = from_page->num_base_pages;
    to_page->inode = from_page->inode;
    to_page->last_accessed = false;

    // Replace the olf page with the new page in the map tree
    fomtierfs_replace_page(&inode_info->page_maps, to_page);

    // The from page is about to be put in the free list, so clear it
    from_page->page_offset = 0;
    from_page->num_base_pages = 0;
    from_page->inode = NULL;

    // Update the page table to point to the new page
    if (pmd_huge(*pmdp)) {
        new_pfn = to_dev->pfn.val + (to_page->page_num << (HPAGE_SHIFT - PAGE_SHIFT));
        pmd = pfn_pmd(new_pfn, pmd_pgprot(*pmdp));
        pmd = pmd_mkold(pmd);
        if (writeable)
            pmd = pmd_mkwrite(pmd);
        set_pmd_at(vma->vm_mm, virt_addr, pmdp, pmd);
    } else {
        for (i = 0; i < to_page->num_base_pages; i++) {
            new_pfn = to_dev->pfn.val + (to_page->page_num << (sbi->page_shift - PAGE_SHIFT)) + i;
            ptep = pte_offset_kernel(pmdp, virt_addr + (i << PAGE_SHIFT));
            if (!ptep || !pte_present(*ptep))
                continue;

            pte = pfn_pte(new_pfn, pte_pgprot(*ptep));
            pte = pte_mkold(pte);
            if (writeable)
                pte = pte_mkwrite(pte);
            set_pte_at(vma->vm_mm, virt_addr + (i << PAGE_SHIFT), ptep, pte);
        }
    }
    flush_tlb_range(vma, virt_addr, virt_addr + sbi->page_size);
}

static bool fomtierfs_page_accessed(struct fomtierfs_page *page, u64 virt_addr, pmd_t *pmdp)
{
    int i;
    pte_t *ptep;

    if (pmd_huge(*pmdp)) {
        return pmd_young(*pmdp);
    } else {
        for (i = 0; i < page->num_base_pages; i++) {
            ptep = pte_offset_kernel(pmdp, virt_addr + (i << PAGE_SHIFT));
            if (!ptep || !pte_present(*ptep))
                continue;

            if (pte_young(*ptep))
                return true;
        }
    }

    return false;
}

static void fomtierfs_page_mkold(struct vm_area_struct *vma, struct fomtierfs_page *page,
        u64 virt_addr, pmd_t *pmdp)
{
    int i;
    pmd_t pmd;
    pte_t *ptep;
    pte_t pte;

    if (pmd_huge(*pmdp)) {
        pmd = pmd_mkold(*pmdp);
        set_pmd_at(vma->vm_mm, virt_addr, pmdp, pmd);
    } else {
        for (i = 0; i < page->num_base_pages; i++) {
            ptep = pte_offset_kernel(pmdp, virt_addr + (i << PAGE_SHIFT));
            if (!ptep || !pte_present(*ptep))
                continue;

            pte = pte_mkold(*ptep);
            set_pte_at(vma->vm_mm, virt_addr + (i << PAGE_SHIFT), ptep, pte);
        }
    }
}

static void fomtierfs_demote_one(struct fomtierfs_sb_info *sbi, struct fomtierfs_page **slow_page)
{
    struct fomtierfs_inode_info *inode_info;
    struct fomtierfs_dev_info *fast_dev = &sbi->mem[FAST_MEM];
    struct fomtierfs_dev_info *slow_dev = &sbi->mem[SLOW_MEM];
    struct fomtierfs_page *page;
    struct vm_area_struct *vma;
    struct address_space *as;
    bool accessed, last_accessed;
    u64 virt_addr;
    pmd_t *pmdp;

    // Grab the page at the end of the active list
    spin_lock(&fast_dev->lock);
    page = list_last_entry(&fast_dev->active_list, struct fomtierfs_page, list);
    list_del(&page->list);
    fast_dev->active_pages--;

    // Figure out if the page is old or not
    spin_lock(&page->lock);

    // Make sure the page is still mapped to a file
    if (!page->inode) {
        spin_unlock(&page->lock);
        spin_unlock(&fast_dev->lock);
        return;
    }

    as = page->inode->i_mapping;
    i_mmap_lock_read(as);

    vma = vma_interval_tree_iter_first(&as->i_mmap, page->page_offset, page->page_offset);
    if (!vma) {
        list_add(&page->list, &fast_dev->active_list);
        fast_dev->active_pages++;

        i_mmap_unlock_read(as);
        spin_unlock(&page->lock);
        spin_unlock(&fast_dev->lock);
        return;
    }
    virt_addr = vma->vm_start
        + ((page->page_offset << sbi->page_shift) - (vma->vm_pgoff << PAGE_SHIFT));
    pmdp = fomtierfs_find_pmd(vma, virt_addr);
    if (!pmdp || !pmd_present(*pmdp)) {
        list_add(&page->list, &fast_dev->active_list);
        fast_dev->active_pages++;

        i_mmap_unlock_read(as);
        spin_unlock(&page->lock);
        spin_unlock(&fast_dev->lock);
        return;
    }

    accessed = fomtierfs_page_accessed(page, virt_addr, pmdp);
    last_accessed = page->last_accessed;
    page->last_accessed = accessed;

    // Only demote if this page hasn't been accessed in either of
    // the last couple of checks
    if (accessed || last_accessed) {
        fomtierfs_page_mkold(vma, page, virt_addr, pmdp);

        // The page was accessed recently, so put it back and move
        // on to the next one.
        list_add(&page->list, &fast_dev->active_list);
        fast_dev->active_pages++;

        i_mmap_unlock_read(as);
        spin_unlock(&page->lock);
        spin_unlock(&fast_dev->lock);
        return;
    }

    i_mmap_unlock_read(as);
    spin_unlock(&page->lock);
    spin_unlock(&fast_dev->lock);

    spin_lock(&page->lock);
    // Make sure the page is still mapped to a file
    if (!page->inode) {
        spin_unlock(&page->lock);
        return;
    }

    spin_lock(&(*slow_page)->lock);

    inode_info = FTFS_I(page->inode);
    write_lock(&inode_info->map_lock);

    migrate_page(sbi, inode_info, *slow_page, page, vma, virt_addr, pmdp);

    write_unlock(&inode_info->map_lock);
    spin_unlock(&(*slow_page)->lock);
    spin_unlock(&page->lock);

    // Put the pages in the lists where they belong
    spin_lock(&fast_dev->lock);
    list_add(&page->list, &fast_dev->free_list);
    fast_dev->free_pages++;
    spin_unlock(&fast_dev->lock);

    spin_lock(&slow_dev->lock);
    list_add(&(*slow_page)->list, &slow_dev->active_list);
    slow_dev->active_pages++;
    spin_unlock(&slow_dev->lock);

    // Indicate that we need to find a new slow_page
    *slow_page = NULL;
}

static void fomtierfs_promote_one(struct fomtierfs_sb_info *sbi, struct fomtierfs_page **fast_page)
{
    struct fomtierfs_inode_info *inode_info;
    struct fomtierfs_dev_info *fast_dev = &sbi->mem[FAST_MEM];
    struct fomtierfs_dev_info *slow_dev = &sbi->mem[SLOW_MEM];
    struct fomtierfs_page *page;
    struct vm_area_struct *vma;
    struct address_space *as;
    bool accessed, last_accessed;
    u64 virt_addr;
    pmd_t *pmdp;

    // Grab the page at the end of the active list
    spin_lock(&slow_dev->lock);
    page = list_last_entry(&slow_dev->active_list, struct fomtierfs_page, list);
    list_del(&page->list);
    slow_dev->active_pages--;

    // Figure out if the page is old or not
    spin_lock(&page->lock);

    // Make sure the page is still mapped to a file
    if (!page->inode) {
        spin_unlock(&page->lock);
        spin_unlock(&slow_dev->lock);
        return;
    }

    as = page->inode->i_mapping;
    i_mmap_lock_read(as);

    vma = vma_interval_tree_iter_first(&as->i_mmap, page->page_offset, page->page_offset);
    if (!vma) {
        list_add(&page->list, &slow_dev->active_list);
        slow_dev->active_pages++;

        i_mmap_unlock_read(as);
        spin_unlock(&page->lock);
        spin_unlock(&slow_dev->lock);
        return;
    }
    virt_addr = vma->vm_start
        + ((page->page_offset << sbi->page_shift)- (vma->vm_pgoff << PAGE_SHIFT));
    pmdp = fomtierfs_find_pmd(vma, virt_addr);
    if (!pmdp || !pmd_present(*pmdp)) {
        list_add(&page->list, &slow_dev->active_list);
        slow_dev->active_pages++;

        i_mmap_unlock_read(as);
        spin_unlock(&page->lock);
        spin_unlock(&slow_dev->lock);
        return;
    }

    accessed = fomtierfs_page_accessed(page, virt_addr, pmdp);
    last_accessed = page->last_accessed;
    page->last_accessed = accessed;

    // Reset the accessed bit if we need to
    if (accessed)
        fomtierfs_page_mkold(vma, page, virt_addr, pmdp);

    // Only promote if the page has been accessed in both of the last
    // couple of checks.
    if (!accessed || !last_accessed) {
        list_add(&page->list, &slow_dev->active_list);
        slow_dev->active_pages++;

        i_mmap_unlock_read(as);
        spin_unlock(&page->lock);
        spin_unlock(&slow_dev->lock);
        return;
    }

    i_mmap_unlock_read(as);
    spin_unlock(&page->lock);
    spin_unlock(&slow_dev->lock);

    spin_lock(&(*fast_page)->lock);
    spin_lock(&page->lock);
    // Make sure the page is still mapped to a file
    if (!page->inode) {
        spin_unlock(&page->lock);
        spin_unlock(&(*fast_page)->lock);
        return;
    }

    inode_info = FTFS_I(page->inode);
    write_lock(&inode_info->map_lock);

    migrate_page(sbi, inode_info, *fast_page, page, vma, virt_addr, pmdp);

    write_unlock(&inode_info->map_lock);
    spin_unlock(&page->lock);
    spin_unlock(&(*fast_page)->lock);

    // Put the pages back where they belong
    spin_lock(&slow_dev->lock);
    list_add(&page->list, &slow_dev->free_list);
    slow_dev->free_pages++;
    spin_unlock(&slow_dev->lock);

    spin_lock(&fast_dev->lock);
    list_add(&(*fast_page)->list, &fast_dev->active_list);
    fast_dev->active_pages++;
    spin_unlock(&fast_dev->lock);

    // Indicate that we need to find a new fast_page
    *fast_page = NULL;
}

// Reader Beware: This function is a mess of locking and unlocking
static int fomtierfs_demote_task(void *data)
{
    // The maximum number of pages to migrate in one iteration
    const u64 MAX_MIGRATE = 1 << 20;
    struct fomtierfs_page *slow_page = NULL;
    struct fomtierfs_page *fast_page = NULL;
    struct fomtierfs_sb_info *sbi = data;
    struct fomtierfs_dev_info *fast_dev = &sbi->mem[FAST_MEM];
    struct fomtierfs_dev_info *slow_dev = &sbi->mem[SLOW_MEM];
    u64 pages_to_check;
    u64 i;

    while (!kthread_should_stop()) {
        /**
         * Demotion code
         */
        pages_to_check = min(fast_dev->active_pages, MAX_MIGRATE);

        for (i = 0; i < pages_to_check; i++) {
            // Don't migrate past the watermark.
            // I should *probably* take a lock here, but being off by a page
            // or two is no big deal.
            if (fast_dev->free_pages > sbi->demotion_watermark) {
                break;
            }

            // If we don't currently have a slow page to move to, get one
            if (!slow_page) {
                spin_lock(&slow_dev->lock);

                if (list_empty(&slow_dev->free_list)) {
                    spin_unlock(&slow_dev->lock);
                    break;
                }

                slow_page = list_first_entry(&slow_dev->free_list, struct fomtierfs_page, list);
                list_del(&slow_page->list);
                slow_dev->free_pages--;
                spin_unlock(&slow_dev->lock);
            }

            fomtierfs_demote_one(sbi, &slow_page);
        }

        // If we have a slow_page left over, put it back in the free list
        if (slow_page) {
            spin_lock(&slow_dev->lock);
            list_add(&slow_page->list, &slow_dev->free_list);
            slow_dev->free_pages++;
            spin_unlock(&slow_dev->lock);

            slow_page = NULL;
        }

        pages_to_check = min(slow_dev->active_pages, MAX_MIGRATE);

        for (i = 0; i < pages_to_check; i++) {
            // Don't migrate past the watermark.
            if (fast_dev->free_pages <= sbi->alloc_watermark) {
                break;
            }

            // If we don't have a fast page to move to, get one
            if (!fast_page) {
                spin_lock(&fast_dev->lock);

                if (list_empty(&fast_dev->free_list)) {
                    spin_unlock(&fast_dev->lock);
                    break;
                }

                fast_page = list_first_entry(&fast_dev->free_list, struct fomtierfs_page, list);
                list_del(&fast_page->list);
                fast_dev->free_pages--;
                spin_unlock(&fast_dev->lock);
            }

            fomtierfs_promote_one(sbi, &fast_page);
        }

        // If we have a fast_page left over, put it back in the free list
        if (fast_page) {
            spin_lock(&fast_dev->lock);
            list_add(&fast_page->list, &fast_dev->free_list);
            fast_dev->free_pages++;
            spin_unlock(&fast_dev->lock);

            fast_page = NULL;
        }

        msleep_interruptible(5000);
    }
    return 0;
}

static int fomtierfs_iomap_begin(struct inode *inode, loff_t offset, loff_t length,
                unsigned flags, struct iomap *iomap, struct iomap *srcmap)
{
    struct fomtierfs_sb_info *sbi = FTFS_SB(inode->i_sb);
    struct fomtierfs_inode_info *inode_info = FTFS_I(inode);
    struct fomtierfs_page *page;
    u64 page_offset;
    u64 page_shift;
    u64 base_page_offset;

    // If we are in huge page mode, and there is a base page fault,
    // we will need to find which base page in the huge page we should map
    if (sbi->page_size == HPAGE_SIZE) {
        base_page_offset = offset & (HPAGE_SIZE-1);
    } else {
        base_page_offset = 0;
    }

    page_shift = sbi->page_shift;
    // Calculate the "page" the offset belongs to
    page_offset = offset >> page_shift;

    iomap->flags = 0;
    iomap->offset = offset;
    iomap->length = length;

    read_lock(&inode_info->map_lock);
    page = fomtierfs_find_page(&inode_info->page_maps, page_offset);

    if (!page) {
        read_unlock(&inode_info->map_lock);

        page = fomtierfs_alloc_page(inode, sbi, page_offset);
        if (!page) {
            return -ENOMEM;
        }

        // Save this new mapping
        write_lock(&inode_info->map_lock);
        if (!fomtierfs_insert_page(&inode_info->page_maps, page)) {
            BUG();
        }

        iomap->flags |= IOMAP_F_NEW;
        iomap->type = IOMAP_MAPPED;
        iomap->addr = (page->page_num << page_shift) + base_page_offset;
        iomap->bdev = sbi->mem[page->type].bdev;
        iomap->dax_dev = sbi->mem[page->type].daxdev;
        write_unlock(&inode_info->map_lock);
    } else {
        // There is already a page allocated for this offset, so just use that
        iomap->type = IOMAP_MAPPED;
        iomap->addr = (page->page_num << page_shift) + base_page_offset;
        iomap->bdev = sbi->mem[page->type].bdev;
        iomap->dax_dev = sbi->mem[page->type].daxdev;

        read_unlock(&inode_info->map_lock);
    }
    page->num_base_pages = max(page->num_base_pages, (u16)((base_page_offset >> PAGE_SHIFT) + 1));

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

static vm_fault_t fomtierfs_huge_fault(struct vm_fault *vmf, enum page_entry_size pe_size)
{
    vm_fault_t result = 0;
    pfn_t pfn;
    int error;

    result = dax_iomap_fault(vmf, pe_size, &pfn, &error, &fomtierfs_iomap_ops);

    return result;
}

static vm_fault_t fomtierfs_fault(struct vm_fault *vmf)
{
    return fomtierfs_huge_fault(vmf, PE_SIZE_PTE);
}

static struct vm_operations_struct fomtierfs_vm_ops = {
    .fault = fomtierfs_fault,
    .huge_fault = fomtierfs_huge_fault,
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
    return thp_get_unmapped_area(file, addr, len, pgoff, flags);
}

static long fomtierfs_fallocate(struct file *file, int mode, loff_t offset, loff_t len)
{
    struct inode *inode = file_inode(file);
    struct fomtierfs_sb_info *sbi = FTFS_SB(inode->i_sb);
    struct fomtierfs_inode_info *inode_info = FTFS_I(inode);
    struct fomtierfs_page *page;
    loff_t off;

    if (mode & FALLOC_FL_PUNCH_HOLE) {
        return fomtierfs_free_range(inode, offset, len);
    } else if (mode != 0) {
        return -EOPNOTSUPP;
    }

    // Allocate and add mappings for the desired range
    for (off = offset; off < offset + len; off += sbi->page_size) {
        page = fomtierfs_alloc_page(inode, sbi, off >> sbi->page_shift);
        if (!page) {
            return -ENOMEM;
        }

        // We normally need to grab inode_info->map_lock, but
        // since this page is being fallocated, it isn't shared yet.
        if (!fomtierfs_insert_page(&inode_info->page_maps, page)) {
            BUG();
        }
    }

    return 0;
}

const struct file_operations fomtierfs_file_operations = {
    .mmap		= fomtierfs_mmap,
    .mmap_supported_flags = MAP_SYNC,
    .fsync		= noop_fsync,
    .splice_read	= generic_file_splice_read,
    .splice_write	= iter_file_splice_write,
    .llseek		= generic_file_llseek,
    .get_unmapped_area	= fomtierfs_mmu_get_unmapped_area,
    .fallocate = fomtierfs_fallocate,
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
    rwlock_init(&info->map_lock);

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
    buf->f_bsize = sbi->page_size;
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
    struct fomtierfs_page *page;

    // Free each mapping in the inode, and place each page back into the free list
    write_lock(&inode_info->map_lock);
    while (node) {
        page = container_of(node, struct fomtierfs_page, node);

        rb_erase(node, &inode_info->page_maps);

        // fomtierfs_return_page take the fomtierfs_dev_info.lock and fomtierfs_page.lock
        // which have higher priority than inode_info->map_lock, so we have to give it up
        write_unlock(&inode_info->map_lock);

        fomtierfs_return_page(sbi, page);

        write_lock(&inode_info->map_lock);

        node = inode_info->page_maps.rb_node;
    }
    write_unlock(&inode_info->map_lock);

    kfree(inode_info);

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
    Opt_slowmem, Opt_source, Opt_basepage,
};

const struct fs_parameter_spec fomtierfs_fs_parameters[] = {
    fsparam_string("slowmem", Opt_slowmem),
    fsparam_string("source", Opt_source),
    fsparam_bool("basepage", Opt_basepage),
    {},
};

static int fomtierfs_parse_param(struct fs_context *fc, struct fs_parameter *param)
{
    struct fs_parse_result result;
    struct fomtierfs_context_info *fc_info = (struct fomtierfs_context_info*)fc->fs_private;
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
        fc_info->slow_dev_name = kstrdup(param->string, GFP_KERNEL);
        break;
    case Opt_source:
        fc->source = kstrdup(param->string, GFP_KERNEL);
        break;
    case Opt_basepage:
        fc_info->base_pages = result.boolean;
        break;
    default:
        pr_err("FOMTierFS: unrecognized option %s", param->key);
        break;
    }

    return 0;
}

static int fomtierfs_populate_dev_info(struct fomtierfs_sb_info *sbi, struct block_device *bdev, enum fomtierfs_mem_type type)
{
    int ret = 0;
    long i;
    long num_base_pages;
    struct fomtierfs_dev_info *di = &sbi->mem[type];
    struct fomtierfs_page *cursor, *temp;
    // dax_direct_access returns the number of base pages.
    // We want to work with pages of the size sbi->page_size, so calcualate
    // this ratio to convert between them.
    unsigned long page_size_ratio = sbi->page_size / PAGE_SIZE;

    di->bdev = bdev;
    di->daxdev = fs_dax_get_by_bdev(bdev);

    // Determine how many pages are in the device
    num_base_pages = dax_direct_access(di->daxdev, 0, LONG_MAX / PAGE_SIZE,
                    &di->virt_addr, &di->pfn);
    if (num_base_pages <= 0) {
        pr_err("FOMTierFS: Determining device size failed");
        return -EIO;
    }

    di->num_pages = num_base_pages / page_size_ratio;
    di->free_pages = num_base_pages / page_size_ratio;
    di->active_pages = 0;

    INIT_LIST_HEAD(&di->free_list);
    INIT_LIST_HEAD(&di->active_list);

    // Put all of the pages into the free list
    for (i = 0; i < di->num_pages; i++) {
        struct fomtierfs_page *page = kzalloc(sizeof(struct fomtierfs_page), GFP_KERNEL);
        if (!page) {
            ret = -ENOMEM;
            goto err;
        }

        page->page_num = i;
        page->type = type;
        page->inode = NULL;
        spin_lock_init(&page->lock);
        list_add(&page->list, &di->free_list);
    }

    spin_lock_init(&di->lock);

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
    struct fomtierfs_context_info *fc_info = (struct fomtierfs_context_info*)fc->fs_private;
    int ret;

    if (fc_info->base_pages) {
        sbi->page_size = PAGE_SIZE;
        sbi->page_shift = PAGE_SHIFT;
    } else {
        sbi->page_size = HPAGE_SIZE;
        sbi->page_shift = HPAGE_SHIFT;
    }

    sb->s_fs_info = sbi;
    sb->s_maxbytes = MAX_LFS_FILESIZE;
    sb->s_magic = 0xDEADBEEF;
    sb->s_op = &fomtierfs_ops;
    sb->s_time_gran = 1;
    // The blocksize cannot be larger than PAGE_SIZE
    if(!sb_set_blocksize(sb, PAGE_SIZE)) {
        pr_err("FOMTierFS: error setting blocksize");
    }

    // Populate the device information for the fast and slow mem
    ret = fomtierfs_populate_dev_info(sbi, sb->s_bdev, FAST_MEM);
    if (ret != 0) {
        pr_err("FOMTierFS: Error populating fast mem device information");
        kfree(sbi);
        return ret;
    }

    slow_dev = blkdev_get_by_path(fc_info->slow_dev_name, FMODE_READ|FMODE_WRITE|FMODE_EXCL, sbi);
    if (IS_ERR(slow_dev)) {
        ret = PTR_ERR(slow_dev);
        pr_err("FOMTierFS: Error opening slow mem device %s %d", fc_info->slow_dev_name, ret);
        kfree(sbi);
        return ret;
    }
    ret = fomtierfs_populate_dev_info(sbi, slow_dev, SLOW_MEM);
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

    // Start the page migration thread
    sbi->demote_task = kthread_create(fomtierfs_demote_task, sbi, "FTFS Demote Thread");
    if (!sbi->demote_task) {
        pr_err("FOMTierFS: Failed to create the migration task");
        kfree(sbi);
        return -ENOMEM;
    }

    wake_up_process(sbi->demote_task);

    // Make the demotion watermark 2% of the total mem
    sbi->demotion_watermark = sbi->mem[FAST_MEM].num_pages * 2 / 100;
    // Make the alloc watermark 1% of the total mem
    sbi->alloc_watermark = sbi->mem[FAST_MEM].num_pages / 100;
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
    struct fomtierfs_context_info *fc_info = (struct fomtierfs_context_info*)fc->fs_private;
    kfree(fc_info->slow_dev_name);
    kfree(fc_info);
}

static const struct fs_context_operations fomtierfs_context_ops = {
	.free		= fomtierfs_free_fc,
	.parse_param	= fomtierfs_parse_param,
	.get_tree	= fomtierfs_get_tree,
};

int fomtierfs_init_fs_context(struct fs_context *fc)
{
    fc->ops = &fomtierfs_context_ops;
    // Zeroing sets fc_info->base_pages to false by default
    fc->fs_private = kzalloc(sizeof(struct fomtierfs_context_info), GFP_KERNEL);
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
            "slow total: %lld\tfree: %lld\n"
            "Demotion Watermark: %llu Alloc Watermark: %llu\n",
            sysfs_sb_info->mem[FAST_MEM].num_pages,
            sysfs_sb_info->mem[FAST_MEM].free_pages,
            sysfs_sb_info->mem[SLOW_MEM].num_pages,
            sysfs_sb_info->mem[SLOW_MEM].free_pages,
            sysfs_sb_info->demotion_watermark,
            sysfs_sb_info->alloc_watermark
        );
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

static ssize_t active_list_show(struct kobject *kobj,
        struct kobj_attribute *attr, char *buf)
{
    ssize_t count = 0;
    struct fomtierfs_dev_info *fast_dev;
    struct fomtierfs_dev_info *slow_dev;
    struct fomtierfs_page *page;

    if (!sysfs_sb_info) {
        return sprintf(buf, "Not mounted");
    }

    fast_dev = &sysfs_sb_info->mem[FAST_MEM];
    slow_dev = &sysfs_sb_info->mem[SLOW_MEM];

    count += sprintf(buf, "fast:\n");

    spin_lock(&fast_dev->lock);
    list_for_each_entry(page, &fast_dev->active_list, list) {
        count += sprintf(&buf[count], "(%lu, %llx) ", page->inode->i_ino, page->page_offset);
    }
    spin_unlock(&fast_dev->lock);

    count += sprintf(&buf[count], "\nslow:\n");

    spin_lock(&slow_dev->lock);
    list_for_each_entry(page, &slow_dev->active_list, list) {
        count += sprintf(&buf[count], "(%lu, %llx) ", page->inode->i_ino, page->page_offset);
    }
    spin_unlock(&slow_dev->lock);

    count += sprintf(&buf[count], "\n");

    return count;
}

static ssize_t active_list_store(struct kobject *kobj,
        struct kobj_attribute *attr,
        const char *buf, size_t count)
{
    return -EINVAL;
}
static struct kobj_attribute active_list_attr =
__ATTR(active_list, 0444, active_list_show, active_list_store);

static ssize_t demotion_watermark_show(struct kobject *kobj,
        struct kobj_attribute *attr, char *buf)
{
    if (!sysfs_sb_info) {
        return sprintf(buf, "Not mounted");
    }

    return sprintf(buf, "%lld\n", sysfs_sb_info->demotion_watermark);
}

static ssize_t demotion_watermark_store(struct kobject *kobj,
        struct kobj_attribute *attr,
        const char *buf, size_t count)
{
    int ret;
    if (!sysfs_sb_info) {
        return -EINVAL;
    }

    ret =  kstrtoull(buf, 10, &sysfs_sb_info->demotion_watermark);
    if (ret)
        return ret;

    return count;
}
static struct kobj_attribute demotion_watermark_attr =
__ATTR(demotion_watermark, 0644, demotion_watermark_show, demotion_watermark_store);

static struct attribute *fomtierfs_attr[] = {
    &usage_attr.attr,
    &active_list_attr.attr,
    &demotion_watermark_attr.attr,
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
