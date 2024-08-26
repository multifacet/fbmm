// SPDX-License-Identifier: GPL-2.0-only
#include <linux/types.h>
#include <linux/file_based_mm.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/rmap.h>
#include <linux/blkdev.h>
#include <linux/mmu_notifier.h>
#include <linux/swap_slots.h>
#include <linux/pagewalk.h>
#include <linux/zswap.h>

#include <asm/tlbflush.h>

#include "internal.h"
#include "swap.h"

/******************************************************************************
 * Swap Helpers
 *****************************************************************************/
static bool fbmm_try_to_unmap_one(struct folio *folio, struct vm_area_struct *vma,
				unsigned long address, void *arg)
{
	struct mm_struct *mm = vma->vm_mm;
	DEFINE_FOLIO_VMA_WALK(pvmw, folio, vma, address, 0);
	pte_t pteval, swp_pte;
	swp_entry_t entry;
	struct page *page;
	bool ret = true;
	struct mmu_notifier_range range;

	range.end = vma_address_end(&pvmw);
	mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma->vm_mm,
							address, range.end);
	mmu_notifier_invalidate_range_start(&range);

	while (page_vma_mapped_walk(&pvmw)) {
		page = folio_page(folio, pte_pfn(*pvmw.pte) - folio_pfn(folio));
		address = pvmw.address;

		pteval = ptep_clear_flush(vma, address, pvmw.pte);

		if (pte_dirty(pteval))
			folio_mark_dirty(folio);

		entry.val = page_private(page);

		if (swap_duplicate(entry) < 0) {
			set_pte_at(mm, address, pvmw.pte, pteval);
			ret = false;
			page_vma_mapped_walk_done(&pvmw);
			break;
		}

		dec_mm_counter(mm, MM_FILEPAGES);
		inc_mm_counter(mm, MM_SWAPENTS);
		swp_pte = swp_entry_to_pte(entry);
		if (pte_soft_dirty(pteval))
			swp_pte = pte_swp_mksoft_dirty(swp_pte);

		set_pte_at(mm, address, pvmw.pte, swp_pte);

		folio_remove_rmap_pte(folio, page, vma);
		folio_put(folio);
	}

	mmu_notifier_invalidate_range_end(&range);

	return ret;
}

static int folio_not_mapped(struct folio *folio)
{
	return !folio_mapped(folio);
}

static void fbmm_try_to_unmap(struct folio *folio)
{
	struct rmap_walk_control rwc = {
		.rmap_one = fbmm_try_to_unmap_one,
		.arg = NULL,
		.done = folio_not_mapped,
	};

	rmap_walk(folio, &rwc);
}

/*
 * fbmm_swapout_folio - Helper function for MFSs to swapout a folio
 * @folio: The folio to swap out. Must has a reference count of at least 3.
 * One the thread is holding on to, one for the file mapping, and one for each
 * page table entry it is mapped to
 *
 * Returns 0 on success and nonzero otherwise
 */
int fbmm_swapout_folio(struct folio *folio)
{
	struct address_space *mapping;
	struct swap_info_struct *si;
	unsigned long offset;
	struct swap_iocb *plug = NULL;
	swp_entry_t entry;

	if (!folio_trylock(folio))
		return 1;

	entry = folio_alloc_swap(folio);
	if (!entry.val)
		goto unlock;

	offset = swp_offset(entry);

	folio->swap = entry;

	folio_mark_dirty(folio);

	if (folio_ref_count(folio) < 3)
		goto unlock;

	if (folio_mapped(folio)) {
		fbmm_try_to_unmap(folio);
		if (folio_mapped(folio))
			goto unlock;
	}

	mapping = folio_mapping(folio);
	if (folio_test_dirty(folio)) {
		try_to_unmap_flush_dirty();
		switch (pageout(folio, mapping, &plug)) {
		case PAGE_KEEP:
			fallthrough;
		case PAGE_ACTIVATE:
			goto unlock;
		case PAGE_SUCCESS:
			/* pageout eventually unlocks the folio on success, so lock it */
			if (!folio_trylock(folio))
				return 1;
			fallthrough;
		case PAGE_CLEAN:
			;
		}
	}

	remove_mapping(mapping, folio);
	folio_unlock(folio);

	si = get_swap_device(entry);
	si->swap_map[offset] &= ~SWAP_HAS_CACHE;
	put_swap_device(si);

	return 0;

unlock:
	folio_unlock(folio);
	return 1;
}
EXPORT_SYMBOL(fbmm_swapout_folio);

static void fbmm_end_swap_bio_write(struct bio *bio)
{
	struct folio *folio = bio_first_folio_all(bio);
	int ret;

	/* This is the simplification of __folio_end_writeback */
	ret = folio_test_clear_writeback(folio);
	if (!ret)
		return;

	sb_clear_inode_writeback(folio_mapping(folio)->host);

	/* Simplification of folio_end_writeback */
	smp_mb__after_atomic();
	acct_reclaim_writeback(folio);
}

/* Analogue to __swap_writepage */
static void __fbmm_writepage(struct folio *folio, struct writeback_control *wbc)
{
	struct bio bio;
	struct bio_vec bv;
	struct swap_info_struct *sis = swp_swap_info(folio->swap);

	bio_init(&bio, sis->bdev, &bv, 1,
			REQ_OP_WRITE | REQ_SWAP | wbc_to_write_flags(wbc));
	bio.bi_iter.bi_sector = swap_folio_sector(folio);
	bio_add_folio_nofail(&bio, folio, folio_size(folio), 0);

	count_vm_events(PSWPOUT, folio_nr_pages(folio));
	folio_start_writeback(folio);
	folio_unlock(folio);

	submit_bio_wait(&bio);
	fbmm_end_swap_bio_write(&bio);
}

int fbmm_writepage(struct page *page, struct writeback_control *wbc)
{
	struct folio *folio = page_folio(page);
	int ret = 0;

	ret = arch_prepare_to_swap(folio);
	if (ret) {
		folio_mark_dirty(folio);
		folio_unlock(folio);
		return 0;
	}

	__fbmm_writepage(folio, wbc);
	return 0;
}
EXPORT_SYMBOL(fbmm_writepage);

struct page *fbmm_read_swap_entry(struct vm_fault *vmf, swp_entry_t entry, unsigned long pgoff,
		struct page *page)
{
	struct vm_area_struct *vma = vmf->vma;
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct swap_info_struct *si;
	struct folio *folio;

	if (unlikely(non_swap_entry(entry)))
		return NULL;

	/*
	 * If a folio is already mapped here, just return that.
	 * Another process has probably already brought in the shared page
	 */
	folio = filemap_get_folio(mapping, pgoff);
	if (!IS_ERR(folio))
		return folio_page(folio, 0);

	si = get_swap_device(entry);
	if (!si)
		return NULL;

	folio = page_folio(page);

	folio_lock(folio);
	folio->swap = entry;
	/* swap_read_folio unlocks the folio */
	swap_read_folio(folio, true, NULL);
	folio->private = NULL;

	swap_free(entry);

	put_swap_device(si);
	count_vm_events(PSWPIN, folio_nr_pages(folio));
	dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
	return folio_page(folio, 0);
}
EXPORT_SYMBOL(fbmm_read_swap_entry);

/******************************************************************************
 * Copy on write helpers
 *****************************************************************************/
struct page_walk_levels {
	struct vm_area_struct *vma;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;
};

static int fbmm_copy_pgd(pgd_t *pgd, unsigned long addr, unsigned long next, struct mm_walk *walk)
{
	struct page_walk_levels *dst_levels = walk->private;

	dst_levels->pgd = pgd_offset(dst_levels->vma->vm_mm, addr);
	return 0;
}

static int fbmm_copy_p4d(p4d_t *p4d, unsigned long addr, unsigned long next, struct mm_walk *walk)
{
	struct page_walk_levels *dst_levels = walk->private;

	dst_levels->p4d = p4d_alloc(dst_levels->vma->vm_mm, dst_levels->pgd, addr);
	if (!dst_levels->p4d)
		return -ENOMEM;
	return 0;
}

static int fbmm_copy_pud(pud_t *pud, unsigned long addr, unsigned long next, struct mm_walk *walk)
{
	struct page_walk_levels *dst_levels = walk->private;

	dst_levels->pud = pud_alloc(dst_levels->vma->vm_mm, dst_levels->p4d, addr);
	if (!dst_levels->pud)
		return -ENOMEM;
	return 0;
}

static int fbmm_copy_pmd(pmd_t *pmd, unsigned long addr, unsigned long next, struct mm_walk *walk)
{
	struct page_walk_levels *dst_levels = walk->private;

	dst_levels->pmd = pmd_alloc(dst_levels->vma->vm_mm, dst_levels->pud, addr);
	if (!dst_levels->pmd)
		return -ENOMEM;
	return 0;
}

static int fbmm_copy_pte(pte_t *pte, unsigned long addr, unsigned long next, struct mm_walk *walk)
{
	struct page_walk_levels *dst_levels = walk->private;
	struct mm_struct *dst_mm = dst_levels->vma->vm_mm;
	struct mm_struct *src_mm = walk->mm;
	pte_t *src_pte = pte;
	pte_t *dst_pte;
	spinlock_t *dst_ptl;
	pte_t entry;
	struct page *page;
	struct folio *folio;
	int ret = 0;

	dst_pte = pte_alloc_map(dst_mm, dst_levels->pmd, addr);
	if (!dst_pte)
		return -ENOMEM;
	dst_ptl = pte_lockptr(dst_mm, dst_levels->pmd);
	/* The spinlock for the src pte should already be taken */
	spin_lock_nested(dst_ptl, SINGLE_DEPTH_NESTING);

	if (pte_none(*src_pte))
		goto unlock;

	/* I don't really want to handle to swap case, so I won't for now */
	if (unlikely(!pte_present(*src_pte))) {
		ret = -EIO;
		goto unlock;
	}

	entry = ptep_get(src_pte);
	page = vm_normal_page(walk->vma, addr, entry);
	if (page)
		folio = page_folio(page);

	folio_get(folio);
	folio_dup_file_rmap_pte(folio, page);
	percpu_counter_inc(&dst_mm->rss_stat[MM_FILEPAGES]);

	if (!(walk->vma->vm_flags & VM_SHARED) && pte_write(entry)) {
		ptep_set_wrprotect(src_mm, addr, src_pte);
		entry = pte_wrprotect(entry);
	}

	entry = pte_mkold(entry);
	set_pte_at(dst_mm, addr, dst_pte, entry);

unlock:
	pte_unmap_unlock(dst_pte, dst_ptl);
	return ret;
}

int fbmm_copy_page_range(struct vm_area_struct *dst, struct vm_area_struct *src)
{
	struct page_walk_levels dst_levels;
	struct mm_walk_ops walk_ops = {
		.pgd_entry = fbmm_copy_pgd,
		.p4d_entry = fbmm_copy_p4d,
		.pud_entry = fbmm_copy_pud,
		.pmd_entry = fbmm_copy_pmd,
		.pte_entry = fbmm_copy_pte,
	};

	dst_levels.vma = dst;

	return walk_page_range(src->vm_mm, src->vm_start, src->vm_end,
		&walk_ops, &dst_levels);
}
EXPORT_SYMBOL(fbmm_copy_page_range);
