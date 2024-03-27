#include <linux/types.h>
#include <linux/file_based_mm.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/swap.h>
#include <linux/swapops.h>
#include <linux/rmap.h>
#include <linux/blkdev.h>
#include <linux/frontswap.h>
#include <linux/mmu_notifier.h>
#include <linux/swap_slots.h>

#include "internal.h"
#include "swap.h"

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
	mmu_notifier_range_init(&range, MMU_NOTIFY_CLEAR, 0, vma, vma->vm_mm,
							address, range.end);
	mmu_notifier_invalidate_range_start(&range);

	while (page_vma_mapped_walk(&pvmw)) {
		// Unexpected PMD-mapped thing
		VM_BUG_ON_FOLIO(!pvmw.pte, folio);

		page = folio_page(folio, pte_pfn(*pvmw.pte) - folio_pfn(folio));
		address = pvmw.address;

		// Nuke the page table entry
		pteval = ptep_clear_flush(vma, address, pvmw.pte);

		if (pte_dirty(pteval))
			folio_mark_dirty(folio);

		entry.val = page_private(page);

		// Increase the ref count on entry
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
		BUG_ON(pte_present(swp_pte));
		// invalidate as we cleared the pte
		mmu_notifier_invalidate_range(mm, address, address + PAGE_SIZE);

		page_remove_rmap(page, vma, false);
		folio_put(folio);
	}

	mmu_notifier_invalidate_range_end(&range);

	return ret;
}

static int folio_not_mapped(struct folio *folio) {
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

bool fbmm_swapout_folio(struct folio *folio) {
	struct address_space *mapping;
    struct swap_info_struct *si;
	unsigned long offset;
	struct swap_iocb *plug = NULL;
	swp_entry_t entry;

	if (!folio_trylock(folio))
		return false;

	// Allocate swap space
	entry = folio_alloc_swap(folio);
	if (!entry.val)
		goto unlock;

	offset = swp_offset(entry);
	si = get_swap_device(entry);

	// Associate the folio with the swap entry
	set_page_private(folio_page(folio, 0), entry.val);

	folio_mark_dirty(folio);

	if (folio_ref_count(folio) != 3) {
		pr_err("folio ref should be 3, is %d\n", folio_ref_count(folio));
		BUG();
	}

	// We need to unmap this folio from every process it's mapped to
	if (folio_mapped(folio)) {
		fbmm_try_to_unmap(folio);
		if (folio_mapped(folio)) {
            pr_err("folio still mapped\n");
			goto unlock;
		}
	}

	if (folio_ref_count(folio) != 2) {
		pr_err("folio ref should be 2, is %d\n", folio_ref_count(folio));
		BUG();
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
				// pageout eventually unlocks the folio for some reason on success...
				if (!folio_trylock(folio)) {
					pr_err("failed lock\n");
					return false;
				}
				fallthrough;
			case PAGE_CLEAN:
				;
		}
	}

	if (!remove_mapping(mapping, folio)) {
		pr_err("error removing mapping %d %ld\n", folio_ref_count(folio), (long int)folio_get_private(folio));
	} else if (folio_ref_count(folio) != 1) {
		pr_err("folio ref should be 1, is %d\n", folio_ref_count(folio));
	}
	folio_unlock(folio);

	si = get_swap_device(entry);
	si->swap_map[offset] &= ~SWAP_HAS_CACHE;

	return true;

unlock:
    pr_err("unlock\n");
	folio_unlock(folio);
	return false;
}
EXPORT_SYMBOL(fbmm_swapout_folio);

void fbmm_end_swap_bio_write(struct bio *bio) {

	struct page *page = bio_first_page_all(bio);
	struct folio *folio = page_folio(page);
	int ret;

	// This is the simplification of __folio_end_writeback
	ret = folio_test_clear_writeback(folio);
	if (!ret) {
		pr_err("Writtenback page didn't have writeback flag?\n");
		BUG();
	}
	if (folio_ref_count(folio) != 2) {
		pr_err("end_swap folio count %d %ld\n", folio_ref_count(folio), (long int)folio_get_private(folio));
	}

	sb_clear_inode_writeback(folio_mapping(folio)->host);

	// Simplification of folio_end_writeback
	smp_mb__after_atomic();
	acct_reclaim_writeback(folio);
}

// Analogue to __swap_writepage
static int __fbmm_writepage(struct page *page, struct writeback_control *wbc)
{
	struct bio bio;
	struct bio_vec bv;
	int ret;
	struct swap_info_struct *sis = page_swap_info(page);

	ret = bdev_write_page(sis->bdev, swap_page_sector(page), page, wbc);
	if (!ret) {
		// bdev_write_page unlocks the page on success
		count_vm_events(PSWPOUT, thp_nr_pages(page));
		return 0;
	}

	// This seems to be a backup if bdev_write_page doesn't work?
	bio_init(&bio, sis->bdev, &bv, 1,
			REQ_OP_WRITE | REQ_SWAP | wbc_to_write_flags(wbc));
	bio.bi_iter.bi_sector = swap_page_sector(page);
	bio_add_page(&bio, page, thp_size(page), 0);

	count_vm_events(PSWPOUT, thp_nr_pages(page));
	set_page_writeback(page);
	unlock_page(page);

	submit_bio_wait(&bio);
	fbmm_end_swap_bio_write(&bio);

	return 0;
}

int fbmm_writepage(struct page *page, struct writeback_control *wbc)
{
	struct folio *folio = page_folio(page);
	int ret = 0;

	ret = arch_prepare_to_swap(&folio->page);
	if (ret) {
		folio_mark_dirty(folio);
		folio_unlock(folio);
		return 0;
	}

	if (frontswap_store(&folio->page) == 0) {
		folio_start_writeback(folio);
		folio_unlock(folio);
		folio_end_writeback(folio);
		return 0;
	}

	return __fbmm_writepage(page, wbc);
}
EXPORT_SYMBOL(fbmm_writepage);

struct page *fbmm_read_swap_entry(struct vm_fault *vmf, swp_entry_t entry, unsigned long pgoff, struct page *page)
{
	struct vm_area_struct *vma = vmf->vma;
	struct address_space *mapping = vma->vm_file->f_mapping;
	struct swap_info_struct *si;
	struct folio *folio;

	if (unlikely(non_swap_entry(entry))) {
		return NULL;
	}

	// If a folio is already mapped here, just return that.
	// Another process has probably already brought in the shared page
	folio = filemap_get_folio(mapping, pgoff);
	if (IS_ERR(folio)) {
		return folio_page(folio, 0);
	}

	si = get_swap_device(entry);
	if (!si) {
		return NULL;
	}

	folio = page_folio(page);

	folio_set_swap_entry(folio, entry);
	swap_readpage(page, true, NULL);
	folio->private = NULL;

	swap_free(entry);

	count_vm_events(PSWPIN, thp_nr_pages(page));
	dec_mm_counter(vma->vm_mm, MM_SWAPENTS);
	return folio_page(folio, 0);
}
EXPORT_SYMBOL(fbmm_read_swap_entry);
