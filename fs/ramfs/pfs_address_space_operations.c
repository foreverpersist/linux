#include "linux/pagemap.h"
#ifdef CONFIG_SYSCALL_ISOLATION

#include "linux/compiler.h"
#include "linux/uaccess.h"
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/backing-dev.h>
#include <linux/hash.h>
#include <linux/swap.h>
#include <linux/security.h>
#include <linux/cdev.h>
#include <linux/memblock.h>
#include <linux/fsnotify.h>
#include <linux/mount.h>
#include <linux/posix_acl.h>
#include <linux/prefetch.h>
#include <linux/buffer_head.h> /* for inode_has_buffers */
#include <linux/ratelimit.h>
#include <linux/list_lru.h>
#include <linux/iversion.h>
#include <trace/events/writeback.h>
#include "internal.h"

extern unsigned long private_vmalloc(unsigned long);
extern void private_vfree(void *);
extern struct page *fetch_private_vmalloc_page(unsigned long addr);

static struct page *pfs_pagecache_get_page(struct address_space *mapping,
					   pgoff_t offset, int fgp_flags,
					   gfp_t gfp_mask)
{
	struct page *page;
	unsigned long pv_addr;
	int err;

repeat:
	page = find_get_entry(mapping, offset);
	if (xa_is_value(page))
		page = NULL;
	if (!page)
		goto no_page;

	lock_page(page);

	if (unlikely(compound_head(page)->mapping != mapping)) {
		unlock_page(page);
		put_page(page);
		goto repeat;
	}
	VM_BUG_ON_PAGE(page->index != offset, page);

no_page:
  if(page)
    return page;

	if (mapping_cap_account_dirty(mapping))
		gfp_mask |= __GFP_WRITE;

	if (fgp_flags & FGP_NOFS)
		gfp_mask &= ~__GFP_FS;

	pv_addr = private_vmalloc(PAGE_SIZE);
	if (!pv_addr)
		return NULL;
	page = fetch_private_vmalloc_page(pv_addr);

	err = add_to_page_cache_lru(page, mapping, offset, gfp_mask);
	if (unlikely(err)) {
		private_vfree((void *)pv_addr);
		page = NULL;
		if (err == -EEXIST)
			goto repeat;
	}

	return page;
}

static struct page *
pfs_grab_cache_page_write_begin(struct address_space *mapping, pgoff_t index,
				unsigned flags)
{
	struct page *page;
	int fgp_flags = FGP_LOCK | FGP_WRITE | FGP_CREAT;

	if (flags & AOP_FLAG_NOFS)
		fgp_flags |= FGP_NOFS;

	page = pfs_pagecache_get_page(mapping, index, fgp_flags,
				      mapping_gfp_mask(mapping));
	if (page)
		wait_for_stable_page(page);

	return page;
}

int pfs_write_begin(struct file *file, struct address_space *mapping,
		    loff_t pos, unsigned len, unsigned flags,
		    struct page **pagep, void **fsdata)
{
	struct page *page;
	pgoff_t index;

	index = pos >> PAGE_SHIFT;

	page = pfs_grab_cache_page_write_begin(mapping, index, flags);
	if (!page)
		return -ENOMEM;

	*pagep = page;

	if (!PageUptodate(page) && (len != PAGE_SIZE)) {
		unsigned from = pos & (PAGE_SIZE - 1);

		zero_user_segments(page, 0, from, from + len, PAGE_SIZE);
	}
	return 0;
}

int pfs_write_end(struct file *file, struct address_space *mapping, loff_t pos,
		  unsigned len, unsigned copied, struct page *page,
		  void *fsdata)
{
	struct inode *inode = page->mapping->host;
	loff_t last_pos = pos + copied;

	/* zero the stale part of the page if we did a short copy */
	if (!PageUptodate(page)) {
		if (copied < len) {
			unsigned from = pos & (PAGE_SIZE - 1);

			zero_user(page, from + copied, len - copied);
		}
		SetPageUptodate(page);
	}
	/*
	 * No need to use i_size_read() here, the i_size
	 * cannot change under us because we hold the i_mutex.
	 */
	if (last_pos > inode->i_size)
		i_size_write(inode, last_pos);

	set_page_dirty(page);
	unlock_page(page);
	if (put_page_testzero(page)) {
		private_vfree((void *)page->pv_addr);
	}

	return copied;
}

const struct address_space_operations pfs_aops = {
	.readpage = simple_readpage,
	.write_begin = pfs_write_begin,
	.write_end = pfs_write_end,
	.set_page_dirty = __set_page_dirty_no_writeback,
};

#endif /* CONFIG_SYSCALL_ISOLATION */
