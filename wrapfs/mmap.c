/*
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "wrapfs.h"
#include <linux/page-flags.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/writeback.h>
#include <linux/crypto.h>

int wrapfs_read_lower(char *data, loff_t offset, size_t size,
                        struct inode *wrapfs_inode, struct file *file)
{
		struct file *lower_file;
        mm_segment_t fs_save;
        ssize_t rc;
	  mode_t previous_mode;

#ifdef WRAPFS_CRYPTO
	struct crypto_cipher *tfm;
	char *decrypted_page_buffer = NULL; // free this
#endif
      
	lower_file = wrapfs_lower_file(file);
        if (!lower_file)
                return -EIO;
        fs_save = get_fs();
        set_fs(get_ds());
	previous_mode = lower_file->f_mode;
	lower_file->f_mode |= FMODE_READ;
        rc = vfs_read(lower_file, data, size, &offset);
	lower_file->f_mode = previous_mode;

#ifdef WRAPFS_CRYPTO	
	decrypted_page_buffer = kmalloc(size, GFP_KERNEL);
	if (decrypted_page_buffer == NULL)
		goto out;		
	memset(decrypted_page_buffer, 0, size);
	
	tfm = crypto_alloc_cipher("aes", 0, 16);
	if (!IS_ERR(tfm))
		crypto_cipher_setkey(tfm, WRAPFS_SB(file->f_dentry->d_sb)->key, 16);
	else
		goto fail;

	crypto_cipher_decrypt_one(tfm, decrypted_page_buffer, data);
	
	/*printk(KERN_ALERT "Decrypted buffer = %s\n", decrypted_page_buffer);*/

	memcpy(data, decrypted_page_buffer, size);
#endif
        set_fs(fs_save);

#ifdef WRAPFS_CRYPTO
	crypto_free_cipher(tfm);
fail:
		kfree(decrypted_page_buffer);
out:
#endif
        return rc;
}

int wrapfs_write_lower(struct inode *wrapfs_inode, char *data,
                         loff_t offset, size_t size, struct file *file)
{
        struct file *lower_file;
        mm_segment_t fs_save;
        ssize_t rc;

        lower_file = wrapfs_lower_file(file);
        if (!lower_file)
                return -EIO;
        fs_save = get_fs();
        set_fs(get_ds());

        rc = vfs_write(lower_file, data, size, &offset);
	
        set_fs(fs_save);
        mark_inode_dirty_sync(wrapfs_inode);
        return rc;
}


int wrapfs_read_lower_page_segment(struct page *page_for_wrapfs,
                                     pgoff_t page_index,
                                     size_t offset_in_page, size_t size,
                                     struct inode *wrapfs_inode,
				     		 struct file *file)
{
        char *virt;
        loff_t offset;
        int rc;

        offset = ((((loff_t)page_index) << PAGE_CACHE_SHIFT) + offset_in_page);
        virt = kmap(page_for_wrapfs);
        rc = wrapfs_read_lower(virt, offset, size, wrapfs_inode, file);
        if (rc > 0)
                rc = 0;
        kunmap(page_for_wrapfs);
        flush_dcache_page(page_for_wrapfs);
        return rc;
}

int wrapfs_write_lower_page_segment(struct inode *wrapfs_inode,
                                      struct page *page_for_lower,
                                      size_t offset_in_page, size_t size, 
                                      struct file *file)
{
        char *virt;
        loff_t offset;
        int rc = -1;

#ifdef WRAPFS_CRYPTO
        unsigned char *encrypted_page_buffer;
        struct crypto_cipher *tfm;
#endif

        offset = ((((loff_t)page_for_lower->index) << PAGE_CACHE_SHIFT)
                  + offset_in_page);
        virt = kmap(page_for_lower);

#ifdef WRAPFS_CRYPTO
        encrypted_page_buffer = kmalloc(size, GFP_KERNEL); //free this
		if (encrypted_page_buffer == NULL)
			goto out;		
        memset(encrypted_page_buffer, 0, size);

        tfm = crypto_alloc_cipher("aes", 0, 16);
        if (!IS_ERR(tfm))
                crypto_cipher_setkey(tfm, WRAPFS_SB(file->f_dentry->d_sb)->key, 16);
		else
				goto fail;

        crypto_cipher_encrypt_one(tfm, encrypted_page_buffer, virt);
        /*printk(KERN_ALERT "Encrypted buffer = %s\n", encrypted_page_buffer);*/
	    /*memcpy(virt, encrypted_page_buffer, size);*/

        rc = wrapfs_write_lower(wrapfs_inode, encrypted_page_buffer, offset, size, file);
#else
		rc = wrapfs_write_lower(wrapfs_inode, virt, offset, size, file);
#endif

        if (rc > 0)
                rc = 0;
        kunmap(page_for_lower);
#ifdef WRAPFS_CRYPTO
	crypto_free_cipher(tfm);
fail:
		kfree(encrypted_page_buffer);
out:
#endif
        return rc;
}

static int wrapfs_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
	int err;
	struct file *file, *lower_file;
	const struct vm_operations_struct *lower_vm_ops;
	struct vm_area_struct lower_vma;

	/*printk(KERN_ALERT "In wrapfs_fault()\n");	*/

	memcpy(&lower_vma, vma, sizeof(struct vm_area_struct));
	file = lower_vma.vm_file;
	lower_vm_ops = WRAPFS_F(file)->lower_vm_ops;
	BUG_ON(!lower_vm_ops);

	lower_file = wrapfs_lower_file(file);
	/*
	 * XXX: vm_ops->fault may be called in parallel.  Because we have to
	 * resort to temporarily changing the vma->vm_file to point to the
	 * lower file, a concurrent invocation of wrapfs_fault could see a
	 * different value.  In this workaround, we keep a different copy of
	 * the vma structure in our stack, so we never expose a different
	 * value of the vma->vm_file called to us, even temporarily.  A
	 * better fix would be to change the calling semantics of ->fault to
	 * take an explicit file pointer.
	 */
	lower_vma.vm_file = lower_file;
	err = lower_vm_ops->fault(&lower_vma, vmf);
	return err;
}

static int wrapfs_writepage(struct page *page, struct writeback_control *wbc)
{
        int err = -EIO;
        struct inode *inode;
        struct inode *lower_inode;
        struct page *lower_page;
        struct address_space *lower_mapping; /* lower inode mapping */
        gfp_t mask;

        /*printk(KERN_ALERT "in writepage() \n");*/

        BUG_ON(!PageUptodate(page));
        inode = page->mapping->host;
        /* if no lower inode, nothing to do */
        if (!inode || !WRAPFS_I(inode) || WRAPFS_I(inode)->lower_inode) {
                err = 0;
                goto out;
        }
        lower_inode = wrapfs_lower_inode(inode);
        lower_mapping = lower_inode->i_mapping;

        /*
         * find lower page (returns a locked page)
         *
         * We turn off __GFP_FS while we look for or create a new lower
         * page.  This prevents a recursion into the file system code, which
         * under memory pressure conditions could lead to a deadlock.  This
         * is similar to how the loop driver behaves (see loop_set_fd in
         * drivers/block/loop.c).  If we can't find the lower page, we
         * redirty our page and return "success" so that the VM will call us
         * again in the (hopefully near) future.
         */
        mask = mapping_gfp_mask(lower_mapping) & ~(__GFP_FS);
        lower_page = find_or_create_page(lower_mapping, page->index, mask);
        if (!lower_page) {
                err = 0;
                set_page_dirty(page);
                goto out;
        }

        /* copy page data from our upper page to the lower page */
        copy_highpage(lower_page, page);
        flush_dcache_page(lower_page);
        SetPageUptodate(lower_page);
        set_page_dirty(lower_page);

        /*
         * Call lower writepage (expects locked page).  However, if we are
         * called with wbc->for_reclaim, then the VFS/VM just wants to
         * reclaim our page.  Therefore, we don't need to call the lower
         * ->writepage: just copy our data to the lower page (already done
         * above), then mark the lower page dirty and unlock it, and return
         * success.
         */
        if (wbc->for_reclaim) {
                unlock_page(lower_page);
                goto out_release;
        }

        BUG_ON(!lower_mapping->a_ops->writepage);
        wait_on_page_writeback(lower_page); /* prevent multiple writers */
        clear_page_dirty_for_io(lower_page); /* emulate VFS behavior */
        err = lower_mapping->a_ops->writepage(lower_page, wbc);
        if (err < 0)
                goto out_release;

        /*
         * Lower file systems such as ramfs and tmpfs, may return
         * AOP_WRITEPAGE_ACTIVATE so that the VM won't try to (pointlessly)
         * write the page again for a while.  But those lower file systems
         * also set the page dirty bit back again.  Since we successfully
         * copied our page data to the lower page, then the VM will come
         * back to the lower page (directly) and try to flush it.  So we can
         * save the VM the hassle of coming back to our page and trying to
         * flush too.  Therefore, we don't re-dirty our own page, and we
         * never return AOP_WRITEPAGE_ACTIVATE back to the VM (we consider
         * this a success).
         *
         * We also unlock the lower page if the lower ->writepage returned
         * AOP_WRITEPAGE_ACTIVATE.  (This "anomalous" behaviour may be
         * addressed in future shmem/VM code.)
         */
        if (err == AOP_WRITEPAGE_ACTIVATE) {
                err = 0;
                unlock_page(lower_page);
        }

        /* all is well */

        /* lower mtimes have changed: update ours */
        /*	fsstack_copy_inode_size(dentry->d_inode,
				lower_file->f_path.dentry->d_inode);
        fsstack_copy_attr_times(dentry->d_inode,
				lower_file->f_path.dentry->d_inode);	
        */

out_release:
        /* b/c find_or_create_page increased refcnt */
        page_cache_release(lower_page);
out:
        /*
         * We unlock our page unconditionally, because we never return
         * AOP_WRITEPAGE_ACTIVATE.
         */
        unlock_page(page);
        return err;
}
static int wrapfs_readpage(struct file *file, struct page *page)
{
	int err=0;

	/*printk(KERN_ALERT "In wrapfs_readpage()\n");*/

	err = wrapfs_read_lower_page_segment(page, page->index, 0, PAGE_CACHE_SIZE, page->mapping->host, file);
	if (err) {
		printk(KERN_ERR "Error reading page; err = "
				 "[%d]\n", err);
		goto out;
	}

out:
	if (err == 0)
		SetPageUptodate(page);
	else
		ClearPageUptodate(page);
	unlock_page(page);
	return err;
}

static int wrapfs_write_begin(struct file *file,
                         struct address_space *mapping,
                         loff_t pos, unsigned len, unsigned flags,
                         struct page **pagep, void **fsdata)
{
        pgoff_t index = pos >> PAGE_CACHE_SHIFT;
        struct page *page;
        loff_t prev_page_end_size;
        int rc = 0;

        /*printk(KERN_ALERT "In wrapfs_write_begin()\n");*/

        page = grab_cache_page_write_begin(mapping, index, flags);
        if (!page)
                return -ENOMEM;
        *pagep = page;

        prev_page_end_size = ((loff_t)index << PAGE_CACHE_SHIFT);
        if (!PageUptodate(page)) {
		rc = wrapfs_read_lower_page_segment(
		page, index, 0, PAGE_CACHE_SIZE,
		mapping->host, file);
		if (rc) {
			printk(KERN_ERR "%s: Error reading "
				   "page; rc = [%d]\n",
				   __func__, rc);
			ClearPageUptodate(page);
			goto out;
		}
		SetPageUptodate(page);
        }

        /* Writing to a new page, and creating a small hole from start
         * of page?  Zero it out. */
        if ((i_size_read(mapping->host) == prev_page_end_size)
            && (pos != 0))
                zero_user(page, 0, PAGE_CACHE_SIZE);
out:
        if (unlikely(rc)) {
                unlock_page(page);
                page_cache_release(page);
                *pagep = NULL;
        }
        return rc;
}

static int wrapfs_write_end(struct file *file,
                         struct address_space *mapping,
                         loff_t pos, unsigned len, unsigned copied,
                         struct page *page, void *fsdata)
{

        unsigned from = pos & (PAGE_CACHE_SIZE - 1);
        unsigned to = from + copied;
        struct inode *wrapfs_inode = mapping->host;
        int rc;
        int need_unlock_page = 1;

        /*printk(KERN_ALERT "In wrapfs_write_end()\n");*/

        /*printk(KERN_ALERT "Calling fill_zeros_to_end_of_page"
                        "(page w/ index = [0x%.16lx], to = [%d])\n", index, to);
		*/
        rc = wrapfs_write_lower_page_segment(wrapfs_inode, page, 0,
                                               to, file);
        if (!rc) {
                rc = copied;
                fsstack_copy_inode_size(wrapfs_inode,
                        wrapfs_lower_inode(wrapfs_inode));
        } else {
                goto out;
        }

        set_page_dirty(page);
        unlock_page(page);
        need_unlock_page = 0;
        if (pos + copied > i_size_read(wrapfs_inode)) {
                i_size_write(wrapfs_inode, pos + copied);
                printk(KERN_ALERT "Expanded file size to "
                        "[0x%.16llx]\n",
                        (unsigned long long)i_size_read(wrapfs_inode));
                balance_dirty_pages_ratelimited(mapping);
        }
        rc = copied;
out:
        if (need_unlock_page)
                unlock_page(page);
        page_cache_release(page);
        return rc;
}

/*
 * XXX: the default address_space_ops for wrapfs is empty.  We cannot set
 * our inode->i_mapping->a_ops to NULL because too many code paths expect
 * the a_ops vector to be non-NULL.
 */
const struct address_space_operations wrapfs_dummy_aops = {
	/* empty on purpose */
};

const struct address_space_operations wrapfs_aops = {
	/* empty on purpose */
        .readpage = wrapfs_readpage,
        .writepage = wrapfs_writepage,
        .write_begin = wrapfs_write_begin,
        .write_end = wrapfs_write_end,	
};

const struct vm_operations_struct wrapfs_vm_ops = {
	.fault		= wrapfs_fault,
};
