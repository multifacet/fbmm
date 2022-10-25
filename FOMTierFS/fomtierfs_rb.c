#include "fs.h"

/*
 * Search a page tree for the fomtierfs_page mapped to the given a file offset.
 * fomtierfs_inode_info->map_lock should be held in read mode.
 * @root The root of the rb tree to search
 * @offset The page offset to look for
 *
 * Returns NULL if the page is not found and the corresponding page if found.
 */
struct fomtierfs_page *fomtierfs_find_page(struct rb_root *root, u64 offset)
{
    struct rb_node *node = root->rb_node;

    while (node) {
        struct fomtierfs_page *data = container_of(node, struct fomtierfs_page, node);

        if (offset < data->page_offset)
            node = node->rb_left;
        else if (offset > data->page_offset)
            node = node->rb_right;
        else
            return data;
    }

    return NULL;
}

/*
 * Insert a new page into a page tree
 * fomtierfs_inode_info->map_lock should be held in write mode.
 * @root The root of the rb tree to insert into
 * @page The page to insert into the tree
 *
 * Returns true if the insert was successful, and false if a page at the same
 * offset already exists.
 */
bool fomtierfs_insert_page(struct rb_root *root, struct fomtierfs_page *page)
{
    struct rb_node **new = &(root->rb_node);
    struct rb_node *parent = NULL;

    // Find place to insert new node
    while (*new) {
        struct fomtierfs_page *this = container_of(*new, struct fomtierfs_page, node);

        parent = *new;

        if (page->page_offset < this->page_offset)
            new = &((*new)->rb_left);
        else if (page->page_offset > this->page_offset)
            new = &((*new)->rb_right);
        else
            return false;
    }

    // Insert the node and rebalance the tree
    rb_link_node(&page->node, parent, new);
    rb_insert_color(&page->node, root);

    return true;
}

/*
 * Replaces the node currently in the tree at new_page->offset.
 * If such a page does not already exist in the tree, BUG out.
 * The fomtierfs_inode_info.map_lock should be held in write mode before this
 * function is called.
 * @root The root of the rb tree to modify
 * @new_page The page that will replace the new page
 */
void fomtierfs_replace_page(struct rb_root *root, struct fomtierfs_page *new_page)
{
    struct fomtierfs_page *old_page;

    old_page = fomtierfs_find_page(root, new_page->page_offset);
    if (!old_page) {
        BUG();
    }

    rb_replace_node(&old_page->node, &new_page->node, root);
}
