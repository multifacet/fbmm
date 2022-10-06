#include "fs.h"

/*
 * Search a mapping tree for the file offset->page mapping given a file offset
 * @root The root of the rb tree to search
 * @offset The page offset to look for
 *
 * Returns NULL if the mapping is not found and the corresponding mapping if found.
 */
struct fomtierfs_page_map *fomtierfs_find_map(struct rb_root *root, u64 offset)
{
    struct rb_node *node = root->rb_node;

    while (node) {
        struct fomtierfs_page_map *data = container_of(node, struct fomtierfs_page_map, node);

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
 * Insert a new mapping into a mapping tree
 * @root The root of the rb tree to insert into
 * @map The mapping to insert into the tree
 *
 * Returns true if the insert was successful, and false if a mapping at the same
 * offset already exists.
 */
bool fomtierfs_insert_mapping(struct rb_root *root, struct fomtierfs_page_map *map)
{
    struct rb_node **new = &(root->rb_node);
    struct rb_node *parent = NULL;

    // Find place to insert new node
    while (*new) {
        struct fomtierfs_page_map *this = container_of(*new, struct fomtierfs_page_map, node);

        parent = *new;

        if (map->page_offset < this->page_offset)
            new = &((*new)->rb_left);
        else if (map->page_offset > this->page_offset)
            new = &((*new)->rb_right);
        else
            return false;
    }

    // Insert the node and rebalance the tree
    rb_link_node(&map->node, parent, new);
    rb_insert_color(&map->node, root);

    return true;
}
