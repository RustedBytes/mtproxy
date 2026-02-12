/*
    This file is part of Mtproto-proxy Library.

    Mtproto-proxy Library is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License as
   published by the Free Software Foundation, either version 2 of the License,
   or (at your option) any later version.

    Mtproto-proxy Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Mtproto-proxy Library.  If not, see
   <http://www.gnu.org/licenses/>.

    Copyright 2024-2026 Rust MTProxy Contributors
*/

/**
 * @file vv_tree_ffi.h
 * @brief FFI bindings for vv-tree (treap data structure)
 *
 * This header provides C-compatible functions for using the Rust
 * implementation of treap (randomized binary search tree) that replaces
 * the functionality from vv/vv-tree.c.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Opaque handle to a treap tree.
 */
typedef struct VvTreeHandle VvTreeHandle;

/**
 * Creates a new treap tree.
 *
 * @return A handle to the new tree, or nullptr on allocation failure.
 */
VvTreeHandle *vv_tree_create(void);

/**
 * Destroys a treap tree and frees its memory.
 *
 * @param handle Handle to the tree to destroy.
 *               After this call, the handle must not be used.
 */
void vv_tree_destroy(VvTreeHandle *handle);

/**
 * Inserts a key into the treap with a given priority.
 *
 * @param handle Handle to the tree.
 * @param key    Key to insert (treated as an opaque pointer).
 * @param priority Priority value for the key.
 */
void vv_tree_insert(VvTreeHandle *handle, const void *key, int priority);

/**
 * Looks up a key in the treap.
 *
 * @param handle Handle to the tree.
 * @param key    Key to look up.
 * @return The key pointer if found, or nullptr if not found.
 */
const void *vv_tree_lookup(VvTreeHandle *handle, const void *key);

/**
 * Deletes a key from the treap.
 *
 * @param handle Handle to the tree.
 * @param key    Key to delete.
 * @return 1 if the key was found and deleted, 0 otherwise.
 */
int vv_tree_delete(VvTreeHandle *handle, const void *key);

/**
 * Clears all elements from the treap.
 *
 * @param handle Handle to the tree.
 */
void vv_tree_clear(VvTreeHandle *handle);

/**
 * Returns the number of elements in the treap.
 *
 * @param handle Handle to the tree.
 * @return The number of elements.
 */
int vv_tree_count(VvTreeHandle *handle);

/**
 * Callback type for tree traversal.
 *
 * @param key The key at the current node.
 */
typedef void (*vv_tree_traverse_callback)(const void *key);

/**
 * Traverses the treap in sorted order, calling the callback for each element.
 *
 * @param handle   Handle to the tree.
 * @param callback Function to call for each key.
 */
void vv_tree_traverse(VvTreeHandle *handle, vv_tree_traverse_callback callback);

#ifdef __cplusplus
}
#endif
