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

#pragma once

/*
 * Rust-backed replacement for the legacy vv-tree.c template instantiations.
 *
 * The API intentionally preserves only the operations that are still used by
 * the C runtime units.
 */

#include "net/net-connections.h"

struct tree_connection;

struct tree_connection *tree_insert_connection(struct tree_connection *tree,
                                               connection_job_t conn,
                                               int priority);
struct tree_connection *tree_delete_connection(struct tree_connection *tree,
                                               connection_job_t conn);
connection_job_t tree_lookup_ptr_connection(struct tree_connection *tree,
                                            connection_job_t conn);

void tree_act_connection(struct tree_connection *tree,
                         void (*act)(connection_job_t));
void tree_act_ex_connection(struct tree_connection *tree,
                            void (*act)(connection_job_t, void *), void *ex);
void tree_act_ex2_connection(struct tree_connection *tree,
                             void (*act)(connection_job_t, void *, void *),
                             void *ex, void *ex2);
void tree_act_ex3_connection(struct tree_connection *tree,
                             void (*act)(connection_job_t, void *, void *,
                                         void *),
                             void *ex, void *ex2, void *ex3);

struct tree_connection *get_tree_ptr_connection(struct tree_connection **tree);
void tree_free_connection(struct tree_connection *tree);
void free_tree_ptr_connection(struct tree_connection *tree);
