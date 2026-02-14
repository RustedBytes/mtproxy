//! FFI export surface for net message runtime.

use super::core::*;
use core::ffi::{c_int, c_void};
use core::ptr;
use core::sync::atomic::Ordering;
use libc::iovec;

#[no_mangle]
pub static mut empty_rwm: RawMessage = RawMessage {
    first: ptr::null_mut(),
    last: ptr::null_mut(),
    total_bytes: 0,
    magic: RM_INIT_MAGIC,
    first_offset: 0,
    last_offset: 0,
};

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_fetch_stats(
    out_total_msgs: *mut c_int,
    out_total_msg_parts: *mut c_int,
) -> c_int {
    if out_total_msgs.is_null() || out_total_msg_parts.is_null() {
        return -1;
    }
    *out_total_msgs = RWM_TOTAL_MSGS.load(Ordering::Relaxed);
    *out_total_msg_parts = RWM_TOTAL_MSG_PARTS.load(Ordering::Relaxed);
    0
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_new_msg_part(
    _neighbor: *mut MsgPart,
    x: *mut MsgBuffer,
) -> *mut MsgPart {
    new_msg_part_impl(_neighbor, x)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_free(raw: *mut RawMessage) -> c_int {
    rwm_free_impl(raw)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_init(
    raw: *mut RawMessage,
    alloc_bytes: c_int,
) -> c_int {
    rwm_create_impl(raw, ptr::null(), alloc_bytes)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_create(
    raw: *mut RawMessage,
    data: *const c_void,
    alloc_bytes: c_int,
) -> c_int {
    rwm_create_impl(raw, data, alloc_bytes)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_clone(
    dest_raw: *mut RawMessage,
    src_raw: *mut RawMessage,
) {
    rwm_clone_impl(dest_raw, src_raw)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_move(
    dest_raw: *mut RawMessage,
    src_raw: *mut RawMessage,
) {
    rwm_move_impl(dest_raw, src_raw)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_push_data(
    raw: *mut RawMessage,
    data: *const c_void,
    alloc_bytes: c_int,
) -> c_int {
    rwm_push_data_ext_impl(
        raw,
        data,
        alloc_bytes,
        RM_PREPEND_RESERVE,
        MSG_SMALL_BUFFER,
        MSG_STD_BUFFER,
    )
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_push_data_ext(
    raw: *mut RawMessage,
    data: *const c_void,
    alloc_bytes: c_int,
    prepend: c_int,
    small_buffer: c_int,
    std_buffer: c_int,
) -> c_int {
    rwm_push_data_ext_impl(raw, data, alloc_bytes, prepend, small_buffer, std_buffer)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_push_data_front(
    raw: *mut RawMessage,
    data: *const c_void,
    alloc_bytes: c_int,
) -> c_int {
    rwm_push_data_front_impl(raw, data, alloc_bytes)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_fetch_data(
    raw: *mut RawMessage,
    data: *mut c_void,
    bytes: c_int,
) -> c_int {
    rwm_fetch_data_impl(raw, data, bytes)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_skip_data(
    raw: *mut RawMessage,
    bytes: c_int,
) -> c_int {
    rwm_skip_data_impl(raw, bytes)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_fetch_lookup(
    raw: *mut RawMessage,
    buf: *mut c_void,
    bytes: c_int,
) -> c_int {
    rwm_fetch_lookup_impl(raw, buf, bytes)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_fetch_data_back(
    raw: *mut RawMessage,
    data: *mut c_void,
    bytes: c_int,
) -> c_int {
    rwm_fetch_data_back_impl(raw, data, bytes)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_fetch_lookup_back(
    raw: *mut RawMessage,
    data: *mut c_void,
    bytes: c_int,
) -> c_int {
    rwm_fetch_lookup_back_impl(raw, data, bytes)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_trunc(raw: *mut RawMessage, len: c_int) -> c_int {
    rwm_trunc_impl(raw, len)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_union(
    raw: *mut RawMessage,
    tail: *mut RawMessage,
) -> c_int {
    rwm_union_impl(raw, tail)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_split(
    raw: *mut RawMessage,
    tail: *mut RawMessage,
    bytes: c_int,
) -> c_int {
    rwm_split_impl(raw, tail, bytes)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_split_head(
    head: *mut RawMessage,
    raw: *mut RawMessage,
    bytes: c_int,
) -> c_int {
    rwm_split_head_impl(head, raw, bytes)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_prepend_alloc(
    raw: *mut RawMessage,
    alloc_bytes: c_int,
) -> *mut c_void {
    rwm_prepend_alloc_impl(raw, alloc_bytes)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_postpone_alloc(
    raw: *mut RawMessage,
    alloc_bytes: c_int,
) -> *mut c_void {
    rwm_postpone_alloc_impl(raw, alloc_bytes)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_clean(raw: *mut RawMessage) {
    rwm_clean_impl(raw)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_clear(raw: *mut RawMessage) {
    rwm_clear_impl(raw)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_check(raw: *mut RawMessage) -> c_int {
    rwm_check_impl(raw)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_fork_message_chain(raw: *mut RawMessage) -> c_int {
    fork_message_chain_impl(raw)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_compare(
    l: *mut RawMessage,
    r: *mut RawMessage,
) -> c_int {
    rwm_compare_impl(l, r)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_prepare_iovec(
    raw: *const RawMessage,
    iov: *mut iovec,
    iov_len: c_int,
    bytes: c_int,
) -> c_int {
    rwm_prepare_iovec_impl(raw, iov, iov_len, bytes)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_dump_sizes(raw: *mut RawMessage) -> c_int {
    rwm_dump_sizes_impl(raw)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_dump(raw: *mut RawMessage) -> c_int {
    rwm_dump_impl(raw)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_crc32c(raw: *mut RawMessage, bytes: c_int) -> u32 {
    rwm_crc32c_impl(raw, bytes)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_crc32(raw: *mut RawMessage, bytes: c_int) -> u32 {
    rwm_crc32_impl(raw, bytes)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_custom_crc32(
    raw: *mut RawMessage,
    bytes: c_int,
    custom_crc32_partial: Crc32PartialFunc,
) -> u32 {
    rwm_custom_crc32_impl(raw, bytes, custom_crc32_partial)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_process(
    raw: *mut RawMessage,
    bytes: c_int,
    process_block: ProcessBlockFn,
    extra: *mut c_void,
) -> c_int {
    rwm_process_ex_impl(raw, bytes, 0, 0, process_block, extra)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_process_ex(
    raw: *mut RawMessage,
    bytes: c_int,
    offset: c_int,
    flags: c_int,
    process_block: ProcessBlockFn,
    extra: *mut c_void,
) -> c_int {
    rwm_process_ex_impl(raw, bytes, offset, flags, process_block, extra)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_process_from_offset(
    raw: *mut RawMessage,
    bytes: c_int,
    offset: c_int,
    process_block: ProcessBlockFn,
    extra: *mut c_void,
) -> c_int {
    rwm_process_ex_impl(raw, bytes, offset, 0, process_block, extra)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_transform_from_offset(
    raw: *mut RawMessage,
    bytes: c_int,
    offset: c_int,
    transform_block: TransformBlockFn,
    extra: *mut c_void,
) -> c_int {
    let process_block: ProcessBlockFn = core::mem::transmute(transform_block);
    rwm_process_ex_impl(raw, bytes, offset, 0, process_block, extra)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_process_and_advance(
    raw: *mut RawMessage,
    bytes: c_int,
    process_block: ProcessBlockFn,
    extra: *mut c_void,
) -> c_int {
    rwm_process_ex_impl(raw, bytes, 0, RMPF_ADVANCE, process_block, extra)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_sha1(
    raw: *mut RawMessage,
    bytes: c_int,
    output: *mut u8,
) -> c_int {
    rwm_sha1_impl(raw, bytes, output)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_encrypt_decrypt_to(
    raw: *mut RawMessage,
    res: *mut RawMessage,
    bytes: c_int,
    ctx: *mut c_void,
    block_size: c_int,
) -> c_int {
    rwm_encrypt_decrypt_to_impl(raw, res, bytes, ctx, block_size)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_get_block_ptr(
    raw: *mut RawMessage,
) -> *mut c_void {
    rwm_get_block_ptr_impl(raw)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_get_block_ptr_bytes(
    raw: *mut RawMessage,
) -> c_int {
    rwm_get_block_ptr_bytes_impl(raw)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_to_tl_string(raw: *mut RawMessage) {
    rwm_to_tl_string_impl(raw)
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_net_msg_rwm_from_tl_string(raw: *mut RawMessage) {
    rwm_from_tl_string_impl(raw)
}
