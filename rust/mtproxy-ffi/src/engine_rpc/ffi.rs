//! FFI export surface for migrated large functions in `engine/engine-rpc.c`.

use super::core::*;
use core::ffi::{c_char, c_double, c_int, c_longlong, c_void};

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_fetch_query(
    parent: *mut c_void,
    tlio_in: *mut TlInState,
    raw: *mut *mut RawMessage,
    error: *mut *mut c_char,
    error_code: *mut c_int,
    actor_id: c_longlong,
    extra_ref: *mut c_void,
    all_list: *mut c_void,
    status: c_int,
) -> *mut c_void {
    unsafe {
        fetch_query_impl(
            parent.cast::<AsyncJob>(),
            tlio_in,
            raw,
            error,
            error_code,
            actor_id,
            extra_ref.cast::<AsyncJob>(),
            all_list.cast::<AsyncJob>(),
            status,
        )
        .cast()
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_process_act_atom_subjob(
    job: *mut c_void,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    unsafe { process_act_atom_subjob_impl(job.cast::<AsyncJob>(), op, jt) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_process_query_job(
    job: *mut c_void,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    unsafe { process_query_job_impl(job.cast::<AsyncJob>(), op, jt) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_tl_aio_init_store(
    type_: c_int,
    pid: *mut ProcessId,
    qid: c_longlong,
) -> *mut c_void {
    unsafe { tl_aio_init_store_impl(type_, pid, qid).cast() }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_engine_work_rpc_req_result(
    tlio_in: *mut TlInState,
    params: *mut QueryWorkParams,
) {
    unsafe { engine_work_rpc_req_result_impl(tlio_in, params) };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_tl_query_result_fun_set(
    func: TlQueryResultFn,
    query_type_id: c_int,
) {
    unsafe { tl_query_result_fun_set_impl(func, query_type_id) };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_engine_tl_init(
    parse: TlParseFn,
    stat: TlStatFn,
    get_op: TlGetOpFn,
    timeout: c_double,
) {
    unsafe { engine_tl_init_impl(parse, stat, get_op, timeout) };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_tl_engine_store_stats(tlio_out: *mut c_void) {
    unsafe { tl_engine_store_stats_impl(tlio_out) };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_process_query_custom_subjob(
    job: *mut c_void,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    unsafe { process_query_custom_subjob_impl(job.cast::<AsyncJob>(), op, jt) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_create_query_job(
    job: *mut c_void,
    raw: *mut RawMessage,
    h: *mut TlQueryHeader,
    timeout: c_double,
    remote_pid: *mut ProcessId,
    out_type: c_int,
    fd: c_int,
    generation: c_int,
) -> c_int {
    unsafe {
        create_query_job_impl(
            job.cast::<AsyncJob>(),
            raw,
            h,
            timeout,
            remote_pid,
            out_type,
            fd,
            generation,
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_create_query_custom_job(
    job: *mut c_void,
    raw: *mut RawMessage,
    timeout: c_double,
    fd: c_int,
    generation: c_int,
) -> c_int {
    unsafe { create_query_custom_job_impl(job.cast::<AsyncJob>(), raw, timeout, fd, generation) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_do_create_query_job(
    raw: *mut RawMessage,
    type_: c_int,
    pid: *mut ProcessId,
    conn: *mut c_void,
) -> c_int {
    unsafe { do_create_query_job_impl(raw, type_, pid, conn) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_default_tl_tcp_rpcs_execute(
    c: *mut c_void,
    op: c_int,
    raw: *mut RawMessage,
) -> c_int {
    unsafe { default_tl_tcp_rpcs_execute_impl(c, op, raw) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_tl_generate_next_qid(
    query_type_id: c_int,
) -> c_longlong {
    unsafe { tl_generate_next_qid_impl(query_type_id) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_tl_store_stats(
    tlio_out: *mut c_void,
    s: *const c_char,
    raw: c_int,
) -> c_int {
    unsafe { tl_store_stats_impl(tlio_out, s, raw) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_query_job_run(
    job: *mut c_void,
    fd: c_int,
    generation: c_int,
) -> c_int {
    unsafe { query_job_run_impl(job.cast::<AsyncJob>(), fd, generation) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_do_query_job_run(
    job: *mut c_void,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    unsafe { do_query_job_run_impl(job.cast::<AsyncJob>(), op, jt) }
}
