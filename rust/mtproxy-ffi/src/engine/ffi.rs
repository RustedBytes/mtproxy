//! FFI export surface for selected `engine` runtime functions.

use super::core::*;
use core::ffi::{c_char, c_double, c_int, c_void};

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_init(
    pwd_filename: *const c_char,
    do_not_open_port: c_int,
) {
    unsafe { engine_init_impl(pwd_filename, do_not_open_port) };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_check_server_functions() {
    unsafe { check_server_functions_impl() };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_do_precise_cron() {
    unsafe { do_precise_cron_impl() };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_default_engine_server_start() {
    unsafe { default_engine_server_start_impl() };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_create_main_thread_pipe(
    pipe_read_end: *mut c_int,
    pipe_write_end: *mut c_int,
) {
    unsafe { create_main_thread_pipe_impl(pipe_read_end, pipe_write_end) };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_wakeup_main_thread(pipe_write_end: c_int) {
    unsafe { wakeup_main_thread_impl(pipe_write_end) };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_server_exit() {
    unsafe { server_exit_impl() };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_server_init(
    listen_connection_type: *mut core::ffi::c_void,
    listen_connection_extra: *mut core::ffi::c_void,
    pipe_read_end: c_int,
) {
    unsafe {
        server_init_impl(
            listen_connection_type,
            listen_connection_extra,
            pipe_read_end,
        )
    };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_startup(e: *mut EngineState, f: *mut ServerFunctions) {
    unsafe { engine_startup_impl(e, f) };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_add_engine_parse_options() {
    unsafe { engine_add_engine_parse_options_impl() };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_default_parse_option_func(a: c_int) -> c_int {
    unsafe { default_parse_option_func_impl(a) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_prepare_stats() -> c_int {
    unsafe { engine_prepare_stats_impl() }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_rpc_stats(tlio_out: *mut core::ffi::c_void) {
    unsafe { engine_rpc_stats_impl(tlio_out) };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_default_parse_extra_args(
    argc: c_int,
    argv: *mut *mut c_char,
) {
    unsafe { default_parse_extra_args_impl(argc, argv) };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_default_cron() {
    unsafe { default_cron_impl() };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_set_signals_handlers() {
    unsafe { set_signals_handlers_impl() };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_set_epoll_wait_timeout(epoll_wait_timeout: c_int) {
    unsafe { engine_set_epoll_wait_timeout_impl(epoll_wait_timeout) };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_precise_cron_function_insert(
    ev: *mut EventPreciseCron,
) {
    unsafe { precise_cron_function_insert_impl(ev) };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_precise_cron_function_remove(
    ev: *mut EventPreciseCron,
) {
    unsafe { precise_cron_function_remove_impl(ev) };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_update_job_stats_gw(ex: *mut c_void) -> c_double {
    unsafe { update_job_stats_gw_impl(ex) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_precise_cron_job_run(
    job: *mut c_void,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    unsafe { precise_cron_job_run_impl(job, op, jt) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_terminate_job_run(
    job: *mut c_void,
    op: c_int,
    jt: *mut c_void,
) -> c_int {
    unsafe { terminate_job_run_impl(job, op, jt) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_default_get_op(tlio_in: *mut c_void) -> c_int {
    unsafe { default_get_op_impl(tlio_in) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_engine_default_main(
    f: *mut ServerFunctions,
    argc: c_int,
    argv: *mut *mut c_char,
) -> c_int {
    unsafe { default_main_impl(f, argc, argv) }
}
