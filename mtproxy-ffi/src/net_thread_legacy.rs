//! Legacy `net/net-thread.c` compatibility exports.

use core::ffi::{c_int, c_long, c_uint, c_void};
use core::mem::size_of;
use core::ptr;

type Job = *mut c_void;
type ConnectionJob = Job;
type JobFunction = unsafe extern "C" fn(Job, c_int, *mut c_void) -> c_int;

const JS_RUN: c_int = 0;
const JS_FINISH: c_int = 7;
const JC_ENGINE: c_int = 8;
const JOB_ERROR: c_int = -1;
const MPQ_POP_NON_BLOCK: c_int = 4;
const JOB_REF_TAG: c_int = 1;

const NOTIFICATION_EVENT_TCP_CONN_READY: c_int = 1;
const NOTIFICATION_EVENT_TCP_CONN_CLOSE: c_int = 2;
const NOTIFICATION_EVENT_TCP_CONN_ALARM: c_int = 3;
const NOTIFICATION_EVENT_TCP_CONN_WAKEUP: c_int = 4;

type NetThreadRpcReadyFn = unsafe extern "C" fn(*mut c_void) -> c_int;
type NetThreadRpcFn = unsafe extern "C" fn(*mut c_void);
type NetThreadFailConnectionFn = unsafe extern "C" fn(*mut c_void, c_int);
type RpcWakeupFn = Option<unsafe extern "C" fn(ConnectionJob) -> c_int>;
type RpcCloseFn = Option<unsafe extern "C" fn(ConnectionJob, c_int) -> c_int>;

#[repr(C)]
struct EventTimer {
    h_idx: c_int,
    flags: c_int,
    wakeup: Option<unsafe extern "C" fn(*mut EventTimer) -> c_int>,
    wakeup_time: f64,
    real_wakeup_time: f64,
}

#[repr(C)]
struct AsyncJob {
    j_flags: c_int,
    j_status: c_int,
    j_sigclass: c_int,
    j_refcnt: c_int,
    j_error: c_int,
    j_children: c_int,
    j_align: c_int,
    j_custom_bytes: c_int,
    j_type: c_uint,
    j_subclass: c_int,
    j_thread: *mut c_void,
    j_execute: Option<JobFunction>,
    j_parent: Job,
    j_custom: [i64; 0],
}

#[repr(C)]
struct ConnectionInfoHead {
    _timer: EventTimer,
    _fd: c_int,
    _generation: c_int,
    _flags: c_int,
    _type_: *mut c_void,
    extra: *mut c_void,
}

#[repr(C)]
struct TcpRpcClientFunctions {
    _info: *mut c_void,
    _rpc_extra: *mut c_void,
    _execute: *mut c_void,
    _check_ready: *mut c_void,
    _flush_packet: *mut c_void,
    _rpc_check_perm: *mut c_void,
    _rpc_init_crypto: *mut c_void,
    _rpc_start_crypto: *mut c_void,
    rpc_wakeup: RpcWakeupFn,
    rpc_alarm: RpcWakeupFn,
    rpc_ready: RpcWakeupFn,
    rpc_close: RpcCloseFn,
    _max_packet_len: c_int,
    _mode_flags: c_int,
}

#[repr(C)]
struct NotificationEvent {
    event_type: c_int,
    who: *mut c_void,
}

#[repr(C)]
struct NotificationEventJobExtra {
    queue: *mut c_void,
}

static mut NOTIFICATION_JOB: Job = ptr::null_mut();

#[allow(clashing_extern_declarations)]
unsafe extern "C" {
    fn create_async_job(
        run_job: Option<JobFunction>,
        job_signals: u64,
        job_subclass: c_int,
        custom_bytes: c_int,
        job_type: u64,
        parent_job_tag_int: c_int,
        parent_job: Job,
    ) -> Job;
    fn unlock_job(job_tag_int: c_int, job: Job) -> c_int;
    fn job_signal(job_tag_int: c_int, job: Job, signo: c_int);
    fn job_incref(job: Job) -> Job;
    fn job_decref(job_tag_int: c_int, job: Job);

    fn alloc_mp_queue_w() -> *mut c_void;
    fn mpq_pop_nw(mq: *mut c_void, flags: c_int) -> *mut c_void;
    fn mpq_push_w(mq: *mut c_void, val: *mut c_void, flags: c_int) -> c_long;

    fn fail_connection(c: ConnectionJob, who: c_int);

    fn mtproxy_ffi_net_thread_run_notification_event(
        event_type: c_int,
        who: *mut c_void,
        event: *mut c_void,
        rpc_ready: Option<NetThreadRpcReadyFn>,
        rpc_close: Option<NetThreadRpcFn>,
        rpc_alarm: Option<NetThreadRpcFn>,
        rpc_wakeup: Option<NetThreadRpcFn>,
        fail_connection: Option<NetThreadFailConnectionFn>,
        job_decref: Option<NetThreadRpcFn>,
        event_free: Option<NetThreadRpcFn>,
    ) -> c_int;
}

#[inline]
const fn jss_allow(signo: c_int) -> u64 {
    0x0100_0000_u64 << (signo as u32)
}

#[inline]
const fn jsc_type(class: c_int, signo: c_int) -> u64 {
    (class as u64) << ((signo as u32 * 4) + 32)
}

#[inline]
const fn jsc_allow(class: c_int, signo: c_int) -> u64 {
    jsc_type(class, signo) | jss_allow(signo)
}

#[inline]
unsafe fn job_custom_ptr<T>(job: Job) -> *mut T {
    ptr::addr_of_mut!((*job.cast::<AsyncJob>()).j_custom).cast::<T>()
}

#[inline]
unsafe fn conn_info(c: ConnectionJob) -> *mut ConnectionInfoHead {
    let conn = unsafe { job_custom_ptr::<ConnectionInfoHead>(c) };
    assert!(!conn.is_null());
    conn
}

#[inline]
unsafe fn tcp_rpcc_func(c: ConnectionJob) -> *mut TcpRpcClientFunctions {
    let conn = unsafe { conn_info(c) };
    let funcs = unsafe { (*conn).extra.cast::<TcpRpcClientFunctions>() };
    assert!(!funcs.is_null());
    funcs
}

unsafe extern "C" fn net_thread_rpc_ready_bridge(who: *mut c_void) -> c_int {
    let funcs = unsafe { tcp_rpcc_func(who) };
    match unsafe { (*funcs).rpc_ready } {
        Some(rpc_ready) => unsafe { rpc_ready(who) },
        None => 0,
    }
}

unsafe extern "C" fn net_thread_rpc_close_bridge(who: *mut c_void) {
    let funcs = unsafe { tcp_rpcc_func(who) };
    let Some(rpc_close) = (unsafe { (*funcs).rpc_close }) else {
        panic!("rpc_close callback is missing");
    };
    let _ = unsafe { rpc_close(who, 0) };
}

unsafe extern "C" fn net_thread_rpc_alarm_bridge(who: *mut c_void) {
    let funcs = unsafe { tcp_rpcc_func(who) };
    let Some(rpc_alarm) = (unsafe { (*funcs).rpc_alarm }) else {
        panic!("rpc_alarm callback is missing");
    };
    let _ = unsafe { rpc_alarm(who) };
}

unsafe extern "C" fn net_thread_rpc_wakeup_bridge(who: *mut c_void) {
    let funcs = unsafe { tcp_rpcc_func(who) };
    let Some(rpc_wakeup) = (unsafe { (*funcs).rpc_wakeup }) else {
        panic!("rpc_wakeup callback is missing");
    };
    let _ = unsafe { rpc_wakeup(who) };
}

unsafe extern "C" fn net_thread_fail_connection_bridge(who: *mut c_void, code: c_int) {
    unsafe { fail_connection(who, code) };
}

unsafe extern "C" fn net_thread_job_decref_bridge(who: *mut c_void) {
    unsafe { job_decref(JOB_REF_TAG, who) };
}

unsafe extern "C" fn net_thread_event_free_bridge(event: *mut c_void) {
    unsafe { libc::free(event) };
}

unsafe fn run_notification_event(ev: *mut NotificationEvent) {
    let rc = unsafe {
        mtproxy_ffi_net_thread_run_notification_event(
            (*ev).event_type,
            (*ev).who,
            ev.cast::<c_void>(),
            Some(net_thread_rpc_ready_bridge),
            Some(net_thread_rpc_close_bridge),
            Some(net_thread_rpc_alarm_bridge),
            Some(net_thread_rpc_wakeup_bridge),
            Some(net_thread_fail_connection_bridge),
            Some(net_thread_job_decref_bridge),
            Some(net_thread_event_free_bridge),
        )
    };
    assert_eq!(rc, 0);
}

unsafe extern "C" fn notification_event_run(job: Job, op: c_int, _jt: *mut c_void) -> c_int {
    if op != JS_RUN {
        return JOB_ERROR;
    }

    let extra = unsafe { job_custom_ptr::<NotificationEventJobExtra>(job) };
    assert!(!extra.is_null());
    loop {
        let ev =
            unsafe { mpq_pop_nw((*extra).queue, MPQ_POP_NON_BLOCK) }.cast::<NotificationEvent>();
        if ev.is_null() {
            break;
        }
        unsafe { run_notification_event(ev) };
    }
    0
}

unsafe fn notification_event_insert_conn(c: ConnectionJob, event_type: c_int) {
    let ev = unsafe { libc::malloc(size_of::<NotificationEvent>()) }.cast::<NotificationEvent>();
    assert!(!ev.is_null());
    unsafe {
        (*ev).who = job_incref(c);
        (*ev).event_type = event_type;
    }

    let job = unsafe { NOTIFICATION_JOB };
    assert!(!job.is_null());
    let extra = unsafe { job_custom_ptr::<NotificationEventJobExtra>(job) };
    assert!(!extra.is_null());
    let _ = unsafe { mpq_push_w((*extra).queue, ev.cast::<c_void>(), 0) };
    unsafe { job_signal(JOB_REF_TAG, job_incref(job), JS_RUN) };
}

#[no_mangle]
pub unsafe extern "C" fn notification_event_job_create() {
    let job = unsafe {
        create_async_job(
            Some(notification_event_run),
            jsc_allow(JC_ENGINE, JS_RUN) | jsc_allow(JC_ENGINE, JS_FINISH),
            0,
            c_int::try_from(size_of::<NotificationEventJobExtra>()).unwrap_or(c_int::MAX),
            0,
            JOB_REF_TAG,
            ptr::null_mut(),
        )
    };
    assert!(!job.is_null());

    let extra = unsafe { job_custom_ptr::<NotificationEventJobExtra>(job) };
    assert!(!extra.is_null());
    unsafe {
        (*extra).queue = alloc_mp_queue_w();
        assert!(!(*extra).queue.is_null());
    }

    unsafe {
        NOTIFICATION_JOB = job;
        let _ = unlock_job(JOB_REF_TAG, job_incref(job));
    }
}

#[no_mangle]
pub unsafe extern "C" fn notification_event_insert_tcp_conn_close(c: ConnectionJob) {
    unsafe { notification_event_insert_conn(c, NOTIFICATION_EVENT_TCP_CONN_CLOSE) };
}

#[no_mangle]
pub unsafe extern "C" fn notification_event_insert_tcp_conn_ready(c: ConnectionJob) {
    unsafe { notification_event_insert_conn(c, NOTIFICATION_EVENT_TCP_CONN_READY) };
}

#[no_mangle]
pub unsafe extern "C" fn notification_event_insert_tcp_conn_alarm(c: ConnectionJob) {
    unsafe { notification_event_insert_conn(c, NOTIFICATION_EVENT_TCP_CONN_ALARM) };
}

#[no_mangle]
pub unsafe extern "C" fn notification_event_insert_tcp_conn_wakeup(c: ConnectionJob) {
    unsafe { notification_event_insert_conn(c, NOTIFICATION_EVENT_TCP_CONN_WAKEUP) };
}
