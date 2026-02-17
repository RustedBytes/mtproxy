//! Rust runtime implementation for selected large functions in `engine/engine.c`.

use core::ffi::{c_char, c_double, c_int, c_long, c_uint, c_void};
use core::mem::{size_of, zeroed};
use core::ptr;

const OUR_SIGRTMAX: c_int = 64;
const SIGNAL_HANDLERS_LEN: usize = 65;

const ENGINE_NO_PORT: u64 = 0x4;
const ENGINE_ENABLE_IPV6: u64 = 0x4;
const ENGINE_ENABLE_TCP: u64 = 0x10;
const ENGINE_ENABLE_MULTITHREAD: u64 = 0x01_000000;
const ENGINE_ENABLE_SLAVE_MODE: u64 = 0x02_000000;
const ENGINE_DEFAULT_ENABLED_MODULES: u64 = ENGINE_ENABLE_TCP;

const DEFAULT_IO_JOB_THREADS: c_int = 16;
const DEFAULT_CPU_JOB_THREADS: c_int = 8;
const DEFAULT_EPOLL_WAIT_TIMEOUT: c_int = 37;
const DATA_BUF_SIZE: usize = 1 << 20;

const JC_IO: c_int = 1;
const JC_CPU: c_int = 2;
const JC_MAIN: c_int = 3;
const JC_CONNECTION: c_int = 4;
const JC_CONNECTION_IO: c_int = 5;
const JC_ENGINE: c_int = 8;
const JC_EPOLL: c_int = JC_MAIN;

const JS_RUN: c_int = 0;
const JS_ALARM: c_int = 4;
const JS_FINISH: c_int = 7;
const JOB_ERROR: c_int = -1;

const JT_HAVE_TIMER: u64 = 1;
const JOB_REF_TAG: c_int = 1;

const RPC_REQ_RESULT: c_uint = 0x63aeda4e;

const AIO_TIMEOUT_DEFAULT: c_double = 0.5;
const EPOLL_TIMEOUT_DEFAULT: c_int = 1;
const DEFAULT_BACKLOG: c_int = 8192;
const MAX_CONNECTIONS: c_int = 65536;
const RPCF_USE_CRC32C: c_int = 2048;

const PORT_RANGE_MOD: c_int = 100;
const RAISE_FILE_GAP: c_int = 16;
const AES_LOAD_PWD_FILE_OPTIONAL_ERROR: c_int = i32::MIN;

const REQUIRED_ARGUMENT: c_int = 1;
const OPTIONAL_ARGUMENT: c_int = 2;
const LONGOPT_JOBS_SET: c_uint = 0x0000_0400;
const EVT_READ: c_int = 4;
const EVT_LEVEL: c_int = 8;
const SM_IPV6: c_int = 2;
const EVA_CONTINUE: c_int = 0;

const FATAL_CANNOT_LOAD_SECRET_FMT: &[u8] = b"fatal: cannot load secret definition file `%s'\n\0";
const FATAL_CANNOT_CHANGE_USER_FMT: &[u8] = b"fatal: cannot change user to %s\n\0";
const BAD_BINDED_IP_FMT: &[u8] = b"Bad binded IP address %d.%d.%d.%d, search in ifconfig\n\0";
const STARTED_AS_FMT: &[u8] = b"Started as [%d.%d.%d.%d:%d:%d:%d]\n\0";
const NONE_STR: &[u8] = b"(none)\0";
const RAISE_FILE_RLIMIT_FAIL_FMT: &[u8] =
    b"raise_file_limit: getrlimit (RLIMIT_NOFILE) fail. %m\n\0";
const FATAL_RAISE_FILE_LIMIT_FMT: &[u8] = b"fatal: cannot raise open file limit to %d\n\0";

const SERVER_STARTED_FMT: &[u8] = b"Server started\n\0";
const MAIN_LOOP_FMT: &[u8] = b"main loop\n\0";
const DID_NOT_EXIT_FMT: &[u8] = b"Did not exit after 120 seconds\n\0";
const TERMINATED_BY_SIGTERM_FMT: &[u8] = b"Terminated by SIGTERM.\n\0";
const TERMINATED_BY_SIGINT_FMT: &[u8] = b"Terminated by SIGINT.\n\0";

const INVOKING_ENGINE_FMT: &[u8] = b"Invoking engine %s\n\0";
const COMMAND_LINE_PARSED_FMT: &[u8] = b"Command line parsed\n\0";
const CREATE_PIPE_READ_CLOSE_FMT: &[u8] = b"%s: closing #%d pipe read end file descriptor.\n\0";
const CREATE_PIPE_WRITE_CLOSE_FMT: &[u8] = b"%s: closing #%d pipe write end file descriptor.\n\0";
const CREATE_PIPE_FUNC_NAME: &[u8] = b"create_main_thread_pipe\0";

const OPTION_CPU_THREADS_NAME: &[u8] = b"cpu-threads\0";
const OPTION_CPU_THREADS_HELP: &[u8] = b"Number of CPU threads (1-64, default 8)\0";
const OPTION_IO_THREADS_NAME: &[u8] = b"io-threads\0";
const OPTION_IO_THREADS_HELP: &[u8] = b"Number of I/O threads (1-64, default 16)\0";
const OPTION_MULTITHREAD_NAME: &[u8] = b"multithread\0";
const OPTION_MULTITHREAD_HELP: &[u8] = b"run in multithread mode\0";
const OPTION_TCP_CPU_THREADS_NAME: &[u8] = b"tcp-cpu-threads\0";
const OPTION_TCP_CPU_THREADS_HELP: &[u8] = b"number of tcp-cpu threads\0";
const OPTION_TCP_IO_THREADS_NAME: &[u8] = b"tcp-iothreads\0";
const OPTION_TCP_IO_THREADS_HELP: &[u8] = b"number of tcp-io threads\0";
const FATAL_PORT_UNDEFINED_FMT: &[u8] = b"fatal: port isn't defined\n\0";
const EXTRA_ARGS_FMT: &[u8] = b"Extra args\n\0";

type Job = *mut c_void;

type ParseFn = Option<unsafe extern "C" fn(*mut c_void, i64) -> *mut c_void>;
type ParseStatsFn = Option<unsafe extern "C" fn(*mut c_void)>;
type ParseOptionFn = Option<unsafe extern "C" fn(c_int) -> c_int>;
type ParseExtraArgsFn = Option<unsafe extern "C" fn(c_int, *mut *mut c_char)>;
type VoidFn = Option<unsafe extern "C" fn()>;
type OnWaitingExitFn = Option<unsafe extern "C" fn() -> c_int>;
type GetOpFn = Option<unsafe extern "C" fn(*mut c_void) -> c_int>;
type CustomOpFn = Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>;
type JobExecuteFn = Option<unsafe extern "C" fn(Job, c_int, *mut c_void) -> c_int>;
type JobTimerWakeupFn = Option<unsafe extern "C" fn(*mut c_void) -> c_double>;
type KsignalHandler = Option<unsafe extern "C" fn(c_int)>;

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcessId {
    ip: c_uint,
    port: i16,
    pid: u16,
    utime: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct EventTimer {
    h_idx: c_int,
    flags: c_int,
    wakeup: Option<unsafe extern "C" fn(*mut EventTimer) -> c_int>,
    wakeup_time: c_double,
    real_wakeup_time: c_double,
}

#[repr(C)]
struct PreciseCronJobExtra {
    ev: EventTimer,
}

#[repr(C)]
struct StatsBuffer {
    buff: *mut c_char,
    pos: c_int,
    size: c_int,
    flags: c_int,
}

#[repr(C, packed(4))]
#[derive(Clone, Copy)]
struct RpcCustomOp {
    op: c_uint,
    func: CustomOpFn,
}

#[repr(C)]
pub(super) struct ServerFunctions {
    cron: VoidFn,
    precise_cron: VoidFn,
    on_exit: VoidFn,
    on_waiting_exit: OnWaitingExitFn,
    on_safe_quit: VoidFn,

    close_net_sockets: VoidFn,

    flags: u64,
    allowed_signals: u64,
    forbidden_signals: u64,
    default_modules: u64,
    default_modules_disabled: u64,

    prepare_stats: ParseStatsFn,

    prepare_parse_options: VoidFn,
    parse_option: ParseOptionFn,
    parse_extra_args: ParseExtraArgsFn,

    pre_init: VoidFn,
    pre_start: VoidFn,

    pre_loop: VoidFn,
    run_script: Option<unsafe extern "C" fn() -> c_int>,

    full_version_str: *const c_char,
    short_version_str: *const c_char,

    epoll_timeout: c_int,
    aio_timeout: c_double,

    parse_function: ParseFn,
    get_op: GetOpFn,

    signal_handlers: [VoidFn; SIGNAL_HANDLERS_LEN],
    custom_ops: *mut RpcCustomOp,

    tcp_methods: *mut c_void,

    http_type: *mut c_void,
    http_functions: *mut c_void,

    cron_subclass: c_int,
    precise_cron_subclass: c_int,
}

#[repr(C)]
pub(super) struct EngineState {
    settings_addr: libc::in_addr,
    do_not_open_port: c_int,
    epoll_wait_timeout: c_int,
    sfd: c_int,

    modules: u64,
    port: c_int,
    start_port: c_int,
    end_port: c_int,

    backlog: c_int,
    maxconn: c_int,
    required_io_threads: c_int,
    required_cpu_threads: c_int,
    required_tcp_cpu_threads: c_int,
    required_tcp_io_threads: c_int,

    aes_pwd_file: *mut c_char,

    f: *mut ServerFunctions,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(super) struct EventPreciseCron {
    next: *mut EventPreciseCron,
    prev: *mut EventPreciseCron,
    wakeup: Option<unsafe extern "C" fn(*mut EventPreciseCron)>,
}

unsafe extern "C" {
    static mut engine_state: *mut EngineState;
    static mut precise_now_diff: c_double;
    static mut server_ipv6: [u8; 16];
    static mut username: *const c_char;
    static mut groupname: *const c_char;
    static mut progname: *const c_char;
    static mut local_progname: *mut c_char;
    static mut start_time: c_int;
    static mut optind: c_int;
    static mut optarg: *mut c_char;
    static mut epoll_sleep_ns: c_int;
    static mut daemonize: c_int;
    static mut ct_http_server: u8;
    static mut PID: ProcessId;

    static mut precise_cron_events: EventPreciseCron;

    fn kprintf(format: *const c_char, ...);
    fn mtproxy_ffi_engine_now_value() -> c_int;
    fn mtproxy_ffi_engine_precise_now_value() -> c_double;
    static mut verbosity: c_int;

    fn engine_set_tcp_methods(f: *mut c_void);
    fn mtproxy_ffi_engine_check_conn_functions_bridge(conn_type: *mut c_void) -> c_int;
    fn engine_set_http_fallback(http_type: *mut c_void, http_functions: *mut c_void);
    fn add_builtin_parse_options();
    fn parse_engine_options_long(argc: c_int, argv: *mut *mut c_char) -> c_int;
    fn rust_sf_register_parse_option_ex_or_die(
        name: *const c_char,
        arg: c_int,
        val: c_int,
        flags: c_uint,
        func: ParseOptionFn,
        help: *const c_char,
    );
    fn mtproxy_ffi_engine_usage_bridge();
    fn engine_tl_init(
        parse: ParseFn,
        stat: Option<unsafe extern "C" fn(*mut c_void)>,
        get_op: GetOpFn,
        timeout: c_double,
        name: *const c_char,
    );
    fn init_epoll();
    fn engine_rpc_stats(tlio_out: *mut c_void);

    fn default_parse_extra_args(argc: c_int, argv: *mut *mut c_char);
    fn default_close_network_sockets();
    fn sigint_handler(sig: c_int);
    fn sigterm_handler(sig: c_int);
    fn empty_signal_handler(sig: c_int);
    fn sigint_immediate_handler(sig: c_int);
    fn sigterm_immediate_handler(sig: c_int);
    fn set_debug_handlers();
    fn signal_check_pending(sig: c_int) -> c_int;
    fn quiet_signal_handler(sig: c_int);
    fn default_signal_handler(sig: c_int);
    fn reopen_logs_ext(is_slave_mode: c_int);

    fn engine_do_open_port();
    fn raise_file_rlimit(maxfiles: c_int) -> c_int;
    fn tcp_set_max_connections(maxconn: c_int);
    fn aes_load_pwd_file(pathname: *const c_char) -> c_int;
    fn change_user_group(new_username: *const c_char, new_groupname: *const c_char) -> c_int;
    fn try_open_port_range(
        start_port: c_int,
        end_port: c_int,
        mod_port: c_int,
        rem_port: c_int,
        quit_on_fail: c_int,
    ) -> c_int;
    fn get_port_mod() -> c_int;
    fn init_server_PID(ip: c_uint, port: c_int);
    fn get_my_ipv4() -> c_uint;
    fn get_my_ipv6(ipv6: *mut u8) -> c_int;
    fn init_msg_buffers(max_buffer_bytes: c_long) -> c_int;
    fn init_async_jobs() -> c_int;
    fn create_new_job_class(job_class: c_int, min_threads: c_int, max_threads: c_int) -> c_int;
    fn create_main_thread_pipe();
    fn alloc_timer_manager(thread_class: c_int) -> Job;
    fn notification_event_job_create();
    fn tcp_set_default_rpc_flags(mask: c_uint, flags: c_int);
    fn get_utime_monotonic() -> c_double;
    fn get_double_time() -> c_double;
    fn drand48_j() -> c_double;
    fn update_all_thread_stats();
    fn init_listening_connection(fd: c_int, type_: *mut c_void, extra: *mut c_void) -> c_int;
    fn init_listening_tcpv6_connection(
        fd: c_int,
        type_: *mut c_void,
        extra: *mut c_void,
        mode: c_int,
    ) -> c_int;
    #[allow(clashing_extern_declarations)]
    fn epoll_sethandler(
        fd: c_int,
        prio: c_int,
        handler: Option<unsafe extern "C" fn(c_int, *mut c_void, *mut c_void) -> c_int>,
        data: *mut c_void,
    ) -> c_int;
    fn epoll_insert(fd: c_int, flags: c_int) -> c_int;
    fn try_open_port(port: c_int, quit_on_fail: c_int) -> c_int;
    fn sb_init(sb: *mut StatsBuffer, buff: *mut c_char, size: c_int);
    fn tl_store_stats(tlio_out: *mut c_void, s: *const c_char, raw: c_int) -> c_int;

    fn engine_process_signals() -> c_int;
    fn free_later_act();

    fn engine_server_init();
    fn register_custom_op_cb(op: c_uint, func: CustomOpFn);
    fn mtproxy_ffi_engine_rpc_custom_op_clear();
    fn engine_work_rpc_req_result(tlio_in: *mut c_void, params: *mut c_void);
    #[allow(clashing_extern_declarations)]
    fn create_async_job(
        run_job: JobExecuteFn,
        job_signals: u64,
        job_subclass: c_int,
        custom_bytes: c_int,
        job_type: u64,
        parent_job_tag_int: c_int,
        parent_job: Job,
    ) -> Job;
    fn schedule_job(job_tag_int: c_int, job: Job) -> c_int;
    fn job_timer_check(job: Job) -> c_int;
    fn job_timer_alloc(thread_class: c_int, alarm: JobTimerWakeupFn, extra: *mut c_void) -> Job;
    fn job_timer_insert(job: Job, timeout: c_double);
    fn job_incref(job: Job) -> Job;
    #[allow(clashing_extern_declarations)]
    fn unlock_job(job_tag_int: c_int, job: *mut crate::AsyncJob) -> c_int;
    fn epoll_work(timeout: c_int) -> c_int;
    fn interrupt_signal_raised() -> c_int;
    fn run_pending_main_jobs() -> c_int;
    fn job_signal(job_tag_int: c_int, job: Job, signo: c_int);

    fn ksignal(sig: c_int, handler: KsignalHandler);
}

static mut LAST_CRON_TIME: c_int = 0;
static mut ENGINE_STATS_DATA_BUF: [c_char; DATA_BUF_SIZE + 1] = [0; DATA_BUF_SIZE + 1];

#[inline]
const fn sig2int(sig: c_int) -> u64 {
    if sig == OUR_SIGRTMAX {
        1
    } else {
        1_u64 << (sig as u32)
    }
}

#[inline]
const fn default_signal_mask() -> u64 {
    sig2int(libc::SIGHUP)
        | sig2int(libc::SIGUSR1)
        | sig2int(OUR_SIGRTMAX)
        | sig2int(OUR_SIGRTMAX - 1)
        | sig2int(OUR_SIGRTMAX - 4)
        | sig2int(OUR_SIGRTMAX - 8)
        | sig2int(OUR_SIGRTMAX - 9)
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
const fn ip_octet_1(ip: c_uint) -> c_int {
    ((ip >> 24) & 0xff) as c_int
}

#[inline]
const fn ip_octet_2(ip: c_uint) -> c_int {
    ((ip >> 16) & 0xff) as c_int
}

#[inline]
const fn ip_octet_3(ip: c_uint) -> c_int {
    ((ip >> 8) & 0xff) as c_int
}

#[inline]
const fn ip_octet_4(ip: c_uint) -> c_int {
    (ip & 0xff) as c_int
}

#[inline]
unsafe fn engine_multithread_enabled(e: *const EngineState) -> bool {
    !e.is_null() && (unsafe { (*e).modules & ENGINE_ENABLE_MULTITHREAD }) != 0
}

#[inline]
unsafe fn engine_tcp_enabled(e: *const EngineState) -> bool {
    !e.is_null() && (unsafe { (*e).modules & ENGINE_ENABLE_TCP }) != 0
}

#[inline]
unsafe fn engine_ipv6_enabled(e: *const EngineState) -> bool {
    !e.is_null() && (unsafe { (*e).modules & ENGINE_ENABLE_IPV6 }) != 0
}

#[inline]
unsafe fn engine_slave_mode_enabled() -> bool {
    !unsafe { engine_state }.is_null()
        && (unsafe { (*engine_state).modules & ENGINE_ENABLE_SLAVE_MODE }) != 0
}

unsafe extern "C" fn rust_default_nop() {}

unsafe extern "C" fn rust_default_parse_option(_: c_int) -> c_int {
    -1
}

unsafe extern "C" fn rust_default_sighup() {}

unsafe extern "C" fn rust_default_sigusr1() {
    unsafe {
        reopen_logs_ext(engine_slave_mode_enabled() as c_int);
    }
}

unsafe extern "C" fn rust_default_sigrtmax_9() {}

unsafe extern "C" fn rust_default_sigrtmax_8() {}

unsafe extern "C" fn rust_default_sigrtmax_4() {}

unsafe extern "C" fn rust_default_sigrtmax_1() {}

unsafe extern "C" fn rust_default_sigrtmax() {}

unsafe extern "C" fn rust_parse_option_engine(val: c_int) -> c_int {
    let e = unsafe { engine_state };
    if e.is_null() {
        return -1;
    }

    let optarg_value = if unsafe { optarg }.is_null() {
        None
    } else {
        Some(unsafe { libc::atoi(optarg) })
    };

    let decision = mtproxy_core::runtime::engine::engine_parse_option_decision(val, optarg_value);
    match decision {
        mtproxy_core::runtime::engine::EngineParseOptionDecision::Reject => -1,
        mtproxy_core::runtime::engine::EngineParseOptionDecision::SetRequiredCpuThreads(v) => {
            unsafe {
                (*e).required_cpu_threads = v;
            }
            0
        }
        mtproxy_core::runtime::engine::EngineParseOptionDecision::SetRequiredIoThreads(v) => {
            unsafe {
                (*e).required_io_threads = v;
            }
            0
        }
        mtproxy_core::runtime::engine::EngineParseOptionDecision::SetRequiredTcpCpuThreads(v) => {
            unsafe {
                (*e).required_tcp_cpu_threads = v;
            }
            0
        }
        mtproxy_core::runtime::engine::EngineParseOptionDecision::SetRequiredTcpIoThreads(v) => {
            unsafe {
                (*e).required_tcp_io_threads = v;
            }
            0
        }
        mtproxy_core::runtime::engine::EngineParseOptionDecision::SetMultithread {
            enable,
            set_epoll_sleep_ns,
        } => {
            unsafe {
                if enable {
                    (*e).modules |= ENGINE_ENABLE_MULTITHREAD;
                } else {
                    (*e).modules &= !ENGINE_ENABLE_MULTITHREAD;
                }
                if set_epoll_sleep_ns {
                    epoll_sleep_ns =
                        mtproxy_core::runtime::engine::ENGINE_EPOLL_SLEEP_NS_MULTITHREAD;
                }
            }
            0
        }
    }
}

#[inline]
unsafe fn vkprintf_no_args(level: c_int, format: *const c_char) {
    unsafe {
        if level <= verbosity {
            kprintf(format);
        }
    }
}

#[inline]
unsafe fn vkprintf_pipe_close(level: c_int, format: *const c_char, fd: c_int) {
    unsafe {
        if level <= verbosity {
            kprintf(format, CREATE_PIPE_FUNC_NAME.as_ptr().cast::<c_char>(), fd);
        }
    }
}

unsafe fn check_signal_handler(
    f: *mut ServerFunctions,
    sig: c_int,
    default_f: unsafe extern "C" fn(),
) {
    let sig_u = usize::try_from(sig).unwrap_or(usize::MAX);
    if sig_u >= SIGNAL_HANDLERS_LEN {
        return;
    }

    if unsafe {
        ((*f).allowed_signals & sig2int(sig)) != 0 && (*f).signal_handlers[sig_u].is_none()
    } {
        unsafe {
            (*f).signal_handlers[sig_u] = Some(default_f);
        }
    }
}

pub(super) unsafe extern "C" fn default_cron_impl() {
    let new_precise_now_diff = unsafe { get_utime_monotonic() - get_double_time() };
    unsafe {
        precise_now_diff = precise_now_diff * 0.99 + 0.01 * new_precise_now_diff;
    }
}

pub(super) unsafe fn set_signals_handlers_impl() {
    unsafe {
        ksignal(libc::SIGINT, Some(sigint_immediate_handler));
        ksignal(libc::SIGTERM, Some(sigterm_immediate_handler));
        set_debug_handlers();
    }
}

pub(super) unsafe fn engine_set_epoll_wait_timeout_impl(epoll_wait_timeout: c_int) {
    assert!((1..=1000).contains(&epoll_wait_timeout));
    let e = unsafe { engine_state };
    assert!(!e.is_null());
    unsafe {
        (*e).epoll_wait_timeout = epoll_wait_timeout;
    }
}

pub(super) unsafe fn precise_cron_function_insert_impl(ev: *mut EventPreciseCron) {
    assert!(!ev.is_null());
    let sentinel = ptr::addr_of_mut!(precise_cron_events);
    unsafe {
        (*ev).next = sentinel;
        (*ev).prev = (*sentinel).prev;
        (*(*ev).next).prev = ev;
        (*(*ev).prev).next = ev;
    }
}

pub(super) unsafe fn precise_cron_function_remove_impl(ev: *mut EventPreciseCron) {
    assert!(!ev.is_null());
    unsafe {
        (*(*ev).next).prev = (*ev).prev;
        (*(*ev).prev).next = (*ev).next;
        (*ev).prev = ptr::null_mut();
        (*ev).next = ptr::null_mut();
    }
}

pub(super) unsafe extern "C" fn update_job_stats_gw_impl(_ex: *mut c_void) -> c_double {
    unsafe {
        update_all_thread_stats();
        10.0 + mtproxy_ffi_engine_precise_now_value()
    }
}

pub(super) unsafe extern "C" fn precise_cron_job_run_impl(
    job: Job,
    op: c_int,
    _jt: *mut c_void,
) -> c_int {
    if op != JS_RUN && op != JS_ALARM {
        return JOB_ERROR;
    }
    if op == JS_ALARM && unsafe { job_timer_check(job) } == 0 {
        return 0;
    }

    unsafe {
        do_precise_cron_impl();
        job_timer_insert(
            job,
            mtproxy_ffi_engine_precise_now_value() + 0.001 * (1.0 + drand48_j()),
        );
    }
    0
}

pub(super) unsafe extern "C" fn terminate_job_run_impl(
    _job: Job,
    op: c_int,
    _jt: *mut c_void,
) -> c_int {
    if op != JS_RUN {
        return JOB_ERROR;
    }

    let e = unsafe { engine_state };
    assert!(!e.is_null());
    let f = unsafe { (*e).f };
    assert!(!f.is_null());

    unsafe {
        if let Some(on_exit) = (*f).on_exit {
            on_exit();
        }
        server_exit_impl();
        libc::exit(0);
    }
}

pub(super) unsafe extern "C" fn default_get_op_impl(tlio_in: *mut c_void) -> c_int {
    unsafe { crate::tl_parse::abi::mtproxy_ffi_tl_fetch_lookup_int(tlio_in.cast()) }
}

unsafe fn raise_file_limit_impl(maxconn: c_int) {
    let mut maxconn_local = maxconn;
    if unsafe { libc::getuid() } != 0 {
        let mut rlim: libc::rlimit = unsafe { zeroed() };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } < 0 {
            unsafe {
                kprintf(RAISE_FILE_RLIMIT_FAIL_FMT.as_ptr().cast());
                libc::exit(1);
            }
        }

        let reserve_gap = RAISE_FILE_GAP as libc::rlim_t;
        let limit_without_gap = if rlim.rlim_cur > reserve_gap {
            rlim.rlim_cur - reserve_gap
        } else {
            0
        };
        if (maxconn_local as libc::rlim_t) > limit_without_gap {
            maxconn_local = limit_without_gap as c_int;
        }
        unsafe {
            tcp_set_max_connections(maxconn_local);
        }
    } else if unsafe { raise_file_rlimit(maxconn_local + RAISE_FILE_GAP) } < 0 {
        unsafe {
            kprintf(
                FATAL_RAISE_FILE_LIMIT_FMT.as_ptr().cast(),
                maxconn_local + RAISE_FILE_GAP,
            );
            libc::exit(1);
        }
    }
}

pub(super) unsafe fn create_main_thread_pipe_impl(
    pipe_read_end: *mut c_int,
    pipe_write_end: *mut c_int,
) {
    assert!(!pipe_read_end.is_null());
    assert!(!pipe_write_end.is_null());

    if unsafe { *pipe_read_end > 0 } {
        unsafe {
            vkprintf_pipe_close(
                2,
                CREATE_PIPE_READ_CLOSE_FMT.as_ptr().cast(),
                *pipe_read_end,
            );
            libc::close(*pipe_read_end);
        }
    }
    if unsafe { *pipe_write_end > 0 } {
        unsafe {
            vkprintf_pipe_close(
                2,
                CREATE_PIPE_WRITE_CLOSE_FMT.as_ptr().cast(),
                *pipe_write_end,
            );
            libc::close(*pipe_write_end);
        }
    }

    let mut pipefd = [0_i32; 2];
    let rc = unsafe { libc::pipe2(pipefd.as_mut_ptr(), libc::O_NONBLOCK) };
    assert!(rc >= 0);
    unsafe {
        *pipe_read_end = pipefd[0];
        *pipe_write_end = pipefd[1];
    }
}

pub(super) unsafe fn wakeup_main_thread_impl(pipe_write_end: c_int) {
    if pipe_write_end == 0 {
        return;
    }
    let x: c_int = 0;
    let r = unsafe {
        libc::write(
            pipe_write_end,
            (&x as *const c_int).cast::<c_void>(),
            size_of::<c_int>(),
        )
    };
    if r < 0 {
        let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        assert!(err == libc::EINTR || err == libc::EAGAIN);
    }
}

unsafe extern "C" fn engine_epoll_nop(fd: c_int, _data: *mut c_void, _ev: *mut c_void) -> c_int {
    let mut x = [0_i32; 100];
    loop {
        let r = unsafe {
            libc::read(
                fd,
                x.as_mut_ptr().cast::<c_void>(),
                (x.len() * size_of::<c_int>()) as libc::size_t,
            )
        };
        if r != (x.len() * size_of::<c_int>()) as isize {
            break;
        }
    }
    EVA_CONTINUE
}

pub(super) unsafe fn server_init_impl(
    listen_connection_type: *mut c_void,
    listen_connection_extra: *mut c_void,
    pipe_read_end: c_int,
) {
    let e = unsafe { engine_state };
    assert!(!e.is_null());
    let f = unsafe { (*e).f };
    assert!(!f.is_null());

    unsafe {
        init_epoll();
        epoll_sethandler(pipe_read_end, 0, Some(engine_epoll_nop), ptr::null_mut());
        epoll_insert(pipe_read_end, EVT_READ | EVT_LEVEL);
    }

    if unsafe { daemonize } != 0 {
        unsafe {
            libc::setsid();
            reopen_logs_ext(engine_slave_mode_enabled() as c_int);
        }
    }

    let listen_plan = mtproxy_core::runtime::engine::engine_server_listen_plan(
        unsafe { (*e).do_not_open_port != 0 },
        unsafe { (*e).port },
        unsafe { (*e).sfd },
        unsafe { engine_tcp_enabled(e) },
        unsafe { engine_ipv6_enabled(e) },
    );

    match listen_plan {
        mtproxy_core::runtime::engine::EngineServerListenPlan::Skip => {}
        mtproxy_core::runtime::engine::EngineServerListenPlan::FatalPortUndefined => unsafe {
            kprintf(FATAL_PORT_UNDEFINED_FMT.as_ptr().cast());
            libc::exit(1);
        },
        mtproxy_core::runtime::engine::EngineServerListenPlan::OpenAndInit {
            open_socket,
            init_listener,
            ipv6_listener,
        } => {
            if open_socket {
                assert!(unsafe { try_open_port((*e).port, 1) } >= 0);
            }
            if init_listener {
                if ipv6_listener {
                    assert!(
                        unsafe {
                            init_listening_tcpv6_connection(
                                (*e).sfd,
                                listen_connection_type,
                                listen_connection_extra,
                                SM_IPV6,
                            )
                        } >= 0
                    );
                } else {
                    assert!(
                        unsafe {
                            init_listening_connection(
                                (*e).sfd,
                                listen_connection_type,
                                listen_connection_extra,
                            )
                        } >= 0
                    );
                }
            }
        }
    }

    unsafe {
        ksignal(libc::SIGINT, Some(sigint_handler));
        ksignal(libc::SIGTERM, Some(sigterm_handler));
        ksignal(libc::SIGPIPE, Some(empty_signal_handler));
        ksignal(libc::SIGPOLL, Some(empty_signal_handler));
    }

    if unsafe { daemonize } != 0 {
        unsafe {
            ksignal(libc::SIGHUP, Some(default_signal_handler));
        }
    }
}

pub(super) unsafe fn server_exit_impl() {
    let e = unsafe { engine_state };
    assert!(!e.is_null());
    let f = unsafe { (*e).f };
    assert!(!f.is_null());

    unsafe {
        if let Some(close_net_sockets) = (*f).close_net_sockets {
            close_net_sockets();
        }

        if signal_check_pending(libc::SIGTERM) != 0 {
            kprintf(TERMINATED_BY_SIGTERM_FMT.as_ptr().cast());
        } else if signal_check_pending(libc::SIGINT) != 0 {
            kprintf(TERMINATED_BY_SIGINT_FMT.as_ptr().cast());
        }
    }
}

pub(super) unsafe fn engine_prepare_stats_impl() -> c_int {
    if unsafe { engine_state }.is_null() {
        return 0;
    }

    let mut sb: StatsBuffer = unsafe { zeroed() };
    unsafe {
        sb_init(
            &mut sb,
            ptr::addr_of_mut!(ENGINE_STATS_DATA_BUF).cast::<c_char>(),
            DATA_BUF_SIZE as c_int,
        );
    }

    let f = unsafe { (*engine_state).f };
    if !f.is_null() {
        if let Some(prepare_stats) = unsafe { (*f).prepare_stats } {
            unsafe {
                prepare_stats((&mut sb as *mut StatsBuffer).cast::<c_void>());
            }
        }
    }

    sb.pos
}

pub(super) unsafe fn engine_rpc_stats_impl(tlio_out: *mut c_void) {
    unsafe {
        engine_prepare_stats_impl();
        tl_store_stats(
            tlio_out,
            ptr::addr_of!(ENGINE_STATS_DATA_BUF).cast::<c_char>(),
            0,
        );
    }
}

pub(super) unsafe fn engine_startup_impl(e: *mut EngineState, f: *mut ServerFunctions) {
    assert!(!e.is_null());
    assert!(!f.is_null());

    unsafe {
        (*e).f = f;
        (*e).modules = (ENGINE_DEFAULT_ENABLED_MODULES | (*f).default_modules)
            & !(*f).default_modules_disabled;
        (*e).backlog = DEFAULT_BACKLOG;
        tcp_set_default_rpc_flags(0xffff_ffff_u32, RPCF_USE_CRC32C);
        (*e).port = -1;

        precise_now_diff = get_utime_monotonic() - get_double_time();

        assert!(libc::SIGRTMAX() == OUR_SIGRTMAX);
        assert!(libc::SIGRTMAX() - libc::SIGRTMIN() >= 20);

        (*e).sfd = 0;
        (*e).epoll_wait_timeout = DEFAULT_EPOLL_WAIT_TIMEOUT;
        (*e).maxconn = MAX_CONNECTIONS;
    }

    unsafe {
        check_server_functions_impl();
    }
}

#[inline]
unsafe fn parse_option_engine_builtin(
    name: *const c_char,
    arg: c_int,
    val: c_int,
    help: *const c_char,
) {
    unsafe {
        rust_sf_register_parse_option_ex_or_die(
            name,
            arg,
            val,
            LONGOPT_JOBS_SET,
            Some(rust_parse_option_engine),
            help,
        );
    }
}

pub(super) unsafe fn engine_add_engine_parse_options_impl() {
    unsafe {
        parse_option_engine_builtin(
            OPTION_CPU_THREADS_NAME.as_ptr().cast(),
            REQUIRED_ARGUMENT,
            mtproxy_core::runtime::engine::ENGINE_OPT_CPU_THREADS,
            OPTION_CPU_THREADS_HELP.as_ptr().cast(),
        );
        parse_option_engine_builtin(
            OPTION_IO_THREADS_NAME.as_ptr().cast(),
            REQUIRED_ARGUMENT,
            mtproxy_core::runtime::engine::ENGINE_OPT_IO_THREADS,
            OPTION_IO_THREADS_HELP.as_ptr().cast(),
        );
        parse_option_engine_builtin(
            OPTION_MULTITHREAD_NAME.as_ptr().cast(),
            OPTIONAL_ARGUMENT,
            mtproxy_core::runtime::engine::ENGINE_OPT_MULTITHREAD,
            OPTION_MULTITHREAD_HELP.as_ptr().cast(),
        );
        parse_option_engine_builtin(
            OPTION_TCP_CPU_THREADS_NAME.as_ptr().cast(),
            REQUIRED_ARGUMENT,
            mtproxy_core::runtime::engine::ENGINE_OPT_TCP_CPU_THREADS,
            OPTION_TCP_CPU_THREADS_HELP.as_ptr().cast(),
        );
        parse_option_engine_builtin(
            OPTION_TCP_IO_THREADS_NAME.as_ptr().cast(),
            REQUIRED_ARGUMENT,
            mtproxy_core::runtime::engine::ENGINE_OPT_TCP_IO_THREADS,
            OPTION_TCP_IO_THREADS_HELP.as_ptr().cast(),
        );
    }
}

pub(super) unsafe fn default_parse_option_func_impl(a: c_int) -> c_int {
    let e = unsafe { engine_state };
    if e.is_null() {
        return -1;
    }
    let f = unsafe { (*e).f };
    if f.is_null() {
        return -1;
    }
    match unsafe { (*f).parse_option } {
        Some(parse_option) => unsafe { parse_option(a) },
        None => -1,
    }
}

pub(super) unsafe fn default_parse_extra_args_impl(argc: c_int, _argv: *mut *mut c_char) {
    if argc != 0 {
        unsafe {
            vkprintf_no_args(0, EXTRA_ARGS_FMT.as_ptr().cast());
            mtproxy_ffi_engine_usage_bridge();
        }
    }
}

pub(super) unsafe fn engine_init_impl(pwd_filename: *const c_char, do_not_open_port: c_int) {
    let e = unsafe { engine_state };
    assert!(!e.is_null());

    if mtproxy_core::runtime::engine::engine_init_open_plan(do_not_open_port != 0)
        == mtproxy_core::runtime::engine::EngineInitOpenPlan::RunPreOpen
    {
        unsafe { engine_do_open_port() };
    }

    unsafe {
        raise_file_limit_impl((*e).maxconn);
    }

    let aes_load_res = unsafe { aes_load_pwd_file(pwd_filename) };
    if aes_load_res < 0
        && (aes_load_res != AES_LOAD_PWD_FILE_OPTIONAL_ERROR || !pwd_filename.is_null())
    {
        unsafe {
            kprintf(FATAL_CANNOT_LOAD_SECRET_FMT.as_ptr().cast(), pwd_filename);
            libc::exit(1);
        }
    }

    if unsafe { change_user_group(username, groupname) } < 0 {
        let username_str = if unsafe { username }.is_null() {
            NONE_STR.as_ptr().cast()
        } else {
            unsafe { username }
        };
        unsafe {
            kprintf(FATAL_CANNOT_CHANGE_USER_FMT.as_ptr().cast(), username_str);
            libc::exit(1);
        }
    }

    if mtproxy_core::runtime::engine::engine_init_port_range_plan(
        do_not_open_port != 0,
        unsafe { (*e).port },
        unsafe { (*e).start_port },
        unsafe { (*e).end_port },
    ) == mtproxy_core::runtime::engine::EngineInitPortRangePlan::TryRange
    {
        unsafe {
            (*e).port = try_open_port_range(
                (*e).start_port,
                (*e).end_port,
                PORT_RANGE_MOD,
                get_port_mod(),
                1,
            );
            assert!((*e).port >= 0);
        }
    }

    let mut ipv4: c_uint = 0;
    let bind_plan = mtproxy_core::runtime::engine::engine_bind_ipv4_plan(c_uint::from_be(unsafe {
        (*e).settings_addr.s_addr
    }));
    match bind_plan {
        mtproxy_core::runtime::engine::EngineBindIpv4Plan::UseAuto => {}
        mtproxy_core::runtime::engine::EngineBindIpv4Plan::UseProvided(addr) => {
            ipv4 = addr;
        }
        mtproxy_core::runtime::engine::EngineBindIpv4Plan::RejectProvided(addr) => unsafe {
            kprintf(
                BAD_BINDED_IP_FMT.as_ptr().cast(),
                ip_octet_1(addr),
                ip_octet_2(addr),
                ip_octet_3(addr),
                ip_octet_4(addr),
            );
        },
    }

    unsafe {
        init_server_PID(if ipv4 != 0 { ipv4 } else { get_my_ipv4() }, (*e).port);
        get_my_ipv6(ptr::addr_of_mut!(server_ipv6).cast());
        init_msg_buffers(0);

        init_async_jobs();

        let mut nc = (*e).required_io_threads;
        if nc <= 0 {
            nc = DEFAULT_IO_JOB_THREADS;
        }
        create_new_job_class(JC_IO, nc, nc);

        nc = (*e).required_cpu_threads;
        if nc <= 0 {
            nc = DEFAULT_CPU_JOB_THREADS;
        }
        create_new_job_class(JC_CPU, nc, nc);

        if engine_multithread_enabled(e) {
            nc = (*e).required_tcp_cpu_threads;
            if nc <= 0 {
                nc = 1;
            }
            create_new_job_class(JC_CONNECTION, nc, nc);

            nc = (*e).required_tcp_io_threads;
            if nc <= 0 {
                nc = 1;
            }
            create_new_job_class(JC_CONNECTION_IO, nc, nc);
            create_new_job_class(JC_ENGINE, 1, 1);
        }

        create_main_thread_pipe();
        alloc_timer_manager(JC_EPOLL);
        notification_event_job_create();
    }

    let pid = unsafe { PID };
    unsafe {
        kprintf(
            STARTED_AS_FMT.as_ptr().cast(),
            ip_octet_1(pid.ip),
            ip_octet_2(pid.ip),
            ip_octet_3(pid.ip),
            ip_octet_4(pid.ip),
            pid.port as c_int,
            pid.pid as c_int,
            pid.utime,
        );
    }
}

pub(super) unsafe fn check_server_functions_impl() {
    let e = unsafe { engine_state };
    assert!(!e.is_null());
    let f = unsafe { (*e).f };
    assert!(!f.is_null());

    unsafe {
        (*f).allowed_signals =
            ((*f).allowed_signals | default_signal_mask()) & !(*f).forbidden_signals;

        check_signal_handler(f, libc::SIGHUP, rust_default_sighup);
        check_signal_handler(f, libc::SIGUSR1, rust_default_sigusr1);
        check_signal_handler(f, OUR_SIGRTMAX - 9, rust_default_sigrtmax_9);
        check_signal_handler(f, OUR_SIGRTMAX - 8, rust_default_sigrtmax_8);
        check_signal_handler(f, OUR_SIGRTMAX - 4, rust_default_sigrtmax_4);
        check_signal_handler(f, OUR_SIGRTMAX - 1, rust_default_sigrtmax_1);
        check_signal_handler(f, OUR_SIGRTMAX, rust_default_sigrtmax);

        if (*f).close_net_sockets.is_none() {
            (*f).close_net_sockets = Some(default_close_network_sockets);
        }
        if (*f).cron.is_none() {
            (*f).cron = Some(default_cron_impl);
        }
        if (*f).parse_option.is_none() {
            (*f).parse_option = Some(rust_default_parse_option);
        }
        if (*f).prepare_parse_options.is_none() {
            (*f).prepare_parse_options = Some(rust_default_nop);
        }
        if (*f).pre_init.is_none() {
            (*f).pre_init = Some(rust_default_nop);
        }
        if (*f).pre_start.is_none() {
            (*f).pre_start = Some(rust_default_nop);
        }
        if (*f).parse_extra_args.is_none() {
            (*f).parse_extra_args = Some(default_parse_extra_args);
        }
        if (*f).pre_loop.is_none() {
            (*f).pre_loop = Some(rust_default_nop);
        }

        if (*f).epoll_timeout == 0 {
            (*f).epoll_timeout = EPOLL_TIMEOUT_DEFAULT;
        }
        if (*f).aio_timeout == 0.0 {
            (*f).aio_timeout = AIO_TIMEOUT_DEFAULT;
        }
        if (*f).get_op.is_none() {
            (*f).get_op = Some(default_get_op_impl);
        }

        for sig in 1..=OUR_SIGRTMAX {
            if ((*f).allowed_signals & sig2int(sig)) != 0 {
                let handler: KsignalHandler = if sig == libc::SIGCHLD {
                    Some(quiet_signal_handler as unsafe extern "C" fn(c_int))
                } else {
                    Some(default_signal_handler as unsafe extern "C" fn(c_int))
                };
                ksignal(sig, handler);
            }
        }
    }
}

pub(super) unsafe fn do_precise_cron_impl() {
    let e = unsafe { engine_state };
    assert!(!e.is_null());
    let f = unsafe { (*e).f };
    assert!(!f.is_null());

    unsafe {
        engine_process_signals();

        let now_value = mtproxy_ffi_engine_now_value();

        if LAST_CRON_TIME != now_value {
            LAST_CRON_TIME = now_value;
            if let Some(cron) = (*f).cron {
                cron();
            }
        }

        if let Some(precise_cron) = (*f).precise_cron {
            precise_cron();
        }

        let sentinel = ptr::addr_of_mut!(precise_cron_events);
        if (*sentinel).next != sentinel {
            let mut ev = *sentinel;
            let ev_ptr: *mut EventPreciseCron = &mut ev;
            (*ev.next).prev = ev_ptr;
            (*ev.prev).next = ev_ptr;
            (*sentinel).next = sentinel;
            (*sentinel).prev = sentinel;

            while ev.next != ev_ptr {
                let current = ev.next;
                match (*current).wakeup {
                    Some(wakeup) => wakeup(current),
                    None => libc::abort(),
                }
                if current == ev.next {
                    precise_cron_function_remove_impl(current);
                    precise_cron_function_insert_impl(current);
                }
            }
        }

        free_later_act();
    }
}

unsafe fn register_custom_ops(f: *mut ServerFunctions) {
    let mut current = unsafe { (*f).custom_ops };
    while !current.is_null() {
        let op = unsafe { ptr::read_unaligned(current) };
        if op.op == 0 {
            break;
        }
        unsafe {
            register_custom_op_cb(op.op, op.func);
            current = current.add(1);
        }
    }
}

pub(super) unsafe fn default_engine_server_start_impl() {
    let e = unsafe { engine_state };
    assert!(!e.is_null());
    let f = unsafe { (*e).f };
    assert!(!f.is_null());

    unsafe {
        engine_server_init();

        vkprintf_no_args(1, SERVER_STARTED_FMT.as_ptr().cast());

        mtproxy_ffi_engine_rpc_custom_op_clear();
        register_custom_op_cb(RPC_REQ_RESULT, Some(engine_work_rpc_req_result));
        register_custom_ops(f);

        let precise_cron_job = create_async_job(
            Some(precise_cron_job_run_impl),
            jsc_allow(JC_ENGINE, JS_RUN)
                | jsc_allow(JC_ENGINE, JS_ALARM)
                | jsc_allow(JC_ENGINE, JS_FINISH),
            (*f).cron_subclass,
            size_of::<PreciseCronJobExtra>() as c_int,
            JT_HAVE_TIMER,
            JOB_REF_TAG,
            ptr::null_mut(),
        );
        job_incref(precise_cron_job);
        schedule_job(JOB_REF_TAG, precise_cron_job);

        let update_job_stats =
            job_timer_alloc(JC_MAIN, Some(update_job_stats_gw_impl), ptr::null_mut());
        job_timer_insert(update_job_stats, 1.0);

        if let Some(pre_loop) = (*f).pre_loop {
            pre_loop();
        }

        let terminate_job = create_async_job(
            Some(terminate_job_run_impl),
            jsc_allow(JC_ENGINE, JS_RUN) | jsc_allow(JC_ENGINE, JS_FINISH),
            -1,
            0,
            0,
            JOB_REF_TAG,
            ptr::null_mut(),
        );
        unlock_job(
            JOB_REF_TAG,
            job_incref(terminate_job).cast::<crate::AsyncJob>(),
        );

        vkprintf_no_args(0, MAIN_LOOP_FMT.as_ptr().cast());

        loop {
            let timeout = if engine_multithread_enabled(e) {
                (*e).epoll_wait_timeout
            } else {
                1
            };
            epoll_work(timeout);
            if interrupt_signal_raised() != 0 {
                if let Some(on_waiting_exit) = (*f).on_waiting_exit {
                    loop {
                        let t = on_waiting_exit() as libc::useconds_t;
                        if t <= 0 {
                            break;
                        }
                        libc::usleep(t);
                        run_pending_main_jobs();
                    }
                }
                if !terminate_job.is_null() {
                    job_signal(JOB_REF_TAG, terminate_job, JS_RUN);
                    run_pending_main_jobs();
                }
                break;
            }

            run_pending_main_jobs();
        }

        libc::sleep(120);
        kprintf(DID_NOT_EXIT_FMT.as_ptr().cast());
        assert!(false);
    }
}

pub(super) unsafe fn default_main_impl(
    f: *mut ServerFunctions,
    argc: c_int,
    argv: *mut *mut c_char,
) -> c_int {
    assert!(!f.is_null());

    unsafe {
        set_signals_handlers_impl();
    }

    let e = unsafe { libc::calloc(1, size_of::<EngineState>()) }.cast::<EngineState>();
    assert!(!e.is_null());
    unsafe {
        engine_state = e;
    }

    unsafe {
        engine_startup_impl(e, f);
        engine_set_epoll_wait_timeout_impl((*f).epoll_timeout);
    }

    if unsafe { !(*f).tcp_methods.is_null() } {
        unsafe {
            engine_set_tcp_methods((*f).tcp_methods);
        }
    }

    if unsafe { !(*f).http_functions.is_null() } {
        let mut http_type = unsafe { (*f).http_type };
        if http_type.is_null() {
            http_type = ptr::addr_of_mut!(ct_http_server).cast();
        }
        unsafe {
            assert!(mtproxy_ffi_engine_check_conn_functions_bridge(http_type) >= 0);
            engine_set_http_fallback(http_type, (*f).http_functions);
        }
    }

    unsafe {
        kprintf(INVOKING_ENGINE_FMT.as_ptr().cast(), (*f).full_version_str);
    }

    let argv0 = if argv.is_null() {
        ptr::null_mut()
    } else {
        unsafe { *argv }
    };
    unsafe {
        progname = argv0.cast_const();
        local_progname = argv0;
    }

    unsafe {
        add_builtin_parse_options();
    }

    if let Some(prepare_parse_options) = unsafe { (*f).prepare_parse_options } {
        unsafe {
            prepare_parse_options();
        }
    }

    unsafe {
        parse_engine_options_long(argc, argv);
    }

    let optind_val = unsafe { optind };
    let args_ptr = if argv.is_null() || optind_val <= 0 {
        argv
    } else {
        unsafe { argv.add(optind_val as usize) }
    };
    if let Some(parse_extra_args) = unsafe { (*f).parse_extra_args } {
        unsafe {
            parse_extra_args(argc - optind_val, args_ptr);
        }
    }

    unsafe {
        (*e).do_not_open_port = ((*f).flags & ENGINE_NO_PORT) as c_int;
    }

    if let Some(pre_init) = unsafe { (*f).pre_init } {
        unsafe {
            pre_init();
        }
    }

    unsafe {
        engine_init_impl((*e).aes_pwd_file.cast_const(), (*e).do_not_open_port);
    }

    unsafe {
        vkprintf_no_args(3, COMMAND_LINE_PARSED_FMT.as_ptr().cast());
    }

    if let Some(pre_start) = unsafe { (*f).pre_start } {
        unsafe {
            pre_start();
        }
    }

    unsafe {
        start_time = libc::time(ptr::null_mut()) as c_int;
    }

    if let Some(run_script) = unsafe { (*f).run_script } {
        let rc = unsafe { run_script() };
        if rc >= 0 {
            return 0;
        }
        return -rc;
    }

    unsafe {
        engine_tl_init(
            (*f).parse_function,
            Some(engine_rpc_stats),
            (*f).get_op,
            (*f).aio_timeout,
            (*f).short_version_str,
        );
        init_epoll();
        default_engine_server_start_impl();
    }

    0
}
