//! FFI export surface for jobs runtime.

use super::core::*;
use core::ffi::c_void;
use core::mem;
use core::ptr;
use libc::pthread_attr_t;

const JOB_SUBCLASS_OFFSET: i32 = 3;
const JOB_THREAD_STACK_SIZE: usize = 4 << 20;

#[inline]
fn safe_div(x: f64, y: f64) -> f64 {
    if y > 0.0 { x / y } else { 0.0 }
}

#[inline]
const fn jss_fast(signo: i32) -> i32 {
    (0x0001_0000_u32 << (signo as u32)) as i32
}

#[inline]
const fn jf_queued_class(class: i32) -> i32 {
    1_i32 << class
}

#[inline]
fn max_double(lhs: f64, rhs: f64) -> f64 {
    if lhs > rhs { lhs } else { rhs }
}

#[no_mangle]
pub unsafe extern "C" fn jobs_enable_tokio_bridge() -> i32 {
    let rc = mtproxy_ffi_jobs_tokio_init();
    if rc < 0 {
        -1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn run_pending_main_jobs() -> i32 {
    // SAFETY: C runtime maintains per-thread job context.
    let thread = unsafe { jobs_get_this_job_thread_c_impl() };
    abort_if(thread.is_null());
    // SAFETY: checked above.
    let jt = unsafe { &mut *thread };
    abort_if(jt.thread_class != JOB_CLASS_MAIN);

    jt.status |= JTS_RUNNING;
    let drained = mtproxy_ffi_jobs_tokio_drain_main(
        Some(jobs_process_main_job_from_tokio),
        JOBS_DRAIN_UNLIMITED,
    );
    abort_if(drained < 0);
    jt.status &= !JTS_RUNNING;
    drained
}

#[no_mangle]
pub unsafe extern "C" fn job_change_signals(job: JobT, job_signals: u64) {
    abort_if(job.is_null());
    // SAFETY: checked above.
    let job_ref = unsafe { &mut *job };
    abort_if((job_ref.j_flags & JF_LOCKED) == 0);

    job_ref.j_status = (job_signals & 0xffff_001f_u64) as i32;
    job_ref.j_sigclass = (job_signals >> 32) as i32;
}

#[no_mangle]
pub unsafe extern "C" fn create_async_job_c_impl(
    run_job: JobExecuteFn,
    job_signals: u64,
    job_subclass: i32,
    custom_bytes: i32,
    job_type: u64,
    parent_job_tag_int: i32,
    parent_job: JobT,
) -> JobT {
    if !parent_job.is_null() && (job_signals & JSP_PARENT_WAKEUP) != 0 {
        // SAFETY: parent job pointer is validated by caller contract.
        unsafe {
            jobs_atomic_fetch_add_c_impl(&raw mut (*parent_job).j_children, 1);
        }
    }

    abort_if(custom_bytes < 0);
    let custom_bytes_usize = custom_bytes as usize;

    // SAFETY: C helper updates job stats and returns current job thread pointer.
    let thread = unsafe { jobs_prepare_async_create_c_impl(custom_bytes) };
    abort_if(thread.is_null());

    // SAFETY: returns sizeof(struct async_job) from C side.
    let header_size = unsafe { jobs_async_job_header_size_c_impl() };
    let alloc_size = header_size
        .checked_add(custom_bytes_usize)
        .and_then(|n| n.checked_add(64))
        .unwrap_or_else(|| {
            std::process::abort();
        });

    // SAFETY: libc allocator called with validated size.
    let p = unsafe { malloc(alloc_size).cast::<u8>() };
    abort_if(p.is_null());

    let align = ((64_usize.wrapping_sub((p as usize) & 63)) & 63) as i32;
    // SAFETY: within allocation bounds by construction.
    let job = unsafe { p.add(align as usize).cast::<AsyncJob>() };
    abort_if(((job as usize) & 63) != 0);

    // SAFETY: `job` points to newly allocated writable memory.
    unsafe {
        (*job).j_flags = JF_LOCKED;
        (*job).j_status = (job_signals & 0xffff_001f_u64) as i32;
        (*job).j_sigclass = (job_signals >> 32) as i32;
        (*job).j_refcnt = 1;
        (*job).j_error = 0;
        (*job).j_children = 0;
        (*job).j_custom_bytes = custom_bytes;
        (*job).j_thread = thread;
        (*job).j_align = align;
        (*job).j_execute = run_job;
        (*job).j_parent = parent_job;
        (*job).j_type = job_type as u32;
        (*job).j_subclass = job_subclass;
    }

    // SAFETY: custom tail starts right after struct header.
    let custom_ptr = unsafe { job.cast::<u8>().add(header_size) };
    // SAFETY: range is inside the allocated block and uniquely owned here.
    unsafe {
        ptr::write_bytes(custom_ptr, 0, custom_bytes_usize);
    }

    if (job_type & JT_HAVE_TIMER) != 0 {
        // SAFETY: freshly initialized job has timer payload area.
        unsafe { job_timer_init(job) };
    }
    if (job_type & JT_HAVE_MSG_QUEUE) != 0 {
        // SAFETY: freshly initialized job has message queue payload area.
        unsafe { job_message_queue_init(job) };
    }

    let _ = parent_job_tag_int;
    job
}

#[no_mangle]
pub unsafe extern "C" fn create_async_job(
    run_job: JobExecuteFn,
    job_signals: u64,
    job_subclass: i32,
    custom_bytes: i32,
    job_type: u64,
    parent_job_tag_int: i32,
    parent_job: JobT,
) -> JobT {
    // SAFETY: preserves the legacy C entrypoint ABI.
    unsafe {
        create_async_job_c_impl(
            run_job,
            job_signals,
            job_subclass,
            custom_bytes,
            job_type,
            parent_job_tag_int,
            parent_job,
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn notify_job_create(sig_class: i32) -> JobT {
    let custom_bytes = unsafe { jobs_notify_job_extra_size_c_impl() };
    abort_if(custom_bytes < 0);
    let signals = jsc_allow(sig_class, JS_RUN)
        | jsc_allow(sig_class, JS_ABORT)
        | jsc_allow(sig_class, JS_MSG)
        | jsc_allow(sig_class, JS_FINISH);
    unsafe {
        create_async_job(
            Some(notify_job_run),
            signals,
            0,
            custom_bytes,
            JT_HAVE_MSG_QUEUE,
            1,
            ptr::null_mut(),
        )
    }
}

#[no_mangle]
pub unsafe extern "C" fn schedule_job(job_tag_int: i32, job: JobT) -> i32 {
    abort_if(job.is_null());
    // SAFETY: checked above.
    let job_ref = unsafe { &mut *job };
    abort_if((job_ref.j_flags & JF_LOCKED) == 0);

    job_ref.j_flags |= JFS_SET_RUN;
    // SAFETY: mirrors C implementation; caller owns one job reference.
    unsafe { unlock_job(job_tag_int, job) }
}

#[no_mangle]
pub unsafe extern "C" fn job_signal_c_impl(job_tag_int: i32, job: JobT, signo: i32) {
    abort_if((signo as u32) > 7);
    // SAFETY: signal set computed from validated `signo`.
    unsafe {
        job_send_signals(job_tag_int, job, jfs_set(signo));
    }
}

#[no_mangle]
pub unsafe extern "C" fn job_decref_c_impl(job_tag_int: i32, job: JobT) {
    abort_if(job.is_null());
    // SAFETY: load/refcount updates use C atomics.
    let refcnt = unsafe { jobs_atomic_load_c_impl(&raw const (*job).j_refcnt) };
    if refcnt >= 2 {
        // SAFETY: same atomic primitive as C original (`__sync_fetch_and_add`).
        let prev = unsafe { jobs_atomic_fetch_add_c_impl(&raw mut (*job).j_refcnt, -1) };
        if prev != 1 {
            return;
        }
        // SAFETY: preserving C logic that restores visible value to 1.
        unsafe {
            jobs_atomic_store_c_impl(&raw mut (*job).j_refcnt, 1);
        }
    }
    let final_refcnt = unsafe { jobs_atomic_load_c_impl(&raw const (*job).j_refcnt) };
    abort_if(final_refcnt != 1);
    // SAFETY: forwards to normal signal path.
    unsafe {
        job_signal(job_tag_int, job, JS_FINISH);
    }
}

#[no_mangle]
pub unsafe extern "C" fn job_incref_c_impl(job: JobT) -> JobT {
    abort_if(job.is_null());
    // SAFETY: same atomic primitive as C original (`__sync_fetch_and_add`).
    unsafe {
        jobs_atomic_fetch_add_c_impl(&raw mut (*job).j_refcnt, 1);
    }
    job
}

#[no_mangle]
pub unsafe extern "C" fn job_signal(job_tag_int: i32, job: JobT, signo: i32) {
    // SAFETY: delegates to Rust-migrated core implementation.
    unsafe { job_signal_c_impl(job_tag_int, job, signo) };
}

#[no_mangle]
pub unsafe extern "C" fn job_decref(job_tag_int: i32, job: JobT) {
    // SAFETY: delegates to Rust-migrated core implementation.
    unsafe { job_decref_c_impl(job_tag_int, job) };
}

#[no_mangle]
pub unsafe extern "C" fn job_incref(job: JobT) -> JobT {
    // SAFETY: delegates to Rust-migrated core implementation.
    unsafe { job_incref_c_impl(job) }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_prepare_stat(sb: *mut StatsBuffer) -> i32 {
    if sb.is_null() {
        return -1;
    }

    let now = unsafe { time(ptr::null_mut()) } as i64;
    let uptime = (now - i64::from(unsafe { start_time })) as i32;
    let tm = unsafe { get_utime_monotonic() };

    let mut tot_recent_idle = [0.0_f64; JOB_CLASS_COUNT];
    let mut tot_recent_q = [0.0_f64; JOB_CLASS_COUNT];
    let mut tot_idle = [0.0_f64; JOB_CLASS_COUNT];
    let mut tot_threads = [0_i32; JOB_CLASS_COUNT];

    unsafe {
        tot_recent_idle[JC_MAIN as usize] = a_idle_time;
        tot_recent_q[JC_MAIN as usize] = a_idle_quotient;
        tot_idle[JC_MAIN as usize] = tot_idle_time;
    }

    let mut i = 0_i32;
    while i <= unsafe { max_job_thread_id } {
        let stat_ptr = unsafe { jobs_module_stat_array[i as usize] };
        if !stat_ptr.is_null() {
            let jt = unsafe { &JobThreads[i as usize] };
            abort_if(jt.id != i);
            let class = (jt.thread_class & JC_MASK) as usize;
            let stat = unsafe { &*stat_ptr };
            tot_recent_idle[class] += stat.a_idle_time;
            tot_recent_q[class] += stat.a_idle_quotient;
            tot_idle[class] += stat.tot_idle_time;
            if stat.locked_since != 0.0 {
                let dt = tm - stat.locked_since;
                tot_recent_idle[class] += dt;
                tot_recent_q[class] += dt;
                tot_idle[class] += dt;
            }
            tot_threads[class] += 1;
        }
        i += 1;
    }

    unsafe { sb_printf(sb, c"thread_average_idle_percent\t".as_ptr()) };
    let mut idx = 0_usize;
    while idx < JOB_CLASS_COUNT {
        if idx != 0 {
            unsafe { sb_printf(sb, c" ".as_ptr()) };
            if (idx & 3) == 0 {
                unsafe { sb_printf(sb, c" ".as_ptr()) };
            }
        }
        unsafe {
            sb_printf(
                sb,
                c"%.3f".as_ptr(),
                safe_div(tot_idle[idx], f64::from(uptime * tot_threads[idx])) * 100.0,
            );
        }
        idx += 1;
    }
    unsafe { sb_printf(sb, c"\n".as_ptr()) };

    unsafe { sb_printf(sb, c"thread_recent_idle_percent\t".as_ptr()) };
    let mut idx = 0_usize;
    while idx < JOB_CLASS_COUNT {
        if idx != 0 {
            unsafe { sb_printf(sb, c" ".as_ptr()) };
            if (idx & 3) == 0 {
                unsafe { sb_printf(sb, c" ".as_ptr()) };
            }
        }
        unsafe {
            sb_printf(
                sb,
                c"%.3f".as_ptr(),
                safe_div(tot_recent_idle[idx], tot_recent_q[idx]) * 100.0,
            );
        }
        idx += 1;
    }
    unsafe { sb_printf(sb, c"\n".as_ptr()) };

    unsafe { sb_printf(sb, c"tot_threads\t".as_ptr()) };
    let mut idx = 0_usize;
    while idx < JOB_CLASS_COUNT {
        if idx != 0 {
            unsafe { sb_printf(sb, c" ".as_ptr()) };
            if (idx & 3) == 0 {
                unsafe { sb_printf(sb, c" ".as_ptr()) };
            }
        }
        unsafe { sb_printf(sb, c"%d".as_ptr(), tot_threads[idx]) };
        idx += 1;
    }
    unsafe { sb_printf(sb, c"\n".as_ptr()) };

    let mut jb_cpu_load_u = [0.0_f64; JOB_CLASS_COUNT];
    let mut jb_cpu_load_s = [0.0_f64; JOB_CLASS_COUNT];
    let mut jb_cpu_load_t = [0.0_f64; JOB_CLASS_COUNT];
    let mut jb_cpu_load_ru = [0.0_f64; JOB_CLASS_COUNT];
    let mut jb_cpu_load_rs = [0.0_f64; JOB_CLASS_COUNT];
    let mut jb_cpu_load_rt = [0.0_f64; JOB_CLASS_COUNT];

    let mut i = 0_i32;
    while i <= unsafe { max_job_thread_id } {
        let stat_ptr = unsafe { jobs_module_stat_array[i as usize] };
        if !stat_ptr.is_null() {
            let jt = unsafe { &JobThreads[i as usize] };
            abort_if(jt.id != i);
            let class = (jt.thread_class & JC_MASK) as usize;
            let ts = unsafe { &JobThreadsStats[i as usize] };

            jb_cpu_load_u[class] += ts.tot_user as f64;
            jb_cpu_load_s[class] += ts.tot_sys as f64;
            jb_cpu_load_t[class] += (ts.tot_user + ts.tot_sys) as f64;

            jb_cpu_load_ru[class] += ts.recent_user as f64;
            jb_cpu_load_rs[class] += ts.recent_sys as f64;
            jb_cpu_load_rt[class] += (ts.recent_user + ts.recent_sys) as f64;
        }
        i += 1;
    }

    let mut tot_cpu_load_u = 0.0;
    let mut tot_cpu_load_s = 0.0;
    let mut tot_cpu_load_t = 0.0;
    let mut tot_cpu_load_ru = 0.0;
    let mut tot_cpu_load_rs = 0.0;
    let mut tot_cpu_load_rt = 0.0;
    let mut max_cpu_load_u = 0.0;
    let mut max_cpu_load_s = 0.0;
    let mut max_cpu_load_t = 0.0;
    let mut max_cpu_load_ru = 0.0;
    let mut max_cpu_load_rs = 0.0;
    let mut max_cpu_load_rt = 0.0;

    let mut i = 0_usize;
    while i < JOB_CLASS_COUNT {
        tot_cpu_load_u += jb_cpu_load_u[i];
        tot_cpu_load_s += jb_cpu_load_s[i];
        tot_cpu_load_t += jb_cpu_load_t[i];
        tot_cpu_load_ru += jb_cpu_load_ru[i];
        tot_cpu_load_rs += jb_cpu_load_rs[i];
        tot_cpu_load_rt += jb_cpu_load_rt[i];

        max_cpu_load_u = max_double(max_cpu_load_u, jb_cpu_load_u[i]);
        max_cpu_load_s = max_double(max_cpu_load_s, jb_cpu_load_s[i]);
        max_cpu_load_t = max_double(max_cpu_load_t, jb_cpu_load_t[i]);
        max_cpu_load_ru = max_double(max_cpu_load_ru, jb_cpu_load_ru[i]);
        max_cpu_load_rs = max_double(max_cpu_load_rs, jb_cpu_load_rs[i]);
        max_cpu_load_rt = max_double(max_cpu_load_rt, jb_cpu_load_rt[i]);
        i += 1;
    }

    let m_clk_to_hs = 100.0 / unsafe { sysconf(libc::_SC_CLK_TCK) as f64 };
    let m_clk_to_ts = 0.1 * m_clk_to_hs;

    let mut j = 0_i32;
    while j < 6 {
        let (title, b, d): (*const i8, &[f64; JOB_CLASS_COUNT], f64) = match j {
            0 => (c"thread_load_average_user\t".as_ptr(), &jb_cpu_load_u, f64::from(uptime)),
            1 => (c"thread_load_average_sys\t".as_ptr(), &jb_cpu_load_s, f64::from(uptime)),
            2 => (c"thread_load_average\t".as_ptr(), &jb_cpu_load_t, f64::from(uptime)),
            3 => (c"thread_load_recent_user\t".as_ptr(), &jb_cpu_load_ru, 10.0),
            4 => (c"thread_load_recent_sys\t".as_ptr(), &jb_cpu_load_rs, 10.0),
            _ => (c"thread_load_recent\t".as_ptr(), &jb_cpu_load_rt, 10.0),
        };
        unsafe { sb_printf(sb, title) };

        let mut i = 0_usize;
        while i < JOB_CLASS_COUNT {
            if i != 0 {
                unsafe { sb_printf(sb, c" ".as_ptr()) };
                if (i & 3) == 0 {
                    unsafe { sb_printf(sb, c" ".as_ptr()) };
                }
            }
            unsafe {
                sb_printf(
                    sb,
                    c"%.3f".as_ptr(),
                    safe_div(m_clk_to_hs * b[i], d * f64::from(tot_threads[i])),
                );
            }
            i += 1;
        }
        unsafe { sb_printf(sb, c"\n".as_ptr()) };
        j += 1;
    }

    unsafe {
        sb_printf(
            sb,
            c"load_average_user\t%.3f\nload_average_sys\t%.3f\nload_average_total\t%.3f\nload_recent_user\t%.3f\nload_recent_sys\t%.3f\nload_recent_total\t%.3f\nmax_average_user\t%.3f\nmax_average_sys\t%.3f\nmax_average_total\t%.3f\nmax_recent_user\t%.3f\nmax_recent_sys\t%.3f\nmax_recent_total\t%.3f\n".as_ptr(),
            safe_div(m_clk_to_hs * tot_cpu_load_u, f64::from(uptime)),
            safe_div(m_clk_to_hs * tot_cpu_load_s, f64::from(uptime)),
            safe_div(m_clk_to_hs * tot_cpu_load_t, f64::from(uptime)),
            m_clk_to_ts * tot_cpu_load_ru,
            m_clk_to_ts * tot_cpu_load_rs,
            m_clk_to_ts * tot_cpu_load_rt,
            safe_div(m_clk_to_hs * max_cpu_load_u, f64::from(uptime)),
            safe_div(m_clk_to_hs * max_cpu_load_s, f64::from(uptime)),
            safe_div(m_clk_to_hs * max_cpu_load_t, f64::from(uptime)),
            m_clk_to_ts * max_cpu_load_ru,
            m_clk_to_ts * max_cpu_load_rs,
            m_clk_to_ts * max_cpu_load_rt,
        );
    }

    let mut sum_job_timers_allocated = 0_i32;
    let mut sum_jobs_allocated_memory = 0_i64;
    let mut sum_timer_ops = 0_i64;
    let mut sum_timer_ops_scheduler = 0_i64;
    let mut i = 0_i32;
    while i <= unsafe { max_job_thread_id } {
        let stat_ptr = unsafe { jobs_module_stat_array[i as usize] };
        if !stat_ptr.is_null() {
            let stat = unsafe { &*stat_ptr };
            sum_job_timers_allocated += stat.job_timers_allocated;
            sum_jobs_allocated_memory += stat.jobs_allocated_memory;
            sum_timer_ops += stat.timer_ops;
            sum_timer_ops_scheduler += stat.timer_ops_scheduler;
        }
        i += 1;
    }
    unsafe {
        sb_printf(
            sb,
            c"job_timers_allocated\t%d\n".as_ptr(),
            sum_job_timers_allocated,
        )
    };

    let mut jb_running = [0_i32; JOB_CLASS_COUNT];
    let mut jb_active = 0_i32;
    let mut jb_created = 0_i64;
    let mut i = 1_i32;
    while i <= unsafe { max_job_thread_id } {
        let jt = unsafe { &JobThreads[i as usize] };
        if jt.status != 0 {
            jb_active += jt.jobs_active as i32;
            jb_created += jt.jobs_created;
            let mut j = 0_usize;
            while j < JOB_CLASS_COUNT {
                jb_running[j] += jt.jobs_running[j];
                j += 1;
            }
        }
        i += 1;
    }
    unsafe {
        sb_printf(
            sb,
            c"jobs_created\t%lld\njobs_active\t%d\n".as_ptr(),
            jb_created,
            jb_active,
        )
    };

    unsafe { sb_printf(sb, c"jobs_running\t".as_ptr()) };
    let mut i = 0_usize;
    while i < JOB_CLASS_COUNT {
        if i != 0 {
            unsafe { sb_printf(sb, c" ".as_ptr()) };
            if (i & 3) == 0 {
                unsafe { sb_printf(sb, c" ".as_ptr()) };
            }
        }
        unsafe { sb_printf(sb, c"%d".as_ptr(), jb_running[i]) };
        i += 1;
    }
    unsafe { sb_printf(sb, c"\n".as_ptr()) };

    unsafe {
        sb_printf(
            sb,
            c"jobs_allocated_memory\t%lld\n".as_ptr(),
            sum_jobs_allocated_memory,
        );
        sb_printf(sb, c"timer_ops\t%lld\n".as_ptr(), sum_timer_ops);
        sb_printf(
            sb,
            c"timer_ops_scheduler\t%lld\n".as_ptr(),
            sum_timer_ops_scheduler,
        );
        (*sb).pos
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_create_job_thread_ex(
    thread_class: i32,
    thread_work: Option<unsafe extern "C" fn(*mut c_void) -> *mut c_void>,
) -> i32 {
    abort_if((thread_class & !JC_MASK) != 0);
    abort_if(thread_class == 0);
    abort_if(((thread_class != JC_MAIN) as i32) ^ ((unsafe { cur_job_threads } == 0) as i32) == 0);
    if unsafe { cur_job_threads } >= MAX_JOB_THREADS as i32 {
        return -1;
    }
    unsafe { check_main_thread() };

    let jc = unsafe { &mut JobClasses[thread_class as usize] };
    let main_queue_ptr = ptr::addr_of_mut!(MainJobQueue);
    if thread_class != JC_MAIN && ptr::eq(jc.job_queue, main_queue_ptr) {
        abort_if(unsafe { main_job_thread }.is_null());
        jc.job_queue = unsafe { alloc_mp_queue_w() };
        unsafe {
            (*main_job_thread).job_class_mask &= !(1 << thread_class);
        }
    }
    abort_if(jc.job_queue.is_null());

    let mut idx = 1_usize;
    let mut jt_ptr: *mut JobThread = ptr::null_mut();
    while idx < MAX_JOB_THREADS {
        let jt = unsafe { &JobThreads[idx] };
        if jt.status == 0 && jt.pthread_id == 0 {
            jt_ptr = unsafe { ptr::addr_of_mut!(JobThreads).cast::<JobThread>().add(idx) };
            break;
        }
        idx += 1;
    }
    if jt_ptr.is_null() {
        return -1;
    }

    unsafe {
        ptr::write_bytes(jt_ptr.cast::<u8>(), 0, mem::size_of::<JobThread>());
        (*jt_ptr).status = JTS_CREATED;
        (*jt_ptr).thread_class = thread_class;
        (*jt_ptr).job_class_mask = 1 | if thread_class == JC_MAIN { 0xffff } else { 1 << thread_class };
        (*jt_ptr).job_queue = jc.job_queue;
        (*jt_ptr).job_class = jc as *mut JobClass;
        (*jt_ptr).id = idx as i32;
    }
    abort_if(unsafe { (*jt_ptr).job_queue }.is_null());
    unsafe { jobs_seed_thread_rand_c_impl(jt_ptr) };

    if thread_class != JC_MAIN {
        let mut attr = mem::MaybeUninit::<pthread_attr_t>::uninit();
        unsafe { pthread_attr_init(attr.as_mut_ptr()) };
        unsafe { pthread_attr_setstacksize(attr.as_mut_ptr(), JOB_THREAD_STACK_SIZE) };

        let r = unsafe {
            pthread_create(
                &raw mut (*jt_ptr).pthread_id,
                attr.as_ptr(),
                thread_work,
                jt_ptr.cast(),
            )
        };
        unsafe { pthread_attr_destroy(attr.as_mut_ptr()) };
        if r != 0 {
            unsafe {
                kprintf(
                    c"create_job_thread: pthread_create() failed: %s\n".as_ptr(),
                    strerror(r),
                );
                (*jt_ptr).status = 0;
            }
            return -1;
        }
    } else {
        abort_if(!unsafe { main_job_thread }.is_null());
        unsafe {
            get_this_thread_id();
            (*jt_ptr).pthread_id = main_pthread_id;
            jobs_set_this_job_thread_c_impl(jt_ptr);
            main_job_thread = jt_ptr;
            jobs_set_job_interrupt_signal_handler_c_impl();
        }
        abort_if(unsafe { (*jt_ptr).id } != 1);
    }

    if (idx as i32) > unsafe { max_job_thread_id } {
        unsafe {
            max_job_thread_id = idx as i32;
        }
    }
    unsafe {
        cur_job_threads += 1;
        jc.cur_threads += 1;
    }
    idx as i32
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_unlock_job(job_tag_int: i32, job: JobT) -> i32 {
    abort_if(job.is_null());
    let jt = unsafe { (*job).j_thread };
    abort_if(jt != unsafe { jobs_get_this_job_thread_c_impl() });

    let thread_class = unsafe { (*jt).thread_class };
    let save_subclass = unsafe { (*job).j_subclass };

    loop {
        let flags = unsafe { (*job).j_flags };
        abort_if((flags & JF_LOCKED) == 0);
        let todo = (flags as u32) & (unsafe { (*job).j_status } as u32) & (!0_u32 << 24);
        if todo == 0 {
            let new_flags = flags & !JF_LOCKED;
            if unsafe { jobs_atomic_cas_c_impl(&raw mut (*job).j_flags, flags, new_flags) } == 0 {
                continue;
            }
            if unsafe { (*job).j_refcnt } >= 2 {
                if unsafe { jobs_atomic_fetch_add_c_impl(&raw mut (*job).j_refcnt, -1) } != 1 {
                    return 0;
                }
                unsafe {
                    (*job).j_refcnt = 1;
                }
            }
            abort_if(unsafe { (*job).j_refcnt } != 1);
            if (unsafe { (*job).j_status } as u32 & jss_allow(JS_FINISH) as u32) != 0 {
                unsafe {
                    (*job).j_flags |= jfs_set(JS_FINISH) | JF_LOCKED;
                }
                continue;
            }

            abort_if(true);
            let module_stat_tls = unsafe { jobs_get_module_stat_tls_c_impl() };
            if !module_stat_tls.is_null() {
                unsafe {
                    (*module_stat_tls).jobs_allocated_memory -=
                        (mem::size_of::<AsyncJob>() + (*job).j_custom_bytes as usize) as i64;
                }
            }
            unsafe {
                job_free(job_tag_int, job);
                (*jt).jobs_active -= 1;
            }
            return -1;
        }

        let signo = 7 - todo.leading_zeros() as i32;
        let mut req_class = (unsafe { (*job).j_sigclass } >> (signo * 4)) & 15;
        let is_fast = (unsafe { (*job).j_status } & jss_fast(signo)) != 0;
        let cur_subclass = unsafe { (*job).j_subclass };

        if (((unsafe { (*jt).job_class_mask } >> req_class) & 1) != 0)
            && (is_fast || unsafe { (*jt).current_job }.is_null())
            && (cur_subclass == save_subclass)
        {
            let current_job = unsafe { (*jt).current_job };
            unsafe {
                jobs_atomic_fetch_and_c_impl(&raw mut (*job).j_flags, !jfs_set(signo));
                (*jt).jobs_running[req_class as usize] += 1;
                (*jt).current_job = job;
                (*jt).status |= JTS_PERFORMING;
            }
            let custom = unsafe { (*job).j_custom_bytes };
            let exec = unsafe { (*job).j_execute };
            let res = exec.map_or(JOB_ERROR, |f| unsafe { f(job, signo, jt) });
            unsafe {
                (*jt).current_job = current_job;
                if current_job.is_null() {
                    (*jt).status &= !JTS_PERFORMING;
                }
                (*jt).jobs_running[req_class as usize] -= 1;
            }
            if res == JOB_DESTROYED {
                let module_stat_tls = unsafe { jobs_get_module_stat_tls_c_impl() };
                if !module_stat_tls.is_null() {
                    unsafe {
                        (*module_stat_tls).jobs_allocated_memory -=
                            (mem::size_of::<AsyncJob>() + custom as usize) as i64;
                    }
                }
                unsafe {
                    (*jt).jobs_active -= 1;
                }
                return res;
            }
            if res == JOB_ERROR {
                unsafe {
                    kprintf(
                        c"fatal: thread %p of class %d: error while invoking method %d of job %p (type %p)\n".as_ptr(),
                        jt,
                        thread_class,
                        signo,
                        job,
                        (*job).j_execute.map_or(ptr::null::<c_void>(), |f| f as *const c_void),
                    );
                }
                abort_if(true);
            }
            if (res & !0x1ff) == 0 {
                if (res & 0xff) != 0 {
                    unsafe {
                        jobs_atomic_fetch_or_c_impl(&raw mut (*job).j_flags, res << 24);
                    }
                }
                if (res & JOB_COMPLETED) != 0 {
                    unsafe { complete_job(job) };
                }
            }
            continue;
        }

        if req_class == 0 {
            req_class = JC_MAIN;
        }
        let queued_flag = jf_queued_class(req_class);
        let new_flags = (flags | queued_flag) & !JF_LOCKED;
        if unsafe { jobs_atomic_cas_c_impl(&raw mut (*job).j_flags, flags, new_flags) } == 0 {
            continue;
        }
        if (flags & queued_flag) == 0 {
            let jc = unsafe { &mut JobClasses[req_class as usize] };
            if jc.subclasses.is_null() {
                let jq = jc.job_queue;
                abort_if(jq.is_null());
                let tokio_class = if ptr::eq(jq, ptr::addr_of_mut!(MainJobQueue)) {
                    JC_MAIN
                } else {
                    req_class
                };
                let queued_job = job.cast::<c_void>();
                let rc = mtproxy_ffi_jobs_tokio_enqueue_class(tokio_class, queued_job);
                if rc < 0 {
                    unsafe {
                        kprintf(
                            c"fatal: rust tokio class enqueue failed (class=%d rc=%d job=%p)\n".as_ptr(),
                            tokio_class,
                            rc,
                            queued_job,
                        );
                    }
                    abort_if(true);
                }
                if ptr::eq(jq, ptr::addr_of_mut!(MainJobQueue))
                    && unsafe { main_thread_interrupt_status } == 1
                    && unsafe {
                        jobs_atomic_fetch_add_c_impl(&raw mut main_thread_interrupt_status, 1)
                    } == 1
                {
                    unsafe { wakeup_main_thread() };
                }
            } else {
                abort_if(unsafe { (*job).j_subclass } != cur_subclass);
                let subclass_cnt = unsafe { (*jc.subclasses).subclass_cnt };
                abort_if(cur_subclass < -2 || cur_subclass >= subclass_cnt);
                let jsc = unsafe { &mut *(*jc.subclasses).subclasses.offset(cur_subclass as isize) };
                unsafe {
                    jobs_atomic_fetch_add_c_impl(&raw mut jsc.total_jobs, 1);
                }

                let subclass_job = job.cast::<c_void>();
                let rc =
                    mtproxy_ffi_jobs_tokio_enqueue_subclass(req_class, cur_subclass, subclass_job);
                if rc < 0 {
                    unsafe {
                        kprintf(
                            c"fatal: rust tokio subclass enqueue failed (class=%d subclass=%d rc=%d job=%p)\n".as_ptr(),
                            req_class,
                            cur_subclass,
                            rc,
                            subclass_job,
                        );
                    }
                    abort_if(true);
                }

                let jq = jc.job_queue;
                abort_if(jq.is_null());
                let tokio_class = if ptr::eq(jq, ptr::addr_of_mut!(MainJobQueue)) {
                    JC_MAIN
                } else {
                    req_class
                };
                let subclass_token = (cur_subclass + JOB_SUBCLASS_OFFSET) as isize as *mut c_void;
                let rc = mtproxy_ffi_jobs_tokio_enqueue_class(tokio_class, subclass_token);
                if rc < 0 {
                    unsafe {
                        kprintf(
                            c"fatal: rust tokio subclass token enqueue failed (class=%d rc=%d token=%p)\n".as_ptr(),
                            tokio_class,
                            rc,
                            subclass_token,
                        );
                    }
                    abort_if(true);
                }
            }
            return 1;
        }

        unsafe { job_decref(job_tag_int, job) };
        return 0;
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_complete_subjob(
    job: JobT,
    parent_tag_int: i32,
    parent: JobT,
    status: i32,
) {
    if parent.is_null() {
        return;
    }
    if (unsafe { (*parent).j_flags } & JF_COMPLETED) != 0 {
        unsafe { job_decref(parent_tag_int, parent) };
        return;
    }
    if unsafe { (*job).j_error } != 0 && (status & JSP_PARENT_ERROR) != 0 {
        if unsafe { (*parent).j_error } == 0 {
            unsafe {
                jobs_atomic_cas_c_impl(
                    &raw mut (*parent).j_error,
                    0,
                    (*job).j_error,
                );
            }
        }
        if (status & JSP_PARENT_WAKEUP as i32) != 0 {
            unsafe {
                jobs_atomic_fetch_add_c_impl(&raw mut (*parent).j_children, -1);
            }
        }
        unsafe { job_signal(parent_tag_int, parent, JS_ABORT) };
        return;
    }
    if (status & JSP_PARENT_WAKEUP as i32) != 0 {
        if unsafe { jobs_atomic_fetch_add_c_impl(&raw mut (*parent).j_children, -1) } == 1
            && (status & JSP_PARENT_RUN) != 0
        {
            unsafe { job_signal(parent_tag_int, parent, JS_RUN) };
        } else {
            unsafe { job_decref(parent_tag_int, parent) };
        }
        return;
    }
    if (status & JSP_PARENT_RUN) != 0 {
        unsafe { job_signal(parent_tag_int, parent, JS_RUN) };
        return;
    }
    unsafe { job_decref(parent_tag_int, parent) };
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_timer_insert(job: JobT, timeout: f64) {
    abort_if(job.is_null());
    abort_if((unsafe { (*job).j_type as u64 } & JT_HAVE_TIMER) == 0);
    let ev = unsafe { (*job).j_custom.as_mut_ptr().cast::<EventTimer>() };
    if unsafe { (*ev).real_wakeup_time } == timeout {
        return;
    }
    unsafe {
        (*ev).real_wakeup_time = timeout;
    }
    if unsafe { (*ev).wakeup }.is_none() {
        unsafe {
            // Keep pointer identity equal to legacy C wrapper:
            // do_immediate_timer_insert() asserts `ev->wakeup == job_timer_wakeup_gateway`.
            (*ev).wakeup = Some(job_timer_wakeup_gateway);
        }
    }

    let this_thread = unsafe { jobs_get_this_job_thread_c_impl() };
    let mut owner = unsafe { (*ev).flags & 255 };
    if owner != 0 {
        if (!this_thread.is_null() && unsafe { (*this_thread).id } == owner)
            || (this_thread.is_null() && owner == 1)
        {
            unsafe { do_immediate_timer_insert(job) };
            return;
        }
    } else if this_thread.is_null() || unsafe { (*this_thread).id } == 1 {
        unsafe {
            (*ev).flags |= 1;
            do_immediate_timer_insert(job);
        }
        return;
    } else if !unsafe { (*this_thread).timer_manager }.is_null() {
        unsafe {
            (*ev).flags |= (*this_thread).id;
            do_immediate_timer_insert(job);
        }
        return;
    } else {
        unsafe {
            (*ev).flags |= 1;
        }
    }

    owner = unsafe { (*ev).flags & 255 };
    abort_if(owner == 0);

    let manager = if owner == 1 {
        unsafe { timer_manager_job }
    } else {
        unsafe { JobThreads[owner as usize].timer_manager }
    };
    let module_stat_tls = unsafe { jobs_get_module_stat_tls_c_impl() };
    if !module_stat_tls.is_null() {
        unsafe {
            (*module_stat_tls).timer_ops_scheduler += 1;
        }
    }
    abort_if(manager.is_null());

    let extra = unsafe { (*manager).j_custom.as_mut_ptr().cast::<JobTimerManagerExtra>() };
    let rc = mtproxy_ffi_jobs_tokio_timer_queue_push(
        unsafe { (*extra).tokio_queue_id },
        unsafe { job_incref(job) }.cast::<c_void>(),
    );
    if rc < 0 {
        unsafe {
            kprintf(
                c"fatal: rust tokio timer queue push failed (qid=%d rc=%d)\n".as_ptr(),
                (*extra).tokio_queue_id,
                rc,
            );
        }
        abort_if(true);
    }
    unsafe { job_signal(1, manager, JS_RUN) };
}

#[inline]
unsafe fn job_message_payload_ptr(message: *mut JobMessage) -> *mut u32 {
    // SAFETY: payload starts immediately after fixed-size header.
    unsafe { message.cast::<u8>().add(mem::size_of::<JobMessage>()).cast::<u32>() }
}

#[inline]
unsafe fn job_message_payload_read(message: *mut JobMessage, idx: usize) -> u32 {
    // SAFETY: caller guarantees payload bounds.
    unsafe { *job_message_payload_ptr(message).add(idx) }
}

unsafe fn job_message_receive_or_continuation(
    job: JobT,
    message: *mut JobMessage,
    receive_message: JobMessageReceiveFn,
    extra: *mut c_void,
    payload_magic: u32,
) -> i32 {
    let msg_flags = unsafe { (*message).flags };
    if (msg_flags & JMC_CONTINUATION) != 0 {
        let payload_ints = unsafe { (*message).payload_ints };
        abort_if(payload_ints < 1);
        abort_if(unsafe { job_message_payload_read(message, 0) } != payload_magic);
        abort_if(payload_ints != 5);

        // payload[1..=2] stores function pointer, payload[3..=4] stores opaque extra pointer.
        let func_ptr_slot = unsafe { job_message_payload_ptr(message).add(1).cast::<*const ()>() };
        let extra_ptr_slot = unsafe { job_message_payload_ptr(message).add(3).cast::<*mut c_void>() };
        let continuation_fn_addr = unsafe { *func_ptr_slot };
        let continuation_extra = unsafe { *extra_ptr_slot };
        abort_if(continuation_fn_addr.is_null());
        // SAFETY: layout follows legacy C payload continuation contract.
        let continuation_fn: unsafe extern "C" fn(JobT, *mut JobMessage, *mut c_void) -> i32 =
            unsafe { mem::transmute(continuation_fn_addr) };
        unsafe { continuation_fn(job, message, continuation_extra) }
    } else {
        let Some(receive) = receive_message else {
            abort_if(true);
            return -1;
        };
        unsafe { receive(job, message, extra) }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_process_one_sublist(subclass_token_id: usize, class: i32) {
    let _ = class;
    let thread_class = unsafe { jobs_get_current_thread_class_c_impl() };
    abort_if(thread_class <= 0);
    let subclass_cnt = unsafe { jobs_get_current_thread_subclass_count_c_impl() };
    abort_if(subclass_cnt < 0);

    let subclass_id = subclass_token_id as i32 - 3;
    abort_if(subclass_id < -2);
    abort_if(subclass_id >= subclass_cnt);

    let enter_rc = mtproxy_ffi_jobs_tokio_subclass_enter(thread_class, subclass_id);
    abort_if(enter_rc < 0);
    if enter_rc == 0 {
        return;
    }

    let permit_rc = mtproxy_ffi_jobs_tokio_subclass_permit_acquire(thread_class, subclass_id);
    abort_if(permit_rc != 0);

    loop {
        loop {
            let pending_rc = mtproxy_ffi_jobs_tokio_subclass_has_pending(thread_class, subclass_id);
            abort_if(pending_rc < 0);
            if pending_rc == 0 {
                break;
            }

            let mut job: *mut c_void = ptr::null_mut();
            let rc = unsafe {
                mtproxy_ffi_jobs_tokio_dequeue_subclass(
                    thread_class,
                    subclass_id,
                    1,
                    &raw mut job,
                )
            };
            abort_if(rc < 0 || job.is_null());
            unsafe {
                process_one_job(1, job.cast::<AsyncJob>(), thread_class);
            }
            let mark_rc = mtproxy_ffi_jobs_tokio_subclass_mark_processed(thread_class, subclass_id);
            abort_if(mark_rc != 0);
        }

        let cont_rc = mtproxy_ffi_jobs_tokio_subclass_exit_or_continue(thread_class, subclass_id);
        abort_if(cont_rc < 0);
        if cont_rc > 0 {
            continue;
        }
        break;
    }

    let release_rc = mtproxy_ffi_jobs_tokio_subclass_permit_release(thread_class, subclass_id);
    abort_if(release_rc != 0);
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_message_send(
    job: JobT,
    src: JobT,
    type_: u32,
    raw: *mut RawMessage,
    dup: i32,
    payload_ints: i32,
    payload: *const u32,
    flags: u32,
    destroy: JobMessageDestructorFn,
) {
    abort_if(job.is_null() || raw.is_null());
    abort_if(payload_ints < 0);
    abort_if(payload_ints > 0 && payload.is_null());
    abort_if((unsafe { (*job).j_type as u64 } & JT_HAVE_MSG_QUEUE) == 0);

    let payload_bytes = (payload_ints as usize) * mem::size_of::<u32>();
    let total_size = mem::size_of::<JobMessage>()
        .checked_add(payload_bytes)
        .unwrap_or_else(|| {
            std::process::abort();
        });
    let message = unsafe { malloc(total_size).cast::<JobMessage>() };
    abort_if(message.is_null());

    unsafe {
        (*message).type_ = type_;
        (*message).flags = flags;
        (*message).src = src;
        (*message).payload_ints = payload_ints as u32;
        (*message).next = ptr::null_mut();
        (*message).destructor = destroy;
        if payload_bytes > 0 {
            memcpy(
                job_message_payload_ptr(message).cast::<c_void>(),
                payload.cast::<c_void>(),
                payload_bytes,
            );
        }
        if dup != 0 {
            rwm_clone(&raw mut (*message).message, raw);
        } else {
            rwm_move(&raw mut (*message).message, raw);
        }
    }

    let queue = unsafe { job_message_queue_get(job) };
    abort_if(queue.is_null());
    let rc = mtproxy_ffi_jobs_tokio_message_queue_push(unsafe { (*queue).tokio_queue_id }, message.cast());
    abort_if(rc < 0);

    unsafe {
        job_signal(1, job, JS_MSG);
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_message_queue_work(
    job: JobT,
    receive_message: JobMessageReceiveFn,
    extra: *mut c_void,
    mask: u32,
) {
    abort_if(job.is_null());
    abort_if((unsafe { (*job).j_type as u64 } & JT_HAVE_MSG_QUEUE) == 0);
    let queue = unsafe { job_message_queue_get(job) };
    abort_if(queue.is_null());

    loop {
        let mut msg: *mut c_void = ptr::null_mut();
        let rc =
            unsafe { mtproxy_ffi_jobs_tokio_message_queue_pop((*queue).tokio_queue_id, &raw mut msg) };
        abort_if(rc < 0);
        if rc == 0 || msg.is_null() {
            break;
        }
        let msg = msg.cast::<JobMessage>();
        unsafe {
            (*msg).next = ptr::null_mut();
            if !(*queue).last.is_null() {
                (*(*queue).last).next = msg;
                (*queue).last = msg;
            } else {
                (*queue).first = msg;
                (*queue).last = msg;
            }
        }
    }

    let mut last: *mut JobMessage = ptr::null_mut();
    let mut ptr_to_current: *mut *mut JobMessage = unsafe { &raw mut (*queue).first };
    let mut stop = false;
    while !stop {
        let current = unsafe { *ptr_to_current };
        if current.is_null() {
            break;
        }
        let kind = unsafe { (*current).flags & JMC_TYPE_MASK };
        abort_if(kind == 0);
        if (mask & (1_u32 << kind)) != 0 {
            let next = unsafe { (*current).next };
            unsafe {
                (*current).next = ptr::null_mut();
            }
            let result = unsafe {
                job_message_receive_or_continuation(
                    job,
                    current,
                    receive_message,
                    extra,
                    (*queue).payload_magic,
                )
            };
            if result < 0 {
                stop = true;
            } else if result == 1 {
                unsafe { mtproxy_ffi_jobs_job_message_free_default(current) };
            } else if result == 2 {
                let destructor = unsafe { (*current).destructor };
                if let Some(dtor) = destructor {
                    unsafe { dtor(current) };
                } else {
                    unsafe { mtproxy_ffi_jobs_job_message_free_default(current) };
                }
            }
            unsafe {
                *ptr_to_current = next;
                if (*queue).last == current {
                    (*queue).last = last;
                }
            }
        } else {
            last = current;
            ptr_to_current = unsafe { &raw mut (*current).next };
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_message_queue_free(job: JobT) {
    abort_if(job.is_null());
    abort_if((unsafe { (*job).j_type as u64 } & JT_HAVE_MSG_QUEUE) == 0);
    let queue_slot = unsafe { job_message_queue_get(job) };
    abort_if(queue_slot.is_null());
    if queue_slot.is_null() {
        return;
    }

    let queue = queue_slot;
    if queue.is_null() {
        return;
    }

    unsafe {
        while !(*queue).first.is_null() {
            let message = (*queue).first;
            (*queue).first = (*message).next;
            mtproxy_ffi_jobs_job_message_free_default(message);
        }
        (*queue).last = ptr::null_mut();
    }

    loop {
        let mut message: *mut c_void = ptr::null_mut();
        let rc = unsafe {
            mtproxy_ffi_jobs_tokio_message_queue_pop((*queue).tokio_queue_id, &raw mut message)
        };
        abort_if(rc < 0);
        if rc == 0 || message.is_null() {
            break;
        }
        unsafe { mtproxy_ffi_jobs_job_message_free_default(message.cast::<JobMessage>()) };
    }

    let destroy_rc = mtproxy_ffi_jobs_tokio_message_queue_destroy(unsafe { (*queue).tokio_queue_id });
    abort_if(destroy_rc < 0);
    unsafe {
        free(queue.cast::<c_void>());
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_message_free_default(message: *mut JobMessage) {
    if message.is_null() {
        return;
    }
    let src = unsafe { (*message).src };
    if !src.is_null() {
        unsafe {
            job_decref(1, src);
        }
    }
    if unsafe { (*message).message.magic } != 0 {
        unsafe {
            rwm_free(&raw mut (*message).message);
        }
    }
    unsafe {
        free(message.cast::<c_void>());
    }
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_free(job_tag_int: i32, job: JobT) -> i32 {
    abort_if(job.is_null());
    if (unsafe { (*job).j_type as u64 } & JT_HAVE_MSG_QUEUE) != 0 {
        unsafe {
            mtproxy_ffi_jobs_job_message_queue_free(job);
        }
    }
    let base_ptr = unsafe { job.cast::<u8>().sub((*job).j_align as usize) };
    unsafe {
        free(base_ptr.cast::<c_void>());
    }
    let _ = job_tag_int;
    -0x7fff_ffff - 1
}

#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_job_timer_wakeup_gateway(et: *mut EventTimer) -> i32 {
    abort_if(et.is_null());
    let header_size = unsafe { jobs_async_job_header_size_c_impl() };
    let job = unsafe {
        (et.cast::<u8>().sub(header_size)).cast::<AsyncJob>()
    };
    abort_if(job.is_null());
    if unsafe { (*et).wakeup_time == (*et).real_wakeup_time } {
        unsafe {
            job_signal(1, job, JS_ALARM);
        }
    } else {
        unsafe {
            job_decref(1, job);
        }
    }
    0
}

/// Initializes shared Tokio scheduler state for Rust-backed jobs queue routing.
///
/// Return codes:
/// - `0`: scheduler is ready
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_init() -> i32 {
    if TOKIO_JOBS_BRIDGE.get().is_some() {
        return 0;
    }
    let _ = TOKIO_JOBS_BRIDGE.set(build_tokio_jobs_bridge());
    0
}

/// Enqueues one opaque `job_t` pointer into Rust/Tokio-backed class queue.
///
/// Return codes:
/// - `0`: enqueued
/// - `-1`: null job
/// - `-2`: scheduler not initialized
/// - `-3`: invalid class id
/// - `-4`: queue closed
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_enqueue_class(job_class: i32, job: *mut c_void) -> i32 {
    if job.is_null() {
        return -1;
    }
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -2;
    };
    enqueue_class_impl(bridge, job_class, job as JobPtr)
}

/// Dequeues one opaque `job_t` pointer from Rust/Tokio-backed class queue.
///
/// Return values:
/// - `1`: one job dequeued into `out_job`
/// - `0`: queue currently empty / disconnected
/// - `-1`: null `out_job`
/// - `-2`: scheduler not initialized
/// - `-3`: invalid class id
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_tokio_dequeue_class(
    job_class: i32,
    blocking: i32,
    out_job: *mut *mut c_void,
) -> i32 {
    if out_job.is_null() {
        return -1;
    }
    // SAFETY: pointer validated above; caller owns storage.
    unsafe {
        *out_job = ptr::null_mut();
    }
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -2;
    };
    dequeue_class_impl(bridge, job_class, blocking != 0, out_job)
}

/// Enqueues one opaque `job_t` pointer into Rust/Tokio-backed subclass queue.
///
/// Return codes:
/// - `0`: enqueued
/// - `-1`: null job
/// - `-2`: scheduler not initialized
/// - `-3`: invalid class id
/// - `-4`: queue closed
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_enqueue_subclass(
    job_class: i32,
    subclass_id: i32,
    job: *mut c_void,
) -> i32 {
    if job.is_null() {
        return -1;
    }
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -2;
    };
    enqueue_subclass_impl(bridge, job_class, subclass_id, job as JobPtr)
}

/// Dequeues one opaque `job_t` pointer from Rust/Tokio-backed subclass queue.
///
/// Return values:
/// - `1`: one job dequeued into `out_job`
/// - `0`: queue currently empty / disconnected
/// - `-1`: null `out_job`
/// - `-2`: scheduler not initialized
/// - `-3`: invalid class id
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_tokio_dequeue_subclass(
    job_class: i32,
    subclass_id: i32,
    blocking: i32,
    out_job: *mut *mut c_void,
) -> i32 {
    if out_job.is_null() {
        return -1;
    }
    // SAFETY: pointer validated above; caller owns storage.
    unsafe {
        *out_job = ptr::null_mut();
    }
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -2;
    };
    dequeue_subclass_impl(bridge, job_class, subclass_id, blocking != 0, out_job)
}

/// Subclass scheduler gate: records one incoming subclass token and tries to lock.
///
/// Return values:
/// - `1`: caller acquired lock and should process subclass queue
/// - `0`: caller should return (another worker owns lock)
/// - `-1`: scheduler not initialized
/// - `-2`: invalid class id
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_subclass_enter(job_class: i32, subclass_id: i32) -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    let Some(res) = mutate_subclass_state(bridge, job_class, subclass_id, |state| {
        state.allowed_to_run_jobs = state.allowed_to_run_jobs.saturating_add(1);
        if state.locked {
            0
        } else {
            state.locked = true;
            1
        }
    }) else {
        return -2;
    };
    res
}

/// Subclass scheduler gate: reports whether there are pending jobs to process.
///
/// Return values:
/// - `1`: pending work exists (`processed < allowed`)
/// - `0`: no pending work
/// - `-1`: scheduler not initialized
/// - `-2`: invalid class id
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_subclass_has_pending(
    job_class: i32,
    subclass_id: i32,
) -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    let Some(state) = state_for_subclass(bridge, job_class, subclass_id) else {
        return -2;
    };
    if state.processed_jobs < state.allowed_to_run_jobs {
        1
    } else {
        0
    }
}

/// Subclass scheduler gate: marks one processed subclass job.
///
/// Return values:
/// - `0`: updated
/// - `-1`: scheduler not initialized
/// - `-2`: invalid class id
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_subclass_mark_processed(
    job_class: i32,
    subclass_id: i32,
) -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    let Some(()) = mutate_subclass_state(bridge, job_class, subclass_id, |state| {
        state.processed_jobs = state.processed_jobs.saturating_add(1);
    }) else {
        return -2;
    };
    0
}

/// Subclass scheduler gate: unlocks once and conditionally re-locks if tokens raced in.
///
/// Return values:
/// - `1`: caller should continue processing (lock held)
/// - `0`: caller should exit processing loop
/// - `-1`: scheduler not initialized
/// - `-2`: invalid class id
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_subclass_exit_or_continue(
    job_class: i32,
    subclass_id: i32,
) -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    let Some(res) = mutate_subclass_state(bridge, job_class, subclass_id, |state| {
        state.locked = false;
        if state.processed_jobs < state.allowed_to_run_jobs {
            state.locked = true;
            1
        } else {
            0
        }
    }) else {
        return -2;
    };
    res
}

/// Subclass scheduler permit gate: blocks until permits can be acquired.
///
/// Semantics match C `sem_wait` branch:
/// - `subclass_id == -1`: acquires all `MAX_SUBCLASS_THREADS` permits
/// - otherwise: acquires one permit
///
/// Return values:
/// - `0`: permits acquired
/// - `-1`: scheduler not initialized
/// - `-2`: invalid class id
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_subclass_permit_acquire(
    job_class: i32,
    subclass_id: i32,
) -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    let Some(pool) = permit_pool_for_class(bridge, job_class) else {
        return -2;
    };
    let needed = if subclass_id == -1 {
        MAX_SUBCLASS_THREADS
    } else {
        1
    };
    let mut state = match pool.state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    while state.available < needed {
        state = match pool.condvar.wait(state) {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
    }
    state.available -= needed;
    0
}

/// Subclass scheduler permit gate: releases previously acquired permits.
///
/// Semantics match C `sem_post` branch:
/// - `subclass_id == -1`: releases all `MAX_SUBCLASS_THREADS` permits
/// - otherwise: releases one permit
///
/// Return values:
/// - `0`: permits released
/// - `-1`: scheduler not initialized
/// - `-2`: invalid class id
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_subclass_permit_release(
    job_class: i32,
    subclass_id: i32,
) -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    let Some(pool) = permit_pool_for_class(bridge, job_class) else {
        return -2;
    };
    let released = if subclass_id == -1 {
        MAX_SUBCLASS_THREADS
    } else {
        1
    };
    let mut state = match pool.state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    state.available = (state.available + released).clamp(0, MAX_SUBCLASS_THREADS);
    pool.condvar.notify_all();
    0
}

/// Backward-compatible helper for main queue enqueue.
///
/// Return codes:
/// - `0`: enqueued
/// - `-1`: null job
/// - `-2`: scheduler not initialized
/// - `-3`: invalid class id
/// - `-4`: queue closed
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_enqueue_main(job: *mut c_void) -> i32 {
    mtproxy_ffi_jobs_tokio_enqueue_class(JOB_CLASS_MAIN, job)
}

/// Backward-compatible helper for draining main queue via callback.
///
/// `max_items == 0` means "drain everything available now".
///
/// Return values:
/// - `>= 0`: number of jobs dispatched
/// - `-1`: null callback
/// - `-2`: scheduler not initialized
/// - `-3`: invalid `max_items` (< 0)
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_drain_main(
    process_one_job: Option<JobsProcessFn>,
    max_items: i32,
) -> i32 {
    let Some(process_one_job_fn) = process_one_job else {
        return -1;
    };
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -2;
    };
    if max_items < 0 {
        return -3;
    }

    let mut drained = 0;
    loop {
        if max_items != JOBS_DRAIN_UNLIMITED && drained >= max_items {
            break;
        }
        let mut job_ptr: *mut c_void = ptr::null_mut();
        let rc = dequeue_class_impl(bridge, JOB_CLASS_MAIN, false, &raw mut job_ptr);
        if rc <= 0 || job_ptr.is_null() {
            break;
        }
        let _ = process_one_job_fn(job_ptr);
        drained += 1;
    }

    drained
}

/// Allocates one Tokio-backed timer-manager queue.
///
/// Return values:
/// - `> 0`: queue id
/// - `-1`: scheduler not initialized
/// - `-3`: queue id space exhausted
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_timer_queue_create() -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    alloc_user_queue(&bridge.timer_queues, bridge)
}

/// Destroys one Tokio-backed timer-manager queue by id.
///
/// Return values:
/// - `0`: destroyed
/// - `-1`: scheduler not initialized
/// - `-2`: invalid/unknown queue id
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_timer_queue_destroy(queue_id: i32) -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    drop_user_queue(&bridge.timer_queues, queue_id)
}

/// Enqueues one opaque pointer into Tokio-backed timer-manager queue.
///
/// Return values:
/// - `0`: enqueued
/// - `-1`: null pointer
/// - `-2`: scheduler not initialized
/// - `-3`: invalid queue id
/// - `-4`: queue closed
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_timer_queue_push(queue_id: i32, ptr: *mut c_void) -> i32 {
    if ptr.is_null() {
        return -1;
    }
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -2;
    };
    let Some(queue) = user_queue_by_id(&bridge.timer_queues, queue_id) else {
        return -3;
    };
    enqueue_user_queue_item(&queue, ptr as JobPtr)
}

/// Dequeues one opaque pointer from Tokio-backed timer-manager queue.
///
/// Return values:
/// - `1`: one pointer dequeued into `out_ptr`
/// - `0`: queue currently empty/disconnected
/// - `-1`: null `out_ptr`
/// - `-2`: scheduler not initialized
/// - `-3`: invalid queue id
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_tokio_timer_queue_pop(
    queue_id: i32,
    out_ptr: *mut *mut c_void,
) -> i32 {
    if out_ptr.is_null() {
        return -1;
    }
    // SAFETY: pointer validated above; caller owns storage.
    unsafe {
        *out_ptr = ptr::null_mut();
    }
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -2;
    };
    let Some(queue) = user_queue_by_id(&bridge.timer_queues, queue_id) else {
        return -3;
    };
    dequeue_user_queue_item(&queue, out_ptr)
}

/// Allocates one Tokio-backed message queue.
///
/// Return values:
/// - `> 0`: queue id
/// - `-1`: scheduler not initialized
/// - `-3`: queue id space exhausted
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_message_queue_create() -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    alloc_user_queue(&bridge.message_queues, bridge)
}

/// Destroys one Tokio-backed message queue by id.
///
/// Return values:
/// - `0`: destroyed
/// - `-1`: scheduler not initialized
/// - `-2`: invalid/unknown queue id
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_message_queue_destroy(queue_id: i32) -> i32 {
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -1;
    };
    drop_user_queue(&bridge.message_queues, queue_id)
}

/// Enqueues one opaque pointer into Tokio-backed message queue.
///
/// Return values:
/// - `0`: enqueued
/// - `-1`: null pointer
/// - `-2`: scheduler not initialized
/// - `-3`: invalid queue id
/// - `-4`: queue closed
#[no_mangle]
pub extern "C" fn mtproxy_ffi_jobs_tokio_message_queue_push(
    queue_id: i32,
    ptr: *mut c_void,
) -> i32 {
    if ptr.is_null() {
        return -1;
    }
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -2;
    };
    let Some(queue) = user_queue_by_id(&bridge.message_queues, queue_id) else {
        return -3;
    };
    enqueue_user_queue_item(&queue, ptr as JobPtr)
}

/// Dequeues one opaque pointer from Tokio-backed message queue.
///
/// Return values:
/// - `1`: one pointer dequeued into `out_ptr`
/// - `0`: queue currently empty/disconnected
/// - `-1`: null `out_ptr`
/// - `-2`: scheduler not initialized
/// - `-3`: invalid queue id
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_jobs_tokio_message_queue_pop(
    queue_id: i32,
    out_ptr: *mut *mut c_void,
) -> i32 {
    if out_ptr.is_null() {
        return -1;
    }
    // SAFETY: pointer validated above; caller owns storage.
    unsafe {
        *out_ptr = ptr::null_mut();
    }
    let Some(bridge) = TOKIO_JOBS_BRIDGE.get() else {
        return -2;
    };
    let Some(queue) = user_queue_by_id(&bridge.message_queues, queue_id) else {
        return -3;
    };
    dequeue_user_queue_item(&queue, out_ptr)
}
