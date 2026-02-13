use super::*;

#[repr(C)]
#[allow(dead_code)]
pub(crate) struct Timespec {
    pub(crate) tv_sec: c_long,
    pub(crate) tv_nsec: c_long,
}

#[repr(C)]
#[allow(dead_code)]
pub(crate) struct Timeval {
    pub(crate) tv_sec: c_long,
    pub(crate) tv_usec: c_long,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyProcessId {
    pub ip: u32,
    pub port: i16,
    pub pid: u16,
    pub utime: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyAesKeyData {
    pub read_key: [u8; 32],
    pub read_iv: [u8; 16],
    pub write_key: [u8; 32],
    pub write_iv: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtproxyAesSecret {
    pub refcnt: i32,
    pub secret_len: i32,
    pub secret: [u8; MAX_PWD_LEN + 4],
}

impl Default for MtproxyAesSecret {
    fn default() -> Self {
        Self {
            refcnt: 0,
            secret_len: 0,
            secret: [0u8; MAX_PWD_LEN + 4],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtproxyCryptoTempDhParams {
    pub magic: i32,
    pub dh_params_select: i32,
    pub a: [u8; DH_KEY_BYTES],
}

impl Default for MtproxyCryptoTempDhParams {
    fn default() -> Self {
        Self {
            magic: 0,
            dh_params_select: 0,
            a: [0u8; DH_KEY_BYTES],
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyCpuid {
    pub magic: i32,
    pub ebx: i32,
    pub ecx: i32,
    pub edx: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyCfgScanResult {
    pub advance: usize,
    pub line_no: i32,
    pub ch: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyCfgIntResult {
    pub value: i64,
    pub consumed: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoCfgGetlexExtResult {
    pub advance: usize,
    pub lex: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoCfgDirectiveTokenResult {
    pub kind: i32,
    pub advance: usize,
    pub value: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoCfgDirectiveStepResult {
    pub kind: i32,
    pub advance: usize,
    pub value: i64,
    pub cluster_decision_kind: i32,
    pub cluster_index: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoCfgParseProxyTargetStepResult {
    pub advance: usize,
    pub target_index: u32,
    pub host_len: u8,
    pub port: u16,
    pub min_connections: i64,
    pub max_connections: i64,
    pub tot_targets_after: u32,
    pub cluster_decision_kind: i32,
    pub cluster_index: i32,
    pub auth_clusters_after: u32,
    pub auth_tot_clusters_after: u32,
    pub cluster_state_after: MtproxyMtprotoOldClusterState,
    pub cluster_targets_action: i32,
    pub cluster_targets_index: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoCfgProxyAction {
    pub host_offset: usize,
    pub step: MtproxyMtprotoCfgParseProxyTargetStepResult,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct MtproxyMtprotoCfgParseFullResult {
    pub tot_targets: u32,
    pub auth_clusters: u32,
    pub auth_tot_clusters: u32,
    pub min_connections: i64,
    pub max_connections: i64,
    pub timeout_seconds: f64,
    pub default_cluster_id: i32,
    pub have_proxy: i32,
    pub default_cluster_index: u32,
    pub has_default_cluster_index: i32,
    pub actions_len: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoCfgFinalizeResult {
    pub default_cluster_index: u32,
    pub has_default_cluster_index: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct MtproxyMtprotoCfgPreinitResult {
    pub tot_targets: i32,
    pub auth_clusters: i32,
    pub min_connections: i64,
    pub max_connections: i64,
    pub timeout_seconds: f64,
    pub default_cluster_id: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoCfgClusterApplyDecisionResult {
    pub kind: i32,
    pub cluster_index: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoPacketInspectResult {
    pub kind: i32,
    pub auth_key_id: i64,
    pub inner_len: i32,
    pub function_id: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoClientPacketParseResult {
    pub kind: i32,
    pub op: i32,
    pub flags: i32,
    pub out_conn_id: i64,
    pub confirm: i32,
    pub payload_offset: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMtprotoOldClusterState {
    pub cluster_id: i32,
    pub targets_num: u32,
    pub write_targets_num: u32,
    pub flags: u32,
    pub first_target_index: u32,
    pub has_first_target_index: i32,
}

pub(crate) type MtproxyConnTargetJob = *mut c_void;

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MtproxyMfCluster {
    pub(crate) targets_num: c_int,
    pub(crate) write_targets_num: c_int,
    pub(crate) targets_allocated: c_int,
    pub(crate) flags: c_int,
    pub(crate) cluster_id: c_int,
    pub(crate) cluster_targets: *mut MtproxyConnTargetJob,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MtproxyMfGroupStats {
    pub(crate) tot_clusters: c_int,
}

#[repr(C)]
pub(crate) struct MtproxyMfConfig {
    pub(crate) tot_targets: c_int,
    pub(crate) auth_clusters: c_int,
    pub(crate) default_cluster_id: c_int,
    pub(crate) min_connections: c_int,
    pub(crate) max_connections: c_int,
    pub(crate) timeout: f64,
    pub(crate) config_bytes: c_int,
    pub(crate) config_loaded_at: c_int,
    pub(crate) config_md5_hex: *mut c_char,
    pub(crate) auth_stats: MtproxyMfGroupStats,
    pub(crate) have_proxy: c_int,
    pub(crate) default_cluster: *mut MtproxyMfCluster,
    pub(crate) targets: [MtproxyConnTargetJob; MTPROTO_CFG_MAX_TARGETS],
    pub(crate) auth_cluster: [MtproxyMfCluster; MTPROTO_CFG_MAX_CLUSTERS],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MtproxyEventTimer {
    pub(crate) h_idx: c_int,
    pub(crate) flags: c_int,
    pub(crate) wakeup: Option<unsafe extern "C" fn(*mut MtproxyEventTimer) -> c_int>,
    pub(crate) wakeup_time: c_double,
    pub(crate) real_wakeup_time: c_double,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MtproxyInAddr {
    pub(crate) s_addr: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MtproxyConnTargetInfo {
    pub(crate) timer: MtproxyEventTimer,
    pub(crate) min_connections: c_int,
    pub(crate) max_connections: c_int,
    pub(crate) conn_tree: *mut c_void,
    pub(crate) type_: *mut c_void,
    pub(crate) extra: *mut c_void,
    pub(crate) target: MtproxyInAddr,
    pub(crate) target_ipv6: [u8; 16],
    pub(crate) port: c_int,
    pub(crate) active_outbound_connections: c_int,
    pub(crate) outbound_connections: c_int,
    pub(crate) ready_outbound_connections: c_int,
    pub(crate) next_reconnect: c_double,
    pub(crate) reconnect_timeout: c_double,
    pub(crate) next_reconnect_timeout: c_double,
    pub(crate) custom_field: c_int,
    pub(crate) next_target: MtproxyConnTargetJob,
    pub(crate) prev_target: MtproxyConnTargetJob,
    pub(crate) hnext: MtproxyConnTargetJob,
    pub(crate) global_refcnt: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct MtproxyHostEnt {
    pub(crate) h_name: *mut c_char,
    pub(crate) h_aliases: *mut *mut c_char,
    pub(crate) h_addrtype: c_int,
    pub(crate) h_length: c_int,
    pub(crate) h_addr_list: *mut *mut c_char,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtproxyTlHeaderParseResult {
    pub status: i32,
    pub consumed: i32,
    pub op: i32,
    pub real_op: i32,
    pub flags: i32,
    pub qid: i64,
    pub actor_id: i64,
    pub errnum: i32,
    pub error_len: i32,
    pub error: [c_char; 192],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtproxyMtprotoParseFunctionResult {
    pub status: i32,
    pub consumed: i32,
    pub errnum: i32,
    pub error_len: i32,
    pub error: [c_char; 192],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtproxyProcStats {
    pub pid: i32,
    pub comm: [c_char; 256],
    pub state: i8,
    pub ppid: i32,
    pub pgrp: i32,
    pub session: i32,
    pub tty_nr: i32,
    pub tpgid: i32,
    pub flags: u64,
    pub minflt: u64,
    pub cminflt: u64,
    pub majflt: u64,
    pub cmajflt: u64,
    pub utime: u64,
    pub stime: u64,
    pub cutime: i64,
    pub cstime: i64,
    pub priority: i64,
    pub nice: i64,
    pub num_threads: i64,
    pub itrealvalue: i64,
    pub starttime: u64,
    pub vsize: u64,
    pub rss: i64,
    pub rlim: u64,
    pub startcode: u64,
    pub endcode: u64,
    pub startstack: u64,
    pub kstkesp: u64,
    pub kstkeip: u64,
    pub signal: u64,
    pub blocked: u64,
    pub sigignore: u64,
    pub sigcatch: u64,
    pub wchan: u64,
    pub nswap: u64,
    pub cnswap: u64,
    pub exit_signal: i32,
    pub processor: i32,
    pub rt_priority: u64,
    pub policy: u64,
    pub delayacct_blkio_ticks: u64,
}

impl Default for MtproxyProcStats {
    fn default() -> Self {
        Self {
            pid: 0,
            comm: [0; 256],
            state: 0,
            ppid: 0,
            pgrp: 0,
            session: 0,
            tty_nr: 0,
            tpgid: 0,
            flags: 0,
            minflt: 0,
            cminflt: 0,
            majflt: 0,
            cmajflt: 0,
            utime: 0,
            stime: 0,
            cutime: 0,
            cstime: 0,
            priority: 0,
            nice: 0,
            num_threads: 0,
            itrealvalue: 0,
            starttime: 0,
            vsize: 0,
            rss: 0,
            rlim: 0,
            startcode: 0,
            endcode: 0,
            startstack: 0,
            kstkesp: 0,
            kstkeip: 0,
            signal: 0,
            blocked: 0,
            sigignore: 0,
            sigcatch: 0,
            wchan: 0,
            nswap: 0,
            cnswap: 0,
            exit_signal: 0,
            processor: 0,
            rt_priority: 0,
            policy: 0,
            delayacct_blkio_ticks: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyMeminfoSummary {
    pub mem_free: i64,
    pub mem_cached: i64,
    pub swap_total: i64,
    pub swap_free: i64,
    pub found_mask: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyConcurrencyBoundary {
    pub boundary_version: u32,
    pub mpq_contract_ops: u32,
    pub mpq_implemented_ops: u32,
    pub jobs_contract_ops: u32,
    pub jobs_implemented_ops: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyNetworkBoundary {
    pub boundary_version: u32,
    pub net_events_contract_ops: u32,
    pub net_events_implemented_ops: u32,
    pub net_timers_contract_ops: u32,
    pub net_timers_implemented_ops: u32,
    pub net_msg_buffers_contract_ops: u32,
    pub net_msg_buffers_implemented_ops: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyRpcBoundary {
    pub boundary_version: u32,
    pub tcp_rpc_common_contract_ops: u32,
    pub tcp_rpc_common_implemented_ops: u32,
    pub tcp_rpc_client_contract_ops: u32,
    pub tcp_rpc_client_implemented_ops: u32,
    pub tcp_rpc_server_contract_ops: u32,
    pub tcp_rpc_server_implemented_ops: u32,
    pub rpc_targets_contract_ops: u32,
    pub rpc_targets_implemented_ops: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyCryptoBoundary {
    pub boundary_version: u32,
    pub net_crypto_aes_contract_ops: u32,
    pub net_crypto_aes_implemented_ops: u32,
    pub net_crypto_dh_contract_ops: u32,
    pub net_crypto_dh_implemented_ops: u32,
    pub aesni_contract_ops: u32,
    pub aesni_implemented_ops: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MtproxyApplicationBoundary {
    pub boundary_version: u32,
    pub engine_rpc_contract_ops: u32,
    pub engine_rpc_implemented_ops: u32,
    pub mtproto_proxy_contract_ops: u32,
    pub mtproto_proxy_implemented_ops: u32,
}

impl Default for MtproxyTlHeaderParseResult {
    fn default() -> Self {
        Self {
            status: 0,
            consumed: 0,
            op: 0,
            real_op: 0,
            flags: 0,
            qid: 0,
            actor_id: 0,
            errnum: 0,
            error_len: 0,
            error: [0; 192],
        }
    }
}

impl Default for MtproxyMtprotoParseFunctionResult {
    fn default() -> Self {
        Self {
            status: 0,
            consumed: 0,
            errnum: 0,
            error_len: 0,
            error: [0; 192],
        }
    }
}

unsafe extern "C" {
    pub(crate) fn getpid() -> c_int;
    pub(crate) fn time(timer: *mut c_long) -> c_long;
    pub(crate) fn clock_gettime(clock_id: c_int, tp: *mut Timespec) -> c_int;
    pub(crate) fn gettimeofday(tv: *mut Timeval, tz: *mut c_void) -> c_int;
    pub(crate) fn open(pathname: *const c_char, flags: c_int, ...) -> c_int;
    pub(crate) fn close(fd: c_int) -> c_int;
    pub(crate) fn exit(status: c_int) -> !;
    pub(crate) fn lrand48() -> c_long;
    pub(crate) fn drand48() -> c_double;
    pub(crate) fn srand48(seedval: c_long);
    pub(crate) fn malloc(size: usize) -> *mut c_void;
    pub(crate) fn calloc(nmemb: usize, size: usize) -> *mut c_void;
    pub(crate) fn free(ptr: *mut c_void);
    pub(crate) fn kprintf(format: *const c_char, ...);
    pub(crate) fn syntax(msg: *const c_char, ...);
    pub(crate) fn load_config(file: *const c_char, fd: c_int) -> c_int;
    pub(crate) fn reset_config();
    pub(crate) fn md5_hex_config(out: *mut c_char);
    pub(crate) fn cfg_gethost() -> *mut MtproxyHostEnt;
    pub(crate) fn destroy_target(ctj_tag_int: c_int, ctj: MtproxyConnTargetJob) -> c_int;
    pub(crate) fn create_target(
        source: *mut MtproxyConnTargetInfo,
        was_created: *mut c_int,
    ) -> MtproxyConnTargetJob;
    pub(crate) fn create_all_outbound_connections() -> c_int;
    pub(crate) fn kdb_load_hosts() -> c_int;

    pub(crate) static mut default_cfg_min_connections: c_int;
    pub(crate) static mut default_cfg_max_connections: c_int;
    pub(crate) static mut default_cfg_ct: MtproxyConnTargetInfo;
    pub(crate) static mut cfg_cur: *mut c_char;
    pub(crate) static mut cfg_end: *mut c_char;
    pub(crate) static mut config_filename: *mut c_char;
    pub(crate) static mut config_bytes: c_int;
    pub(crate) static mut CurConf: *mut MtproxyMfConfig;
    pub(crate) static mut NextConf: *mut MtproxyMfConfig;
    pub(crate) static mut verbosity: c_int;
}
