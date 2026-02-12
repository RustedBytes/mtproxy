//! Helpers ported from `common/resolver.c`.
//!
//! This module keeps filesystem and libc DNS I/O outside `mtproxy-core` and
//! ports the deterministic resolver logic:
//! - `/etc/hosts` parse and hash-table build
//! - `kdb_load_hosts()` state transitions
//! - `kdb_gethostbyname()` lookup routing decisions
//! - `detect_hostname()` hostname extraction/validation rules

use alloc::vec;
use alloc::vec::Vec;

pub const C_TRANSLATION_UNIT: &str = "common/resolver.c";
pub const HOSTS_FILE: &str = "/etc/hosts";
pub const MAX_HOSTS_SIZE: usize = 1 << 24;
pub const MAX_HOSTNAME_LEN: usize = 64;
pub const MAX_HOST_ALIAS_LEN: usize = 127;
pub const MAX_BRACKETED_IPV6_LEN: usize = 64;
pub const HOSTNAME_BUFFER_CAPACITY: usize = 256;

pub const HOST_HASH_SIZES: [usize; 36] = [
    29, 41, 59, 89, 131, 197, 293, 439, 659, 991, 1_481, 2_221, 3_329, 4_993, 7_487, 11_239,
    16_843, 25_253, 37_879, 56_821, 85_223, 127_837, 191_773, 287_629, 431_441, 647_161, 970_747,
    1_456_121, 2_184_179, 3_276_253, 4_914_373, 7_371_571, 11_057_357, 16_586_039, 24_879_017,
    37_318_507,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostsFileMetadata {
    pub size: i64,
    pub mtime: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostsLoadInput<'a> {
    Error,
    Data {
        metadata: HostsFileMetadata,
        contents: &'a [u8],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildHostsError {
    NoHashSize,
    ParseMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostLookupPlan<'a> {
    /// `name` is `[ipv6-literal]`; strip brackets and use `AF_INET6`.
    Ipv6Literal(&'a [u8]),
    /// Defer to libc/system resolver (`gethostbyname*` path in C).
    SystemDns(&'a [u8]),
    /// Name resolved from loaded `/etc/hosts` cache.
    HostsIpv4(u32),
    /// No dot/colon and absent in hosts table, so C returns `0`.
    NotFound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetectHostnameError {
    Missing,
    InvalidFileBuffer,
    BadHostname,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeResult {
    Found(usize),
    Empty(usize),
    Full,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InternalLoadResult {
    Error,
    Unchanged,
    Loaded,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HostSlot {
    ip: u32,
    name: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostsTable {
    hsize: usize,
    parsed_words: usize,
    htable: Vec<Option<HostSlot>>,
}

impl HostsTable {
    pub fn from_hosts_contents(contents: &[u8]) -> Result<Self, BuildHostsError> {
        let parsed_words = parse_hosts(contents, |_, _| {});
        let Some(hsize) = choose_hash_size(parsed_words) else {
            return Err(BuildHostsError::NoHashSize);
        };

        let mut table = Self {
            hsize,
            parsed_words,
            htable: vec![None; hsize],
        };

        let rebuilt_words = parse_hosts(contents, |name, ip| {
            let _ = table.insert(name, ip);
        });
        if rebuilt_words != parsed_words {
            return Err(BuildHostsError::ParseMismatch);
        }
        Ok(table)
    }

    #[must_use]
    pub const fn hash_size(&self) -> usize {
        self.hsize
    }

    #[must_use]
    pub const fn parsed_words(&self) -> usize {
        self.parsed_words
    }

    #[must_use]
    pub fn lookup_ip(&self, name: &[u8]) -> Option<u32> {
        if name.len() > MAX_HOST_ALIAS_LEN {
            return None;
        }
        match self.probe(name) {
            ProbeResult::Found(idx) => self.htable[idx].as_ref().map(|slot| slot.ip),
            ProbeResult::Empty(_) | ProbeResult::Full => None,
        }
    }

    fn insert(&mut self, name: &[u8], ip: u32) -> bool {
        if ip == 0 || name.is_empty() || name.len() > MAX_HOST_ALIAS_LEN {
            return false;
        }
        match self.probe(name) {
            ProbeResult::Found(_) => true,
            ProbeResult::Empty(idx) => {
                self.htable[idx] = Some(HostSlot {
                    ip,
                    name: name.to_vec(),
                });
                true
            }
            ProbeResult::Full => false,
        }
    }

    fn probe(&self, name: &[u8]) -> ProbeResult {
        if self.hsize < 2 {
            return ProbeResult::Full;
        }
        let (mut h1, h2) = hash_pair(name, self.hsize);
        let mut probes = 0usize;
        while probes < self.hsize {
            match &self.htable[h1] {
                Some(slot) if slot.name.as_slice() == name => return ProbeResult::Found(h1),
                Some(_) => {
                    h1 += h2;
                    if h1 >= self.hsize {
                        h1 -= self.hsize;
                    }
                }
                None => return ProbeResult::Empty(h1),
            }
            probes += 1;
        }
        ProbeResult::Full
    }
}

#[derive(Clone, Debug, Default)]
pub struct ResolverState {
    kdb_hosts_loaded: i32,
    hosts: Option<HostsTable>,
    hosts_metadata: Option<HostsFileMetadata>,
}

impl ResolverState {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            kdb_hosts_loaded: 0,
            hosts: None,
            hosts_metadata: None,
        }
    }

    #[must_use]
    pub const fn kdb_hosts_loaded(&self) -> i32 {
        self.kdb_hosts_loaded
    }

    #[must_use]
    pub fn hosts_table(&self) -> Option<&HostsTable> {
        self.hosts.as_ref()
    }

    #[must_use]
    pub const fn hosts_metadata(&self) -> Option<HostsFileMetadata> {
        self.hosts_metadata
    }

    /// Mirrors `kdb_load_hosts()` return semantics from C:
    /// - `-1`: load failed and no previously loaded cache exists
    /// - `0`: unchanged or load failed while old cache remains active
    /// - `1`: cache loaded/reloaded successfully
    pub fn kdb_load_hosts(&mut self, input: HostsLoadInput<'_>) -> i32 {
        match self.kdb_load_hosts_internal(input) {
            InternalLoadResult::Error => {
                if self.kdb_hosts_loaded <= 0 {
                    self.kdb_hosts_loaded = -1;
                }
                if self.kdb_hosts_loaded < 0 {
                    -1
                } else {
                    0
                }
            }
            InternalLoadResult::Unchanged => {
                debug_assert!(self.kdb_hosts_loaded > 0);
                0
            }
            InternalLoadResult::Loaded => {
                self.kdb_hosts_loaded = 1;
                1
            }
        }
    }

    fn kdb_load_hosts_internal(&mut self, input: HostsLoadInput<'_>) -> InternalLoadResult {
        let HostsLoadInput::Data { metadata, contents } = input else {
            return InternalLoadResult::Error;
        };

        let Ok(size) = usize::try_from(metadata.size) else {
            return InternalLoadResult::Error;
        };
        if size >= MAX_HOSTS_SIZE || contents.len() != size {
            return InternalLoadResult::Error;
        }
        if self.kdb_hosts_loaded > 0 && self.hosts_metadata == Some(metadata) {
            return InternalLoadResult::Unchanged;
        }

        let Ok(table) = HostsTable::from_hosts_contents(contents) else {
            return InternalLoadResult::Error;
        };
        self.hosts = Some(table);
        self.hosts_metadata = Some(metadata);
        InternalLoadResult::Loaded
    }

    #[must_use]
    pub fn kdb_gethostbyname_plan<'a>(&self, name: &'a [u8]) -> HostLookupPlan<'a> {
        if is_bracketed_ipv6_literal(name) {
            return HostLookupPlan::Ipv6Literal(&name[1..name.len() - 1]);
        }

        if self.kdb_hosts_loaded <= 0 || name.len() > MAX_HOST_ALIAS_LEN {
            return HostLookupPlan::SystemDns(name);
        }

        if let Some(ip) = self.hosts.as_ref().and_then(|hosts| hosts.lookup_ip(name)) {
            return HostLookupPlan::HostsIpv4(ip);
        }

        if name.contains(&b'.') || name.contains(&b':') {
            HostLookupPlan::SystemDns(name)
        } else {
            HostLookupPlan::NotFound
        }
    }

    /// C-equivalent lazy path: load hosts once on the first lookup when state
    /// is still `0`.
    #[must_use]
    pub fn kdb_gethostbyname_plan_with_lazy_load<'a, F>(
        &mut self,
        name: &'a [u8],
        mut load_hosts: F,
    ) -> HostLookupPlan<'a>
    where
        F: FnMut(&mut Self),
    {
        if self.kdb_hosts_loaded == 0 {
            load_hosts(self);
        }
        self.kdb_gethostbyname_plan(name)
    }
}

#[must_use]
pub const fn parse_ipv6(_ipv6: &mut [u16; 8], _text: &[u8]) -> i32 {
    -1
}

/// `res->ip` from hosts table is converted with `htonl()` before exposing the
/// bytes as `h_addr`.
#[must_use]
pub const fn host_ip_to_network_order(ip: u32) -> u32 {
    ip.to_be()
}

/// Extracts hostname token from `/etc/hostname` file bytes using C rules:
/// - reject `<= 0` or `>= 256` bytes
/// - skip leading spaces/tabs
/// - take bytes while `byte > 32`
#[must_use]
pub fn parse_hostname_file_buffer(buffer: &[u8]) -> Option<&[u8]> {
    if buffer.is_empty() || buffer.len() >= HOSTNAME_BUFFER_CAPACITY {
        return None;
    }
    let mut start = 0usize;
    while start < buffer.len() && (buffer[start] == b' ' || buffer[start] == b'\t') {
        start += 1;
    }
    let mut end = start;
    while end < buffer.len() && buffer[end] > b' ' {
        end += 1;
    }
    Some(&buffer[start..end])
}

#[must_use]
pub fn is_valid_hostname(hostname: &[u8]) -> bool {
    if hostname.is_empty() || hostname.len() >= MAX_HOSTNAME_LEN {
        return false;
    }
    hostname.iter().copied().all(is_allowed_hostname_byte)
}

pub fn detect_hostname_candidate<'a>(
    env_hostname: Option<&'a [u8]>,
    hostname_file_buffer: Option<&'a [u8]>,
) -> Result<&'a [u8], DetectHostnameError> {
    let candidate = match env_hostname {
        Some(value) if !value.is_empty() => value,
        _ => {
            let Some(file_data) = hostname_file_buffer else {
                return Err(DetectHostnameError::Missing);
            };
            let Some(parsed) = parse_hostname_file_buffer(file_data) else {
                return Err(DetectHostnameError::InvalidFileBuffer);
            };
            parsed
        }
    };

    if candidate.is_empty() {
        return Err(DetectHostnameError::Missing);
    }
    if !is_valid_hostname(candidate) {
        return Err(DetectHostnameError::BadHostname);
    }
    Ok(candidate)
}

fn is_allowed_hostname_byte(byte: u8) -> bool {
    byte.is_ascii_digit()
        || byte.is_ascii_lowercase()
        || byte.is_ascii_uppercase()
        || byte == b'.'
        || byte == b'-'
        || byte == b'_'
}

fn choose_hash_size(parsed_words: usize) -> Option<usize> {
    let need = parsed_words.saturating_mul(2);
    HOST_HASH_SIZES.iter().copied().find(|&size| size > need)
}

fn hash_pair(name: &[u8], hsize: usize) -> (usize, usize) {
    let mut h1 = 0usize;
    let mut h2 = 0usize;
    for &byte in name {
        h1 = (h1.wrapping_mul(17).wrapping_add(usize::from(byte))) % hsize;
        h2 = (h2.wrapping_mul(239).wrapping_add(usize::from(byte))) % (hsize - 1);
    }
    (h1, h2 + 1)
}

fn is_bracketed_ipv6_literal(name: &[u8]) -> bool {
    name.len() >= 2
        && name.len() <= MAX_BRACKETED_IPV6_LEN
        && name[0] == b'['
        && name[name.len() - 1] == b']'
}

fn parse_hosts<F>(contents: &[u8], mut on_host: F) -> usize
where
    F: FnMut(&[u8], u32),
{
    let data = data_until_nul(contents);
    let mut ptr = 0usize;
    let mut ans = 0usize;

    while ptr < data.len() {
        ptr = skip_space(data, ptr);
        let mut ip = 0u32;
        let mut octets = 0usize;

        while octets < 4 {
            let Some(byte) = read_decimal_byte(data, &mut ptr) else {
                break;
            };
            ip = (ip << 8) | u32::from(byte);
            octets += 1;
            if octets < 4 {
                if ptr >= data.len() || data[ptr] != b'.' {
                    break;
                }
                ptr += 1;
            }
        }

        let has_space_after_ip = ptr < data.len() && (data[ptr] == b' ' || data[ptr] == b'\t');
        if octets == 4 && has_space_after_ip && ip != 0 {
            loop {
                let Some(word) = get_word(data, &mut ptr) else {
                    break;
                };
                if word.len() <= MAX_HOST_ALIAS_LEN {
                    on_host(word, ip);
                    ans += 1;
                }
            }
        }

        ptr = skip_to_eol(data, ptr);
    }

    ans
}

fn data_until_nul(contents: &[u8]) -> &[u8] {
    let len = contents
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(contents.len());
    &contents[..len]
}

fn skip_space(data: &[u8], mut idx: usize) -> usize {
    while idx < data.len() && (data[idx] == b' ' || data[idx] == b'\t') {
        idx += 1;
    }
    idx
}

fn skip_to_eol(data: &[u8], mut idx: usize) -> usize {
    while idx < data.len() && data[idx] != b'\n' {
        idx += 1;
    }
    if idx < data.len() {
        idx += 1;
    }
    idx
}

fn get_word<'a>(data: &'a [u8], ptr: &mut usize) -> Option<&'a [u8]> {
    let start = skip_space(data, *ptr);
    let mut end = start;
    while end < data.len() && data[end] != b' ' && data[end] != b'\t' && data[end] != b'\n' {
        end += 1;
    }
    *ptr = end;
    if end == start {
        None
    } else {
        Some(&data[start..end])
    }
}

fn read_decimal_byte(data: &[u8], ptr: &mut usize) -> Option<u8> {
    let start = *ptr;
    if start >= data.len() || !data[start].is_ascii_digit() {
        return None;
    }
    let mut value = 0u32;
    while *ptr < data.len() && data[*ptr].is_ascii_digit() {
        value = value
            .saturating_mul(10)
            .saturating_add(u32::from(data[*ptr] - b'0'));
        *ptr += 1;
    }
    if value > u32::from(u8::MAX) {
        *ptr = start;
        return None;
    }
    u8::try_from(value).ok()
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::{
        detect_hostname_candidate, host_ip_to_network_order, is_valid_hostname,
        parse_hostname_file_buffer, parse_ipv6, BuildHostsError, DetectHostnameError,
        HostLookupPlan, HostsFileMetadata, HostsLoadInput, HostsTable, ResolverState,
        MAX_HOSTS_SIZE,
    };

    #[test]
    fn hosts_table_parses_hosts_entries_and_lookups() {
        let hosts =
            b"127.0.0.1 localhost localhost.localdomain\n192.168.1.5 router\n0.0.0.0 ignored\n";
        let table = HostsTable::from_hosts_contents(hosts).unwrap();
        assert_eq!(table.parsed_words(), 3);
        assert!(table.hash_size() >= 29);
        assert_eq!(table.lookup_ip(b"localhost"), Some(0x7f00_0001));
        assert_eq!(table.lookup_ip(b"router"), Some(0xc0a8_0105));
        assert_eq!(table.lookup_ip(b"missing"), None);
    }

    #[test]
    fn hosts_table_rejects_when_hash_size_pool_is_exhausted() {
        // More than half of the largest prime is intentionally unrepresentable.
        assert_eq!(super::choose_hash_size(18_659_254), None);
        assert_ne!(super::choose_hash_size(18_659_253), None);
        let _ = BuildHostsError::NoHashSize;
    }

    #[test]
    fn resolver_load_semantics_match_c_behavior() {
        let mut state = ResolverState::new();
        assert_eq!(state.kdb_load_hosts(HostsLoadInput::Error), -1);
        assert_eq!(state.kdb_hosts_loaded(), -1);

        let hosts = b"127.0.0.1 localhost\n";
        let metadata = HostsFileMetadata {
            size: i64::try_from(hosts.len()).unwrap(),
            mtime: 10,
        };
        assert_eq!(
            state.kdb_load_hosts(HostsLoadInput::Data {
                metadata,
                contents: hosts
            }),
            1
        );
        assert_eq!(state.kdb_hosts_loaded(), 1);
        assert_eq!(state.kdb_load_hosts(HostsLoadInput::Error), 0);
        assert_eq!(
            state.kdb_gethostbyname_plan(b"localhost"),
            HostLookupPlan::HostsIpv4(0x7f00_0001)
        );

        assert_eq!(
            state.kdb_load_hosts(HostsLoadInput::Data {
                metadata,
                contents: hosts
            }),
            0
        );
    }

    #[test]
    fn resolver_rejects_invalid_snapshot_sizes() {
        let mut state = ResolverState::new();
        let hosts = b"127.0.0.1 localhost\n";
        let mismatched = HostsFileMetadata {
            size: 999,
            mtime: 1,
        };
        assert_eq!(
            state.kdb_load_hosts(HostsLoadInput::Data {
                metadata: mismatched,
                contents: hosts
            }),
            -1
        );

        let too_big = HostsFileMetadata {
            size: i64::try_from(MAX_HOSTS_SIZE).unwrap(),
            mtime: 2,
        };
        assert_eq!(
            state.kdb_load_hosts(HostsLoadInput::Data {
                metadata: too_big,
                contents: &[]
            }),
            -1
        );
    }

    #[test]
    fn lookup_plan_matches_c_fallback_rules() {
        let mut state = ResolverState::new();
        assert_eq!(
            state.kdb_gethostbyname_plan(b"[2001:db8::1]"),
            HostLookupPlan::Ipv6Literal(b"2001:db8::1")
        );
        assert_eq!(
            state.kdb_gethostbyname_plan(b"localhost"),
            HostLookupPlan::SystemDns(b"localhost")
        );

        let hosts = b"10.0.0.1 gw\n";
        let metadata = HostsFileMetadata {
            size: i64::try_from(hosts.len()).unwrap(),
            mtime: 3,
        };
        assert_eq!(
            state.kdb_load_hosts(HostsLoadInput::Data {
                metadata,
                contents: hosts
            }),
            1
        );
        assert_eq!(
            state.kdb_gethostbyname_plan(b"gw"),
            HostLookupPlan::HostsIpv4(0x0a00_0001)
        );
        assert_eq!(
            state.kdb_gethostbyname_plan(b"unknown"),
            HostLookupPlan::NotFound
        );
        assert_eq!(
            state.kdb_gethostbyname_plan(b"unknown.example"),
            HostLookupPlan::SystemDns(b"unknown.example")
        );

        let long_name = std::vec![b'a'; 128];
        assert_eq!(
            state.kdb_gethostbyname_plan(&long_name),
            HostLookupPlan::SystemDns(long_name.as_slice())
        );
    }

    #[test]
    fn lazy_load_helper_runs_once_when_state_is_zero() {
        let mut state = ResolverState::new();
        let hosts = b"127.0.0.1 localhost\n";
        let metadata = HostsFileMetadata {
            size: i64::try_from(hosts.len()).unwrap(),
            mtime: 4,
        };
        let mut load_calls = 0usize;
        let plan = state.kdb_gethostbyname_plan_with_lazy_load(b"localhost", |resolver| {
            load_calls += 1;
            let _ = resolver.kdb_load_hosts(HostsLoadInput::Data {
                metadata,
                contents: hosts,
            });
        });
        assert_eq!(load_calls, 1);
        assert_eq!(plan, HostLookupPlan::HostsIpv4(0x7f00_0001));

        let _ = state.kdb_gethostbyname_plan_with_lazy_load(b"localhost", |_| {
            load_calls += 1;
        });
        assert_eq!(load_calls, 1);
    }

    #[test]
    fn hostname_file_parsing_and_validation_match_c_rules() {
        assert_eq!(
            parse_hostname_file_buffer(b" \tproxy-node-1 \nignored"),
            Some(b"proxy-node-1".as_slice())
        );
        assert_eq!(parse_hostname_file_buffer(b""), None);
        assert_eq!(parse_hostname_file_buffer(&[b'a'; 256]), None);

        assert!(is_valid_hostname(b"proxy-node_1.example"));
        assert!(!is_valid_hostname(b""));
        assert!(!is_valid_hostname(b"bad host"));
        assert!(!is_valid_hostname(&[b'a'; 64]));
    }

    #[test]
    fn detect_hostname_prefers_env_and_applies_validation() {
        assert_eq!(
            detect_hostname_candidate(Some(b"from-env"), Some(b"from-file\n")),
            Ok(b"from-env".as_slice())
        );
        assert_eq!(
            detect_hostname_candidate(Some(b""), Some(b"  from-file\nmore")),
            Ok(b"from-file".as_slice())
        );
        assert_eq!(
            detect_hostname_candidate(None, Some(b" \t \n")),
            Err(DetectHostnameError::Missing)
        );
        assert_eq!(
            detect_hostname_candidate(None, Some(&[b'a'; 256])),
            Err(DetectHostnameError::InvalidFileBuffer)
        );
        assert_eq!(
            detect_hostname_candidate(Some(b"bad host"), None),
            Err(DetectHostnameError::BadHostname)
        );
    }

    #[test]
    fn parse_ipv6_stub_matches_c() {
        let mut out = [0u16; 8];
        assert_eq!(parse_ipv6(&mut out, b"::1"), -1);
    }

    #[test]
    fn network_order_conversion_matches_c_htonl_intent() {
        let be = host_ip_to_network_order(0x7f00_0001);
        assert_eq!(be.to_ne_bytes(), [127, 0, 0, 1]);
    }
}
