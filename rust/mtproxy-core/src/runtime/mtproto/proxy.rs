//! Rust runtime model for `mtproto/mtproto-proxy.c`.
//!
//! This module ports deterministic proxy logic that can be migrated without
//! direct socket/event-loop coupling:
//! - external-connection ID/hash/tag helpers
//! - external-connection table lifecycle and LRU order
//! - TL-backed proxy request envelope build/parse
//! - mtproto packet classification helpers
//! - text IPv4/IPv6 parsing helpers used by HTTP ingress

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::vec;
use alloc::vec::Vec;
use core::convert::TryFrom;

use crate::runtime::config::tl_parse::{
    parse_answer_header, parse_query_header, TlError, TlInState, TlOutState, TL_ERROR_HEADER,
    TL_ERROR_NOT_ENOUGH_DATA,
};

pub const EXT_CONN_TABLE_SIZE: usize = 1 << 22;
pub const EXT_CONN_HASH_SHIFT: u32 = 20;
pub const EXT_CONN_HASH_SIZE: usize = 1 << EXT_CONN_HASH_SHIFT;

pub const TL_HTTP_QUERY_INFO: i32 = i32::from_ne_bytes(0xd45a_b381_u32.to_ne_bytes());
pub const TL_PROXY_TAG: i32 = i32::from_ne_bytes(0xdb1e_26ae_u32.to_ne_bytes());

pub const CODE_REQ_PQ: i32 = 0x6046_9778;
pub const CODE_REQ_PQ_MULTI: i32 = i32::from_ne_bytes(0xbe7e_8ef1_u32.to_ne_bytes());
pub const CODE_REQ_DH_PARAMS: i32 = i32::from_ne_bytes(0xd712_e4be_u32.to_ne_bytes());
pub const CODE_SET_CLIENT_DH_PARAMS: i32 = i32::from_ne_bytes(0xf504_5f1f_u32.to_ne_bytes());

pub const RPC_PROXY_REQ: i32 = 0x36ce_f1ee;
pub const RPC_PROXY_ANS: i32 = 0x4403_da0d;
pub const RPC_CLOSE_CONN: i32 = 0x1fcf_425d;
pub const RPC_CLOSE_EXT: i32 = 0x5eb6_34a2;
pub const RPC_SIMPLE_ACK: i32 = 0x3bac_409b;
pub const RPC_PONG: i32 = i32::from_ne_bytes(0x8430_eaa7_u32.to_ne_bytes());

pub const TL_ERROR_UNKNOWN_FUNCTION_ID: i32 = -2000;
pub const TL_ERROR_WRONG_ACTOR_ID: i32 = -2002;

const MTPROTO_EXT_CONN_HASH_MULT_A: u64 = 11_400_714_819_323_198_485;
const MTPROTO_EXT_CONN_HASH_MULT_B: u64 = 13_043_817_825_332_782_213;

const LRAND48_MULT: u64 = 0x5deece66d;
const LRAND48_ADD: u64 = 0xb;
const LRAND48_MASK: u64 = (1_u64 << 48) - 1;
const LRAND48_SEED_LOW: u64 = 0x330e;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExtConnection {
    pub in_fd: i32,
    pub in_gen: i32,
    pub out_fd: i32,
    pub out_gen: i32,
    pub in_conn_id: i64,
    pub out_conn_id: i64,
    pub auth_key_id: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtConnLookupMode {
    Find,
    Delete,
    CreateIfMissing,
    FindOrCreate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtConnLookupOutcome {
    NotFound,
    AlreadyExists,
    Found(ExtConnection),
    Created(ExtConnection),
    Deleted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExtConnTableError {
    InvalidTableSize,
    InvalidHashShift,
    DuplicateInFdLinks,
    MissingConnection,
    AlreadyBound,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpQueryInfo<'a> {
    pub origin: &'a [u8],
    pub referer: &'a [u8],
    pub user_agent: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyReqBuildInput<'a> {
    pub flags: i32,
    pub out_conn_id: i64,
    pub remote_ipv6: [u8; 16],
    pub remote_port: i32,
    pub our_ipv6: [u8; 16],
    pub our_port: i32,
    pub proxy_tag: Option<&'a [u8]>,
    pub http_query_info: Option<HttpQueryInfo<'a>>,
    pub payload: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyReqView<'a> {
    pub flags: i32,
    pub out_conn_id: i64,
    pub remote_ipv6: [u8; 16],
    pub remote_port: i32,
    pub our_ipv6: [u8; 16],
    pub our_port: i32,
    pub extra: &'a [u8],
    pub payload: &'a [u8],
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProxyReqExtra {
    pub proxy_tag: Option<Vec<u8>>,
    pub http_origin: Option<Vec<u8>>,
    pub http_referer: Option<Vec<u8>>,
    pub http_user_agent: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MtprotoPacketKind {
    Encrypted { auth_key_id: i64 },
    UnencryptedDh { inner_len: i32, function: i32 },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpcClientPacket<'a> {
    Pong,
    ProxyAns {
        flags: i32,
        out_conn_id: i64,
        payload: &'a [u8],
    },
    SimpleAck {
        out_conn_id: i64,
        confirm: i32,
    },
    CloseExt {
        out_conn_id: i64,
    },
    Unknown {
        op: i32,
    },
    Malformed {
        op: i32,
    },
}

#[derive(Clone, Debug)]
struct ExtConnEntry {
    conn: ExtConnection,
    slot: usize,
    lru_prev: Option<usize>,
    lru_next: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct ExtConnectionTable {
    table_size: usize,
    table_mask: usize,
    hash_shift: u32,
    lrand48_state: u64,
    entries: Vec<Option<ExtConnEntry>>,
    free_entries: Vec<usize>,
    by_in_key: BTreeMap<(i32, i64), usize>,
    by_in_fd: BTreeMap<i32, Vec<usize>>,
    by_out_fd: BTreeMap<i32, Vec<usize>>,
    by_out_conn_id: BTreeMap<i64, usize>,
    out_slot_owner: BTreeMap<usize, usize>,
    out_slot_last_conn_id: BTreeMap<usize, i64>,
    lru_head: Option<usize>,
    lru_tail: Option<usize>,
    ext_connections: usize,
    ext_connections_created: usize,
}

impl ExtConnectionTable {
    #[must_use]
    pub fn new() -> Self {
        Self::with_sizes(EXT_CONN_TABLE_SIZE, EXT_CONN_HASH_SHIFT, 0x1234_5678).unwrap_or_else(
            |_| Self {
                table_size: EXT_CONN_TABLE_SIZE,
                table_mask: EXT_CONN_TABLE_SIZE - 1,
                hash_shift: EXT_CONN_HASH_SHIFT,
                lrand48_state: ((0x1234_5678_u64 << 16) | LRAND48_SEED_LOW) & LRAND48_MASK,
                entries: Vec::new(),
                free_entries: Vec::new(),
                by_in_key: BTreeMap::new(),
                by_in_fd: BTreeMap::new(),
                by_out_fd: BTreeMap::new(),
                by_out_conn_id: BTreeMap::new(),
                out_slot_owner: BTreeMap::new(),
                out_slot_last_conn_id: BTreeMap::new(),
                lru_head: None,
                lru_tail: None,
                ext_connections: 0,
                ext_connections_created: 0,
            },
        )
    }

    pub fn with_sizes(
        table_size: usize,
        hash_shift: u32,
        lrand48_seed: u64,
    ) -> Result<Self, ExtConnTableError> {
        if table_size == 0 || (table_size & (table_size - 1)) != 0 {
            return Err(ExtConnTableError::InvalidTableSize);
        }
        if hash_shift == 0 || hash_shift >= 32 {
            return Err(ExtConnTableError::InvalidHashShift);
        }
        let max_bucket = 1_usize
            .checked_shl(hash_shift)
            .ok_or(ExtConnTableError::InvalidHashShift)?;
        if max_bucket == 0 {
            return Err(ExtConnTableError::InvalidHashShift);
        }
        Ok(Self {
            table_size,
            table_mask: table_size - 1,
            hash_shift,
            lrand48_state: ((lrand48_seed << 16) | LRAND48_SEED_LOW) & LRAND48_MASK,
            entries: Vec::new(),
            free_entries: Vec::new(),
            by_in_key: BTreeMap::new(),
            by_in_fd: BTreeMap::new(),
            by_out_fd: BTreeMap::new(),
            by_out_conn_id: BTreeMap::new(),
            out_slot_owner: BTreeMap::new(),
            out_slot_last_conn_id: BTreeMap::new(),
            lru_head: None,
            lru_tail: None,
            ext_connections: 0,
            ext_connections_created: 0,
        })
    }

    #[must_use]
    pub const fn table_size(&self) -> usize {
        self.table_size
    }

    #[must_use]
    pub const fn hash_shift(&self) -> u32 {
        self.hash_shift
    }

    #[must_use]
    pub const fn ext_connections(&self) -> usize {
        self.ext_connections
    }

    #[must_use]
    pub const fn ext_connections_created(&self) -> usize {
        self.ext_connections_created
    }

    fn lrand48_next(&mut self) -> usize {
        self.lrand48_state = (self
            .lrand48_state
            .wrapping_mul(LRAND48_MULT)
            .wrapping_add(LRAND48_ADD))
            & LRAND48_MASK;
        let value = (self.lrand48_state >> 17) & 0x7fff_ffff;
        usize::try_from(value).unwrap_or(0)
    }

    fn alloc_entry_slot(&mut self) -> usize {
        match self.free_entries.pop() {
            Some(idx) => idx,
            None => {
                let idx = self.entries.len();
                self.entries.push(None);
                idx
            }
        }
    }

    fn index_for_in_key(&self, in_fd: i32, in_conn_id: i64) -> Option<usize> {
        self.by_in_key.get(&(in_fd, in_conn_id)).copied()
    }

    fn entry_ref(&self, idx: usize) -> Option<&ExtConnEntry> {
        self.entries.get(idx).and_then(Option::as_ref)
    }

    fn entry_mut(&mut self, idx: usize) -> Option<&mut ExtConnEntry> {
        self.entries.get_mut(idx).and_then(Option::as_mut)
    }

    fn map_push(map: &mut BTreeMap<i32, Vec<usize>>, key: i32, idx: usize) {
        map.entry(key).or_default().push(idx);
    }

    fn map_remove_index(map: &mut BTreeMap<i32, Vec<usize>>, key: i32, idx: usize) {
        if let Some(indices) = map.get_mut(&key) {
            indices.retain(|v| *v != idx);
            if indices.is_empty() {
                map.remove(&key);
            }
        }
    }

    fn pick_free_out_slot(&mut self, in_fd: i32, in_conn_id: i64) -> usize {
        let mut h = if in_conn_id != 0 {
            self.lrand48_next()
        } else {
            usize::try_from(i64::from(in_fd)).unwrap_or(0)
        };
        loop {
            let slot = h & self.table_mask;
            if !self.out_slot_owner.contains_key(&slot) {
                return slot;
            }
            h = self.lrand48_next();
        }
    }

    fn alloc_out_conn_id(&mut self, slot: usize) -> i64 {
        let prev = self.out_slot_last_conn_id.get(&slot).copied().unwrap_or(0);
        let mask_i64 = i64::try_from(self.table_mask).unwrap_or(i64::MAX);
        let slot_i64 = i64::try_from(slot).unwrap_or(0);
        let next = (prev | mask_i64).wrapping_add(1).wrapping_add(slot_i64);
        self.out_slot_last_conn_id.insert(slot, next);
        next
    }

    pub fn get_ext_connection_by_in_fd(
        &self,
        in_fd: i32,
    ) -> Result<Option<ExtConnection>, ExtConnTableError> {
        let Some(indices) = self.by_in_fd.get(&in_fd) else {
            return Ok(None);
        };
        let mut active = None;
        for idx in indices {
            if let Some(entry) = self.entry_ref(*idx) {
                if active.is_some() {
                    return Err(ExtConnTableError::DuplicateInFdLinks);
                }
                active = Some(entry.conn);
            }
        }
        Ok(active)
    }

    #[must_use]
    pub fn find_ext_connection_by_out_conn_id(&self, out_conn_id: i64) -> Option<ExtConnection> {
        let idx = self.by_out_conn_id.get(&out_conn_id).copied()?;
        let entry = self.entry_ref(idx)?;
        Some(entry.conn)
    }

    pub fn get_ext_connection_by_in_conn_id(
        &mut self,
        in_fd: i32,
        in_gen: i32,
        in_conn_id: i64,
        mode: ExtConnLookupMode,
    ) -> Result<ExtConnLookupOutcome, ExtConnTableError> {
        if let Some(idx) = self.index_for_in_key(in_fd, in_conn_id) {
            let conn = self
                .entry_ref(idx)
                .map(|entry| entry.conn)
                .ok_or(ExtConnTableError::MissingConnection)?;
            return match mode {
                ExtConnLookupMode::Find | ExtConnLookupMode::FindOrCreate => {
                    Ok(ExtConnLookupOutcome::Found(conn))
                }
                ExtConnLookupMode::CreateIfMissing => Ok(ExtConnLookupOutcome::AlreadyExists),
                ExtConnLookupMode::Delete => {
                    let _ = self.remove_ext_connection_index(idx);
                    Ok(ExtConnLookupOutcome::Deleted)
                }
            };
        }

        if mode != ExtConnLookupMode::CreateIfMissing && mode != ExtConnLookupMode::FindOrCreate {
            return Ok(ExtConnLookupOutcome::NotFound);
        }

        let slot = self.pick_free_out_slot(in_fd, in_conn_id);
        let out_conn_id = self.alloc_out_conn_id(slot);
        let idx = self.alloc_entry_slot();
        let entry = ExtConnEntry {
            conn: ExtConnection {
                in_fd,
                in_gen,
                out_fd: 0,
                out_gen: 0,
                in_conn_id,
                out_conn_id,
                auth_key_id: 0,
            },
            slot,
            lru_prev: None,
            lru_next: None,
        };
        self.entries[idx] = Some(entry);
        self.by_in_key.insert((in_fd, in_conn_id), idx);
        if in_fd != 0 {
            Self::map_push(&mut self.by_in_fd, in_fd, idx);
        }
        self.by_out_conn_id.insert(out_conn_id, idx);
        self.out_slot_owner.insert(slot, idx);
        self.ext_connections = self.ext_connections.saturating_add(1);
        self.ext_connections_created = self.ext_connections_created.saturating_add(1);

        let created = self
            .entry_ref(idx)
            .map(|created_entry| created_entry.conn)
            .ok_or(ExtConnTableError::MissingConnection)?;
        Ok(ExtConnLookupOutcome::Created(created))
    }

    pub fn bind_ext_connection(
        &mut self,
        in_fd: i32,
        in_conn_id: i64,
        out_fd: Option<(i32, i32)>,
        auth_key_id: i64,
    ) -> Result<ExtConnection, ExtConnTableError> {
        let idx = self
            .index_for_in_key(in_fd, in_conn_id)
            .ok_or(ExtConnTableError::MissingConnection)?;
        let mut map_out_fd = None;
        let conn = {
            let entry = self
                .entry_mut(idx)
                .ok_or(ExtConnTableError::MissingConnection)?;
            if entry.conn.out_fd != 0 && out_fd.is_some() {
                return Err(ExtConnTableError::AlreadyBound);
            }
            if let Some((out_fd_val, out_gen)) = out_fd {
                entry.conn.out_fd = out_fd_val;
                entry.conn.out_gen = out_gen;
                map_out_fd = Some(out_fd_val);
            }
            entry.conn.auth_key_id = auth_key_id;
            entry.conn
        };
        if let Some(out_fd_val) = map_out_fd {
            Self::map_push(&mut self.by_out_fd, out_fd_val, idx);
        }
        Ok(conn)
    }

    pub fn update_auth_key(
        &mut self,
        in_fd: i32,
        in_conn_id: i64,
        auth_key_id: i64,
    ) -> Result<(), ExtConnTableError> {
        let idx = self
            .index_for_in_key(in_fd, in_conn_id)
            .ok_or(ExtConnTableError::MissingConnection)?;
        let entry = self
            .entry_mut(idx)
            .ok_or(ExtConnTableError::MissingConnection)?;
        entry.conn.auth_key_id = auth_key_id;
        Ok(())
    }

    pub fn remove_ext_connection_by_out_conn_id(&mut self, out_conn_id: i64) -> bool {
        let Some(idx) = self.by_out_conn_id.get(&out_conn_id).copied() else {
            return false;
        };
        self.remove_ext_connection_index(idx)
    }

    pub fn remove_ext_connection_by_in_conn_id(&mut self, in_fd: i32, in_conn_id: i64) -> bool {
        let Some(idx) = self.index_for_in_key(in_fd, in_conn_id) else {
            return false;
        };
        self.remove_ext_connection_index(idx)
    }

    fn remove_ext_connection_index(&mut self, idx: usize) -> bool {
        let Some(entry) = self.entry_ref(idx).cloned() else {
            return false;
        };
        self.lru_delete_index(idx);
        self.by_in_key
            .remove(&(entry.conn.in_fd, entry.conn.in_conn_id));
        if entry.conn.in_fd != 0 {
            Self::map_remove_index(&mut self.by_in_fd, entry.conn.in_fd, idx);
        }
        if entry.conn.out_fd != 0 {
            Self::map_remove_index(&mut self.by_out_fd, entry.conn.out_fd, idx);
        }
        self.by_out_conn_id.remove(&entry.conn.out_conn_id);
        self.out_slot_owner.remove(&entry.slot);
        self.entries[idx] = None;
        self.free_entries.push(idx);
        self.ext_connections = self.ext_connections.saturating_sub(1);
        true
    }

    fn lru_delete_index(&mut self, idx: usize) {
        let Some((prev, next)) = self
            .entry_ref(idx)
            .map(|entry| (entry.lru_prev, entry.lru_next))
        else {
            return;
        };
        if prev.is_none() && next.is_none() && self.lru_head != Some(idx) {
            return;
        }

        if let Some(prev_idx) = prev {
            if let Some(prev_entry) = self.entry_mut(prev_idx) {
                prev_entry.lru_next = next;
            }
        } else {
            self.lru_head = next;
        }
        if let Some(next_idx) = next {
            if let Some(next_entry) = self.entry_mut(next_idx) {
                next_entry.lru_prev = prev;
            }
        } else {
            self.lru_tail = prev;
        }
        if let Some(entry) = self.entry_mut(idx) {
            entry.lru_prev = None;
            entry.lru_next = None;
        }
    }

    fn lru_insert_index(&mut self, idx: usize) {
        self.lru_delete_index(idx);
        let old_tail = self.lru_tail;
        if let Some(entry) = self.entry_mut(idx) {
            entry.lru_prev = old_tail;
            entry.lru_next = None;
        }
        if let Some(tail_idx) = old_tail {
            if let Some(tail_entry) = self.entry_mut(tail_idx) {
                tail_entry.lru_next = Some(idx);
            }
        } else {
            self.lru_head = Some(idx);
        }
        self.lru_tail = Some(idx);
    }

    pub fn lru_delete_by_in_fd(&mut self, in_fd: i32) -> Result<bool, ExtConnTableError> {
        let Some(conn) = self.get_ext_connection_by_in_fd(in_fd)? else {
            return Ok(false);
        };
        let Some(idx) = self.index_for_in_key(conn.in_fd, conn.in_conn_id) else {
            return Ok(false);
        };
        self.lru_delete_index(idx);
        Ok(true)
    }

    pub fn lru_insert_by_in_fd_gen(
        &mut self,
        in_fd: i32,
        in_gen: i32,
    ) -> Result<bool, ExtConnTableError> {
        let Some(conn) = self.get_ext_connection_by_in_fd(in_fd)? else {
            return Ok(false);
        };
        if conn.in_gen != in_gen {
            return Ok(false);
        }
        let Some(idx) = self.index_for_in_key(conn.in_fd, conn.in_conn_id) else {
            return Ok(false);
        };
        self.lru_insert_index(idx);
        Ok(true)
    }

    #[must_use]
    pub fn lru_pop_oldest(&mut self) -> Option<ExtConnection> {
        let idx = self.lru_head?;
        let conn = self.entry_ref(idx)?.conn;
        self.lru_delete_index(idx);
        Some(conn)
    }
}

impl Default for ExtConnectionTable {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use]
pub fn mtproto_ext_conn_hash(in_fd: i32, in_conn_id: i64, hash_shift: i32) -> i32 {
    if !(1..=31).contains(&hash_shift) {
        return -1;
    }
    let shift_u = u32::try_from(hash_shift).unwrap_or(0);
    let in_fd_u = u64::from_ne_bytes(i64::from(in_fd).to_ne_bytes());
    let in_conn_id_u = u64::from_ne_bytes(in_conn_id.to_ne_bytes());
    let h = in_fd_u
        .wrapping_mul(MTPROTO_EXT_CONN_HASH_MULT_A)
        .wrapping_add(in_conn_id_u.wrapping_mul(MTPROTO_EXT_CONN_HASH_MULT_B));
    let value = h >> (64 - shift_u);
    i32::try_from(value).unwrap_or(-1)
}

#[must_use]
pub const fn mtproto_conn_tag(generation: i32) -> i32 {
    1 + (generation & 0x00ff_ffff)
}

#[must_use]
pub fn parse_text_ipv4(input: &str) -> u32 {
    let mut iter = input.split('.');
    let parse_part = |part: Option<&str>| -> Option<i32> { part?.trim().parse::<i32>().ok() };
    let Some(a) = parse_part(iter.next()) else {
        return 0;
    };
    let Some(b) = parse_part(iter.next()) else {
        return 0;
    };
    let Some(c) = parse_part(iter.next()) else {
        return 0;
    };
    let Some(d) = parse_part(iter.next()) else {
        return 0;
    };
    if iter.next().is_some() {
        return 0;
    }
    if ((a | b | c | d) & !0xff) != 0 {
        return 0;
    }
    let au = u32::try_from(a).unwrap_or(0);
    let bu = u32::try_from(b).unwrap_or(0);
    let cu = u32::try_from(c).unwrap_or(0);
    let du = u32::try_from(d).unwrap_or(0);
    (au << 24) | (bu << 16) | (cu << 8) | du
}

#[must_use]
pub fn parse_text_ipv6(ip: &mut [u8; 16], input: &str) -> i32 {
    let bytes = input.as_bytes();
    let mut ptr = 0usize;
    let mut k: Option<usize> = None;

    if bytes.get(0) == Some(&b':') && bytes.get(1) == Some(&b':') {
        k = Some(0);
        ptr = 2;
    }

    let mut i = 0usize;
    while i < 8 {
        let mut c = bytes.get(ptr).copied().unwrap_or(0);
        if i > 0 {
            if c == b':' {
                ptr = ptr.saturating_add(1);
                c = bytes.get(ptr).copied().unwrap_or(0);
            } else if k.is_some() {
                break;
            } else {
                return -1;
            }
            if c == b':' {
                if k.is_some() {
                    return -1;
                }
                k = Some(i);
                ptr = ptr.saturating_add(1);
                c = bytes.get(ptr).copied().unwrap_or(0);
            }
        }

        let mut j = 0usize;
        let mut value = 0u32;
        while c.is_ascii_hexdigit() {
            let lower = c | 0x20;
            value = (value << 4)
                + if lower <= b'9' {
                    u32::from(lower - b'0')
                } else {
                    u32::from(lower - b'a' + 10)
                };
            j = j.saturating_add(1);
            if j > 4 {
                return -1;
            }
            ptr = ptr.saturating_add(1);
            c = bytes.get(ptr).copied().unwrap_or(0);
        }

        if j == 0 {
            if k == Some(i) {
                break;
            }
            return -1;
        }

        ip[2 * i] = u8::try_from(value >> 8).unwrap_or(0);
        ip[2 * i + 1] = u8::try_from(value & 0xff).unwrap_or(0);
        i = i.saturating_add(1);
    }

    if ptr != bytes.len() {
        return -1;
    }

    if i < 8 {
        let Some(kv) = k else {
            return -1;
        };
        if kv > i {
            return -1;
        }
        let gap = 2 * (8 - i);
        let move_len = 2 * (i - kv);
        if move_len > 0 {
            ip.copy_within((2 * kv)..(2 * kv + move_len), 2 * kv + gap);
        }
        ip[(2 * kv)..(2 * kv + gap)].fill(0);
    }

    i32::try_from(ptr).unwrap_or(-1)
}

fn read_i32_le(data: &[u8], offset: usize) -> Option<i32> {
    let end = offset.checked_add(4)?;
    let bytes: [u8; 4] = data.get(offset..end)?.try_into().ok()?;
    Some(i32::from_le_bytes(bytes))
}

fn read_i64_le(data: &[u8], offset: usize) -> Option<i64> {
    let end = offset.checked_add(8)?;
    let bytes: [u8; 8] = data.get(offset..end)?.try_into().ok()?;
    Some(i64::from_le_bytes(bytes))
}

#[must_use]
pub fn inspect_mtproto_packet(data: &[u8]) -> Option<MtprotoPacketKind> {
    let packet_len = i32::try_from(data.len()).ok()?;
    inspect_mtproto_packet_header(data, packet_len)
}

#[must_use]
pub fn inspect_mtproto_packet_header(data: &[u8], packet_len: i32) -> Option<MtprotoPacketKind> {
    if packet_len < 28 || (packet_len & 3) != 0 {
        return None;
    }
    if data.len() < 24 {
        return None;
    }

    let auth_key_id = read_i64_le(data, 0)?;
    if auth_key_id != 0 {
        return Some(MtprotoPacketKind::Encrypted { auth_key_id });
    }

    let inner_len = read_i32_le(data, 16)?;
    if inner_len.saturating_add(20) > packet_len {
        return None;
    }
    if inner_len < 20 {
        return None;
    }
    let function = read_i32_le(data, 20)?;
    if function != CODE_REQ_PQ
        && function != CODE_REQ_PQ_MULTI
        && function != CODE_REQ_DH_PARAMS
        && function != CODE_SET_CLIENT_DH_PARAMS
    {
        return None;
    }
    Some(MtprotoPacketKind::UnencryptedDh {
        inner_len,
        function,
    })
}

pub fn build_rpc_proxy_req(
    out: &mut [u8],
    input: &ProxyReqBuildInput<'_>,
) -> Result<usize, TlError> {
    fn tl_string_encoded_len(len: usize) -> usize {
        let header = if len < 254 { 1usize } else { 4usize };
        let raw = header.saturating_add(len);
        raw.saturating_add((4 - (raw & 3)) & 3)
    }

    if (input.flags & 8) != 0 && input.proxy_tag.is_none() {
        return Err(TlError::new(
            TL_ERROR_HEADER,
            "RPC_PROXY_REQ flag 0x8 requires proxy_tag",
        ));
    }
    if (input.flags & 4) != 0 && input.http_query_info.is_none() {
        return Err(TlError::new(
            TL_ERROR_HEADER,
            "RPC_PROXY_REQ flag 0x4 requires HTTP query info",
        ));
    }

    let mut out_state = TlOutState::new_str(out, 0);
    out_state.store_int(RPC_PROXY_REQ)?;
    out_state.store_int(input.flags)?;
    out_state.store_long(input.out_conn_id)?;
    out_state.store_raw_data(&input.remote_ipv6)?;
    out_state.store_int(input.remote_port)?;
    out_state.store_raw_data(&input.our_ipv6)?;
    out_state.store_int(input.our_port)?;

    if (input.flags & 12) != 0 {
        let mut extra_cap = 0usize;
        if (input.flags & 8) != 0 {
            let proxy_tag = input.proxy_tag.unwrap_or_default();
            extra_cap = extra_cap.saturating_add(4);
            extra_cap = extra_cap.saturating_add(tl_string_encoded_len(proxy_tag.len()));
        }
        if (input.flags & 4) != 0 {
            let http_info = input.http_query_info.unwrap_or(HttpQueryInfo {
                origin: &[],
                referer: &[],
                user_agent: &[],
            });
            extra_cap = extra_cap.saturating_add(4);
            extra_cap = extra_cap.saturating_add(tl_string_encoded_len(http_info.origin.len()));
            extra_cap = extra_cap.saturating_add(tl_string_encoded_len(http_info.referer.len()));
            extra_cap = extra_cap.saturating_add(tl_string_encoded_len(http_info.user_agent.len()));
        }

        let mut extra_buf = vec![0u8; extra_cap];
        let mut extra_state = TlOutState::new_str(&mut extra_buf, 0);

        if (input.flags & 8) != 0 {
            extra_state.store_int(TL_PROXY_TAG)?;
            if let Some(proxy_tag) = input.proxy_tag {
                extra_state.store_string(proxy_tag)?;
            }
        }
        if (input.flags & 4) != 0 {
            extra_state.store_int(TL_HTTP_QUERY_INFO)?;
            if let Some(http_info) = input.http_query_info {
                extra_state.store_string(http_info.origin)?;
                extra_state.store_string(http_info.referer)?;
                extra_state.store_string(http_info.user_agent)?;
            }
        }

        let extra_size = extra_state.out_pos();
        let extra_size_i32 = i32::try_from(extra_size).unwrap_or(i32::MAX);
        out_state.store_int(extra_size_i32)?;
        out_state.store_raw_data(&extra_buf[..extra_size])?;
    }

    out_state.store_raw_data(input.payload)?;
    Ok(out_state.out_pos())
}

pub fn parse_rpc_proxy_req(data: &[u8]) -> Result<ProxyReqView<'_>, TlError> {
    let mut in_state = TlInState::new(data);
    let op = in_state.fetch_int()?;
    if op != RPC_PROXY_REQ {
        return Err(TlError::new(
            TL_ERROR_HEADER,
            format!("Expected RPC_PROXY_REQ, got 0x{op:08x}"),
        ));
    }

    let flags = in_state.fetch_int()?;
    let out_conn_id = in_state.fetch_long()?;

    let mut remote_ipv6 = [0u8; 16];
    let _ = in_state.fetch_raw_data(&mut remote_ipv6)?;
    let remote_port = in_state.fetch_int()?;

    let mut our_ipv6 = [0u8; 16];
    let _ = in_state.fetch_raw_data(&mut our_ipv6)?;
    let our_port = in_state.fetch_int()?;

    let mut extra = &[][..];
    if (flags & 12) != 0 {
        let extra_len_i32 = in_state.fetch_int()?;
        if extra_len_i32 < 0 {
            return Err(TlError::new(
                TL_ERROR_HEADER,
                format!("Negative RPC_PROXY_REQ extra length: {extra_len_i32}"),
            ));
        }
        let extra_len = usize::try_from(extra_len_i32).unwrap_or(usize::MAX);
        let extra_start = in_state.position();
        let _ = in_state.skip(extra_len)?;
        extra = data
            .get(extra_start..extra_start.saturating_add(extra_len))
            .ok_or_else(|| {
                TlError::new(
                    TL_ERROR_NOT_ENOUGH_DATA,
                    "RPC_PROXY_REQ extra slice out of bounds",
                )
            })?;
    }

    let payload_start = in_state.position();
    let payload = data.get(payload_start..).ok_or_else(|| {
        TlError::new(
            TL_ERROR_NOT_ENOUGH_DATA,
            "RPC_PROXY_REQ payload slice out of bounds",
        )
    })?;

    Ok(ProxyReqView {
        flags,
        out_conn_id,
        remote_ipv6,
        remote_port,
        our_ipv6,
        our_port,
        extra,
        payload,
    })
}

pub fn parse_rpc_proxy_req_extra(extra: &[u8]) -> Result<ProxyReqExtra, TlError> {
    let mut in_state = TlInState::new(extra);
    let mut parsed = ProxyReqExtra::default();
    while in_state.unread() > 0 {
        let tag = in_state.fetch_int()?;
        match tag {
            TL_PROXY_TAG => {
                let mut buf = vec![0u8; 512];
                let len = in_state.fetch_string(&mut buf, 512)?;
                buf.truncate(len);
                parsed.proxy_tag = Some(buf);
            }
            TL_HTTP_QUERY_INFO => {
                let mut origin = vec![0u8; 1024];
                let mut referer = vec![0u8; 1024];
                let mut user_agent = vec![0u8; 1024];
                let origin_len = in_state.fetch_string(&mut origin, 1024)?;
                let referer_len = in_state.fetch_string(&mut referer, 1024)?;
                let user_agent_len = in_state.fetch_string(&mut user_agent, 1024)?;
                origin.truncate(origin_len);
                referer.truncate(referer_len);
                user_agent.truncate(user_agent_len);
                parsed.http_origin = Some(origin);
                parsed.http_referer = Some(referer);
                parsed.http_user_agent = Some(user_agent);
            }
            other => {
                return Err(TlError::new(
                    TL_ERROR_HEADER,
                    format!("Unknown RPC_PROXY_REQ extra tag 0x{other:08x}"),
                ));
            }
        }
    }
    Ok(parsed)
}

pub fn parse_mtfront_function(tlio_in: &mut TlInState<'_>, actor_id: i64) -> Result<(), TlError> {
    if actor_id != 0 {
        return Err(TlError::new(
            TL_ERROR_WRONG_ACTOR_ID,
            "MTProxy only supports actor_id = 0",
        ));
    }
    let op = tlio_in.fetch_int()?;
    Err(TlError::new(
        TL_ERROR_UNKNOWN_FUNCTION_ID,
        format!("Unknown op {op:08x}"),
    ))
}

#[must_use]
pub fn parse_client_packet(data: &[u8]) -> RpcClientPacket<'_> {
    let total_len = i32::try_from(data.len()).unwrap_or(i32::MAX);
    let mut in_state = TlInState::new(data);
    let Ok(op) = in_state.fetch_int() else {
        return RpcClientPacket::Malformed { op: 0 };
    };

    match op {
        RPC_PONG => RpcClientPacket::Pong,
        RPC_PROXY_ANS => {
            if total_len < 16 {
                return RpcClientPacket::Malformed { op };
            }
            let Ok(flags) = in_state.fetch_int() else {
                return RpcClientPacket::Malformed { op };
            };
            let Ok(out_conn_id) = in_state.fetch_long() else {
                return RpcClientPacket::Malformed { op };
            };
            let payload_start = in_state.position();
            let payload = data.get(payload_start..).unwrap_or(&[]);
            RpcClientPacket::ProxyAns {
                flags,
                out_conn_id,
                payload,
            }
        }
        RPC_SIMPLE_ACK => {
            if total_len != 16 {
                return RpcClientPacket::Malformed { op };
            }
            let Ok(out_conn_id) = in_state.fetch_long() else {
                return RpcClientPacket::Malformed { op };
            };
            let Ok(confirm) = in_state.fetch_int() else {
                return RpcClientPacket::Malformed { op };
            };
            RpcClientPacket::SimpleAck {
                out_conn_id,
                confirm,
            }
        }
        RPC_CLOSE_EXT => {
            if total_len != 12 {
                return RpcClientPacket::Malformed { op };
            }
            let Ok(out_conn_id) = in_state.fetch_long() else {
                return RpcClientPacket::Malformed { op };
            };
            RpcClientPacket::CloseExt { out_conn_id }
        }
        _ => RpcClientPacket::Unknown { op },
    }
}

pub fn parse_forwarded_query_header(data: &[u8]) -> Result<i32, TlError> {
    let parsed = parse_query_header(data)?;
    Ok(parsed.header.op)
}

pub fn parse_forwarded_answer_header(data: &[u8]) -> Result<i32, TlError> {
    let parsed = parse_answer_header(data)?;
    Ok(parsed.header.op)
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::{
        build_rpc_proxy_req, inspect_mtproto_packet, inspect_mtproto_packet_header,
        mtproto_conn_tag, mtproto_ext_conn_hash, parse_client_packet,
        parse_forwarded_answer_header, parse_forwarded_query_header, parse_mtfront_function,
        parse_rpc_proxy_req, parse_rpc_proxy_req_extra, parse_text_ipv4, parse_text_ipv6,
        ExtConnLookupMode, ExtConnLookupOutcome, ExtConnectionTable, HttpQueryInfo,
        MtprotoPacketKind, ProxyReqBuildInput, RpcClientPacket, CODE_REQ_PQ, RPC_CLOSE_EXT,
        RPC_PONG, RPC_PROXY_ANS, RPC_SIMPLE_ACK, TL_HTTP_QUERY_INFO, TL_PROXY_TAG,
    };
    use crate::runtime::config::tl_parse::{TlInState, TlOutState, RPC_INVOKE_REQ, RPC_REQ_RESULT};

    #[test]
    fn mtproto_hash_and_conn_tag_match_c_logic() {
        let c_hash = |in_fd: i32, in_conn_id: i64, shift: i32| -> i32 {
            let in_fd_u = u64::from_ne_bytes(i64::from(in_fd).to_ne_bytes());
            let in_conn_id_u = u64::from_ne_bytes(in_conn_id.to_ne_bytes());
            let h = in_fd_u
                .wrapping_mul(11_400_714_819_323_198_485)
                .wrapping_add(in_conn_id_u.wrapping_mul(13_043_817_825_332_782_213));
            i32::try_from(h >> (64 - u32::try_from(shift).unwrap_or(0))).unwrap_or(-1)
        };

        assert_eq!(mtproto_conn_tag(0), 1);
        assert_eq!(mtproto_conn_tag(0x1234_5678), 0x0034_5679);
        assert_eq!(
            mtproto_conn_tag(i32::from_ne_bytes(0xffff_ffff_u32.to_ne_bytes())),
            0x0100_0000
        );

        assert_eq!(
            mtproto_ext_conn_hash(42, 0x1234_5678_9abc_def0_i64, 20),
            c_hash(42, 0x1234_5678_9abc_def0_i64, 20)
        );
        assert_eq!(mtproto_ext_conn_hash(-1, -17, 20), c_hash(-1, -17, 20));
        assert_eq!(mtproto_ext_conn_hash(1, 2, 0), -1);
    }

    #[test]
    fn ext_connection_table_handles_create_find_delete_modes() {
        let mut table = ExtConnectionTable::with_sizes(8, 3, 1).expect("table");

        let created = table
            .get_ext_connection_by_in_conn_id(10, 7, 0, ExtConnLookupMode::CreateIfMissing)
            .expect("create");
        let out_conn_id = match created {
            ExtConnLookupOutcome::Created(conn) => conn.out_conn_id,
            other => panic!("expected created, got {other:?}"),
        };
        assert_eq!(out_conn_id, 10);
        assert_eq!(table.ext_connections(), 1);
        assert_eq!(table.ext_connections_created(), 1);

        let found = table
            .get_ext_connection_by_in_conn_id(10, 7, 0, ExtConnLookupMode::Find)
            .expect("find");
        assert_eq!(
            found,
            ExtConnLookupOutcome::Found(
                table
                    .find_ext_connection_by_out_conn_id(out_conn_id)
                    .expect("out lookup")
            )
        );

        let dup = table
            .get_ext_connection_by_in_conn_id(10, 7, 0, ExtConnLookupMode::CreateIfMissing)
            .expect("create existing");
        assert_eq!(dup, ExtConnLookupOutcome::AlreadyExists);

        let deleted = table
            .get_ext_connection_by_in_conn_id(10, 7, 0, ExtConnLookupMode::Delete)
            .expect("delete");
        assert_eq!(deleted, ExtConnLookupOutcome::Deleted);
        assert_eq!(table.ext_connections(), 0);

        let recreated = table
            .get_ext_connection_by_in_conn_id(18, 8, 0, ExtConnLookupMode::CreateIfMissing)
            .expect("recreate");
        match recreated {
            ExtConnLookupOutcome::Created(conn) => assert_eq!(conn.out_conn_id, 18),
            other => panic!("expected created, got {other:?}"),
        }
    }

    #[test]
    fn ext_connection_table_lru_order_matches_insert_move_tail_behavior() {
        let mut table = ExtConnectionTable::with_sizes(16, 4, 7).expect("table");
        let a = table
            .get_ext_connection_by_in_conn_id(1, 1, 0, ExtConnLookupMode::CreateIfMissing)
            .expect("create a");
        let b = table
            .get_ext_connection_by_in_conn_id(2, 2, 0, ExtConnLookupMode::CreateIfMissing)
            .expect("create b");
        let (a_conn, b_conn) = match (a, b) {
            (ExtConnLookupOutcome::Created(a_conn), ExtConnLookupOutcome::Created(b_conn)) => {
                (a_conn, b_conn)
            }
            _ => panic!("create outcomes"),
        };

        assert!(table
            .lru_insert_by_in_fd_gen(a_conn.in_fd, a_conn.in_gen)
            .expect("lru a"));
        assert!(table
            .lru_insert_by_in_fd_gen(b_conn.in_fd, b_conn.in_gen)
            .expect("lru b"));
        assert_eq!(table.lru_pop_oldest().map(|c| c.in_fd), Some(1));

        assert!(table
            .lru_insert_by_in_fd_gen(a_conn.in_fd, a_conn.in_gen)
            .expect("lru a"));
        assert!(table
            .lru_insert_by_in_fd_gen(b_conn.in_fd, b_conn.in_gen)
            .expect("lru b"));
        assert!(table
            .lru_insert_by_in_fd_gen(a_conn.in_fd, a_conn.in_gen)
            .expect("move a tail"));
        assert_eq!(table.lru_pop_oldest().map(|c| c.in_fd), Some(2));
    }

    #[test]
    fn parse_ipv4_and_ipv6_match_expected_formats() {
        assert_eq!(parse_text_ipv4("127.0.0.1"), 0x7f00_0001);
        assert_eq!(parse_text_ipv4("256.0.0.1"), 0);
        assert_eq!(parse_text_ipv4("1.2.3"), 0);

        let mut ip = [0u8; 16];
        let consumed = parse_text_ipv6(&mut ip, "2001:db8::1");
        assert_eq!(consumed, 11);
        assert_eq!(
            ip,
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );

        let mut loopback = [0u8; 16];
        assert_eq!(parse_text_ipv6(&mut loopback, "::1"), 3);
        assert_eq!(loopback, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn mtproto_packet_inspection_matches_forward_checks() {
        let mut encrypted = [0u8; 28];
        encrypted[0..8].copy_from_slice(&0x1122_3344_5566_7788_i64.to_le_bytes());
        let parsed = inspect_mtproto_packet(&encrypted).expect("encrypted parse");
        assert_eq!(
            parsed,
            MtprotoPacketKind::Encrypted {
                auth_key_id: 0x1122_3344_5566_7788_i64
            }
        );

        let mut plain = [0u8; 40];
        plain[16..20].copy_from_slice(&20_i32.to_le_bytes());
        plain[20..24].copy_from_slice(&CODE_REQ_PQ.to_le_bytes());
        let parsed_plain = inspect_mtproto_packet(&plain).expect("plain parse");
        assert_eq!(
            parsed_plain,
            MtprotoPacketKind::UnencryptedDh {
                inner_len: 20,
                function: CODE_REQ_PQ
            }
        );

        let parsed_header_only =
            inspect_mtproto_packet_header(&plain[..28], 40).expect("header-only parse");
        assert_eq!(parsed_header_only, parsed_plain);

        plain[20..24].copy_from_slice(&0_i32.to_le_bytes());
        assert!(inspect_mtproto_packet(&plain).is_none());
    }

    #[test]
    fn proxy_request_build_and_parse_roundtrip_with_extra_tags() {
        let payload = [1u8, 2, 3, 4, 5, 6];
        let input = ProxyReqBuildInput {
            flags: 12,
            out_conn_id: 0x55,
            remote_ipv6: [0x11; 16],
            remote_port: 443,
            our_ipv6: [0x22; 16],
            our_port: 8443,
            proxy_tag: Some(&[0xaa; 16]),
            http_query_info: Some(HttpQueryInfo {
                origin: b"https://origin.example",
                referer: b"https://referer.example/path",
                user_agent: b"agent/1.0",
            }),
            payload: &payload,
        };

        let mut out = [0u8; 4096];
        let used = build_rpc_proxy_req(&mut out, &input).expect("build");
        let view = parse_rpc_proxy_req(&out[..used]).expect("parse");

        assert_eq!(view.flags, 12);
        assert_eq!(view.out_conn_id, 0x55);
        assert_eq!(view.remote_ipv6, [0x11; 16]);
        assert_eq!(view.our_ipv6, [0x22; 16]);
        assert_eq!(view.remote_port, 443);
        assert_eq!(view.our_port, 8443);
        assert_eq!(view.payload, payload);

        let extra = parse_rpc_proxy_req_extra(view.extra).expect("extra parse");
        assert_eq!(extra.proxy_tag.as_deref(), Some(&[0xaa; 16][..]));
        assert_eq!(
            extra.http_origin.as_deref(),
            Some(&b"https://origin.example"[..])
        );
        assert_eq!(
            extra.http_referer.as_deref(),
            Some(&b"https://referer.example/path"[..])
        );
        assert_eq!(extra.http_user_agent.as_deref(), Some(&b"agent/1.0"[..]));

        let mut extra_in = TlInState::new(view.extra);
        assert_eq!(extra_in.fetch_int().expect("tag"), TL_PROXY_TAG);
        let mut tag_buf = [0u8; 64];
        let tag_len = extra_in.fetch_string(&mut tag_buf, 64).expect("tag string");
        assert_eq!(&tag_buf[..tag_len], &[0xaa; 16]);
        assert_eq!(extra_in.fetch_int().expect("http tag"), TL_HTTP_QUERY_INFO);
    }

    #[test]
    fn client_packet_parser_matches_rpc_shapes() {
        let pong = RPC_PONG.to_le_bytes();
        assert_eq!(parse_client_packet(&pong), RpcClientPacket::Pong);

        let mut proxy_ans = Vec::new();
        proxy_ans.extend_from_slice(&RPC_PROXY_ANS.to_le_bytes());
        proxy_ans.extend_from_slice(&0x12_i32.to_le_bytes());
        proxy_ans.extend_from_slice(&0x1234_5678_9abc_def0_i64.to_le_bytes());
        proxy_ans.extend_from_slice(&[7u8, 8u8, 9u8]);
        assert_eq!(
            parse_client_packet(&proxy_ans),
            RpcClientPacket::ProxyAns {
                flags: 0x12,
                out_conn_id: 0x1234_5678_9abc_def0_i64,
                payload: &[7u8, 8u8, 9u8],
            }
        );

        let mut ack = Vec::new();
        ack.extend_from_slice(&RPC_SIMPLE_ACK.to_le_bytes());
        ack.extend_from_slice(&9_i64.to_le_bytes());
        ack.extend_from_slice(&7_i32.to_le_bytes());
        assert_eq!(
            parse_client_packet(&ack),
            RpcClientPacket::SimpleAck {
                out_conn_id: 9,
                confirm: 7,
            }
        );

        let mut close = Vec::new();
        close.extend_from_slice(&RPC_CLOSE_EXT.to_le_bytes());
        close.extend_from_slice(&123_i64.to_le_bytes());
        assert_eq!(
            parse_client_packet(&close),
            RpcClientPacket::CloseExt { out_conn_id: 123 }
        );
    }

    #[test]
    fn mtfront_parse_function_keeps_actor_and_unknown_op_errors() {
        let first = 0x1234_5678_i32.to_le_bytes();
        let mut input = TlInState::new(&first);
        let err = parse_mtfront_function(&mut input, 1).expect_err("actor error");
        assert_eq!(err.errnum, -2002);

        let second = 0x1234_5678_i32.to_le_bytes();
        let mut input = TlInState::new(&second);
        let err = parse_mtfront_function(&mut input, 0).expect_err("unknown op");
        assert_eq!(err.errnum, -2000);
        assert!(err.message.contains("Unknown op"));
    }

    #[test]
    fn forwarded_header_helpers_route_through_tl_parser_module() {
        let mut query = [0u8; 64];
        let mut out = TlOutState::new_str(&mut query, 0);
        out.store_int(RPC_INVOKE_REQ).expect("op");
        out.store_long(123).expect("qid");
        out.store_int(0x0102_0304).expect("body");
        let q_len = out.out_pos();
        assert_eq!(
            parse_forwarded_query_header(&query[..q_len]).expect("query parse"),
            RPC_INVOKE_REQ
        );

        let mut answer = [0u8; 64];
        let mut out = TlOutState::new_str(&mut answer, 0);
        out.store_int(RPC_REQ_RESULT).expect("op");
        out.store_long(123).expect("qid");
        out.store_int(0x0102_0304).expect("body");
        let a_len = out.out_pos();
        assert_eq!(
            parse_forwarded_answer_header(&answer[..a_len]).expect("answer parse"),
            RPC_REQ_RESULT
        );
    }
}
