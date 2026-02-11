//! Rust port of selected parsing helpers from `mtproto/mtproto-config.c`.

use core::convert::TryFrom;

/// Mirrors `MAX_CFG_TARGETS` from `mtproto/mtproto-config.h`.
pub const DEFAULT_MAX_CFG_TARGETS: usize = 4096;
/// Local in-memory slot count for Step 15 parser-model target metadata.
pub const DEFAULT_INLINE_TARGET_SLOTS: usize = 64;

/// Returned when tokenization cannot match a known lexeme.
pub const CFG_LEX_INVALID: i32 = -1;
/// Returned at end of input.
pub const CFG_LEX_EOF: i32 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CfgScanResult {
    advance: usize,
    ch: u8,
}

fn cfg_is_word_char(ch: u8) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, b'.' | b'-' | b'_')
}

fn cfg_skipspc_scan(input: &[u8]) -> CfgScanResult {
    let mut cursor = 0usize;
    loop {
        if cursor >= input.len() {
            return CfgScanResult {
                advance: cursor,
                ch: 0,
            };
        }
        match input[cursor] {
            b' ' | b'\t' | b'\r' | b'\n' => {
                cursor += 1;
            }
            b'#' => {
                cursor += 1;
                while cursor < input.len() && input[cursor] != b'\n' {
                    cursor += 1;
                }
            }
            ch => {
                return CfgScanResult {
                    advance: cursor,
                    ch,
                };
            }
        }
    }
}

fn cfg_skspc_scan(input: &[u8]) -> CfgScanResult {
    let mut cursor = 0usize;
    while cursor < input.len() && matches!(input[cursor], b' ' | b'\t') {
        cursor += 1;
    }
    let ch = input.get(cursor).copied().unwrap_or(0);
    CfgScanResult {
        advance: cursor,
        ch,
    }
}

fn cfg_skipspc_in_place(input: &[u8], cursor: &mut usize) {
    let scan = cfg_skipspc_scan(&input[*cursor..]);
    *cursor += scan.advance;
}

fn cfg_skspc_in_place(input: &[u8], cursor: &mut usize) {
    let scan = cfg_skspc_scan(&input[*cursor..]);
    *cursor += scan.advance;
}

fn cfg_getword_len(input: &[u8], cursor: usize) -> usize {
    let scan = cfg_skspc_scan(&input[cursor..]);
    let mut i = cursor + scan.advance;
    if i >= input.len() {
        return 0;
    }

    if input[i] != b'[' {
        let start = i;
        while i < input.len() && cfg_is_word_char(input[i]) {
            i += 1;
        }
        return i - start;
    }

    let start = i;
    i += 1;
    while i < input.len() && (cfg_is_word_char(input[i]) || input[i] == b':') {
        i += 1;
    }
    if i < input.len() && input[i] == b']' {
        i + 1 - start
    } else {
        i - start
    }
}

fn matches_prefix_at(input: &[u8], cursor: usize, prefix: &[u8]) -> bool {
    let end = cursor.saturating_add(prefix.len());
    end <= input.len() && input[cursor..end] == *prefix
}

/// Port of `cfg_getlex_ext()` keyword/punctuation matching logic.
///
/// This function mirrors the C matching order and prefix behavior:
/// it recognizes `min_connections`, `max_connections`, `proxy_for`, `proxy`,
/// `timeout`, and `default`, returning the same lexeme codes used by C.
pub fn cfg_getlex_ext(input: &[u8], cursor: &mut usize) -> i32 {
    cfg_skipspc_in_place(input, cursor);

    if *cursor >= input.len() {
        return CFG_LEX_EOF;
    }

    let current = input[*cursor];
    match current {
        b';' | b':' | b'{' | b'}' => {
            *cursor += 1;
            i32::from(current)
        }
        b'm' => {
            if matches_prefix_at(input, *cursor, b"min_connections") {
                *cursor += 15;
                i32::from(b'x')
            } else if matches_prefix_at(input, *cursor, b"max_connections") {
                *cursor += 15;
                i32::from(b'X')
            } else {
                CFG_LEX_INVALID
            }
        }
        b'p' => {
            if matches_prefix_at(input, *cursor, b"proxy_for") {
                *cursor += 9;
                i32::from(b'Y')
            } else if matches_prefix_at(input, *cursor, b"proxy") {
                *cursor += 5;
                i32::from(b'y')
            } else {
                CFG_LEX_INVALID
            }
        }
        b't' => {
            if matches_prefix_at(input, *cursor, b"timeout") {
                *cursor += 7;
                i32::from(b't')
            } else {
                CFG_LEX_INVALID
            }
        }
        b'd' => {
            if matches_prefix_at(input, *cursor, b"default") {
                *cursor += 7;
                i32::from(b'D')
            } else {
                CFG_LEX_INVALID
            }
        }
        0 => CFG_LEX_EOF,
        _ => CFG_LEX_INVALID,
    }
}

/// Mirrors fields touched by `init_old_mf_cluster()` / `extend_old_mf_cluster()`
/// in the directive parse path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtprotoClusterState {
    pub cluster_id: i32,
    pub targets_num: u32,
    pub write_targets_num: u32,
    pub flags: u32,
    pub first_target_index: Option<usize>,
}

impl MtprotoClusterState {
    const EMPTY: Self = Self {
        cluster_id: 0,
        targets_num: 0,
        write_targets_num: 0,
        flags: 0,
        first_target_index: None,
    };
}

/// Parsed target metadata produced by `cfg_parse_server_port`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtprotoParsedTarget {
    pub host_len: u8,
    pub port: u16,
    pub min_connections: i64,
    pub max_connections: i64,
}

/// Stateless parse preview for `cfg_parse_server_port`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtprotoCfgParseServerPortPreview {
    pub advance: usize,
    pub target_index: usize,
    pub target: MtprotoParsedTarget,
}

/// Mirrors mutable config fields touched by `preinit_config()` and directive
/// parsing blocks in `parse_config()`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MtprotoConfigState<
    const MAX_CLUSTERS: usize,
    const MAX_TARGETS: usize = DEFAULT_INLINE_TARGET_SLOTS,
> {
    pub tot_targets: usize,
    pub auth_clusters: usize,
    pub min_connections: i64,
    pub max_connections: i64,
    pub timeout_seconds: f64,
    pub default_cluster_id: i32,
    pub have_proxy: bool,
    pub default_cluster_index: Option<usize>,
    pub auth_cluster: [MtprotoClusterState; MAX_CLUSTERS],
    pub parsed_targets: [Option<MtprotoParsedTarget>; MAX_TARGETS],
}

impl<const MAX_CLUSTERS: usize, const MAX_TARGETS: usize>
    MtprotoConfigState<MAX_CLUSTERS, MAX_TARGETS>
{
    /// Empty config state before `preinit_config`.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            tot_targets: 0,
            auth_clusters: 0,
            min_connections: 0,
            max_connections: 0,
            timeout_seconds: 0.0,
            default_cluster_id: 0,
            have_proxy: false,
            default_cluster_index: None,
            auth_cluster: [MtprotoClusterState::EMPTY; MAX_CLUSTERS],
            parsed_targets: [None; MAX_TARGETS],
        }
    }
}

impl<const MAX_CLUSTERS: usize, const MAX_TARGETS: usize> Default
    for MtprotoConfigState<MAX_CLUSTERS, MAX_TARGETS>
{
    fn default() -> Self {
        Self::new()
    }
}

/// Defaults consumed by `preinit_config()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtprotoConfigDefaults {
    pub min_connections: i64,
    pub max_connections: i64,
}

/// Scalar state written by `preinit_config()` in C runtime paths.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MtprotoPreinitState {
    pub tot_targets: usize,
    pub auth_clusters: usize,
    pub min_connections: i64,
    pub max_connections: i64,
    pub timeout_seconds: f64,
    pub default_cluster_id: i32,
    pub have_proxy: bool,
    pub default_cluster_index: Option<usize>,
}

/// Parse options for directive-block processing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtprotoDirectiveParseOptions {
    /// Mirrors `flags & 1` from C parse path.
    pub create_targets: bool,
    /// Upper bound used for `too many targets` validation.
    pub max_targets: usize,
}

impl Default for MtprotoDirectiveParseOptions {
    fn default() -> Self {
        Self {
            create_targets: false,
            max_targets: DEFAULT_MAX_CFG_TARGETS,
        }
    }
}

/// Directive-parse errors corresponding to C `Syntax(...)` failures.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MtprotoDirectiveParseError {
    InvalidTimeout(i64),
    InvalidMaxConnections(i64),
    InvalidMinConnections(i64),
    InvalidTargetId(i64),
    SpaceExpectedAfterTargetId,
    TooManyAuthClusters(usize),
    TooManyTargets(usize),
    HostnameExpected,
    PortNumberExpected,
    PortOutOfRange(i64),
    ProxiesIntermixed(i32),
    ProxyDirectiveExpected,
    ExpectedSemicolon(i32),
    MissingProxyDirectives,
    NoProxyServersDefined,
    InternalClusterExtendInvariant,
}

/// Parsed directive token classification for incremental C-loop migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MtprotoDirectiveTokenKind {
    Eof = 0,
    Timeout = 1,
    DefaultCluster = 2,
    ProxyFor = 3,
    Proxy = 4,
    MaxConnections = 5,
    MinConnections = 6,
}

/// One-token parse result for C directive-loop handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtprotoDirectiveTokenPreview {
    pub kind: MtprotoDirectiveTokenKind,
    pub advance: usize,
    pub value: i64,
}

/// One-step parse result for C directive-loop control flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtprotoDirectiveStepPreview {
    pub kind: MtprotoDirectiveTokenKind,
    pub advance: usize,
    pub value: i64,
    pub cluster_apply_decision: Option<MtprotoClusterApplyDecision>,
}

/// Cluster-target pointer action needed when applying a proxy step in C runtime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MtprotoClusterTargetsAction {
    KeepExisting = 0,
    Clear = 1,
    SetToTargetIndex = 2,
}

/// Combined proxy target parse/apply preview for `parse_config()` C runtime path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtprotoProxyTargetStepPreview {
    pub advance: usize,
    pub target_index: usize,
    pub target: MtprotoParsedTarget,
    pub tot_targets_after: usize,
    pub cluster_apply_decision: MtprotoClusterApplyDecision,
    pub cluster_state_after: MtprotoClusterState,
    pub cluster_targets_action: MtprotoClusterTargetsAction,
    pub auth_clusters_after: usize,
    pub auth_tot_clusters_after: usize,
}

/// One proxy side-effect action produced by full config-pass planning.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtprotoProxyTargetPassAction {
    /// Offset (from parser input start) at which `host:port` payload begins.
    pub host_offset: usize,
    /// Parsed/apply metadata for this proxy directive.
    pub step: MtprotoProxyTargetStepPreview,
}

impl MtprotoProxyTargetPassAction {
    const EMPTY: Self = Self {
        host_offset: 0,
        step: MtprotoProxyTargetStepPreview {
            advance: 0,
            target_index: 0,
            target: MtprotoParsedTarget {
                host_len: 0,
                port: 0,
                min_connections: 0,
                max_connections: 0,
            },
            tot_targets_after: 0,
            cluster_apply_decision: MtprotoClusterApplyDecision {
                kind: MtprotoClusterApplyDecisionKind::CreateNew,
                cluster_index: 0,
            },
            cluster_state_after: MtprotoClusterState::EMPTY,
            cluster_targets_action: MtprotoClusterTargetsAction::KeepExisting,
            auth_clusters_after: 0,
            auth_tot_clusters_after: 0,
        },
    };
}

impl Default for MtprotoProxyTargetPassAction {
    fn default() -> Self {
        Self::EMPTY
    }
}

/// Terminal parser snapshot for one full `parse_config()` pass.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MtprotoParseConfigPassResult {
    pub tot_targets: usize,
    pub auth_clusters: usize,
    pub auth_tot_clusters: usize,
    pub min_connections: i64,
    pub max_connections: i64,
    pub timeout_seconds: f64,
    pub default_cluster_id: i32,
    pub have_proxy: bool,
    pub default_cluster_index: Option<usize>,
    pub actions_len: usize,
}

fn parse_unsigned_from(input: &[u8], cursor: &mut usize) -> i64 {
    cfg_skspc_in_place(input, cursor);
    let mut value = 0i64;
    let mut consumed = 0usize;
    while *cursor < input.len() && input[*cursor].is_ascii_digit() {
        value = value
            .saturating_mul(10)
            .saturating_add(i64::from(input[*cursor] - b'0'));
        *cursor += 1;
        consumed += 1;
    }
    if consumed == 0 {
        0
    } else {
        value
    }
}

fn parse_signed_zero_from(input: &[u8], cursor: &mut usize) -> Option<i64> {
    cfg_skspc_in_place(input, cursor);
    let mut sign = 1i64;
    if *cursor < input.len() && input[*cursor] == b'-' {
        sign = -1;
        *cursor += 1;
    }
    let start_digits = *cursor;
    let mut value = 0i64;
    while *cursor < input.len() && input[*cursor].is_ascii_digit() {
        value = value
            .saturating_mul(10)
            .saturating_add(sign.saturating_mul(i64::from(input[*cursor] - b'0')));
        *cursor += 1;
    }
    if *cursor == start_digits {
        None
    } else {
        Some(value)
    }
}

/// Parses one `mtproto-config` directive token and associated scalar argument.
///
/// This mirrors the directive switch handling from `parse_config()` for
/// `t`/`D`/`Y`/`y`/`X`/`x`, but does not parse proxy `host:port` payload or
/// trailing semicolon.
pub fn cfg_scan_directive_token(
    input: &[u8],
    min_connections: i64,
    max_connections: i64,
) -> Result<MtprotoDirectiveTokenPreview, MtprotoDirectiveParseError> {
    let mut cursor = 0usize;
    let token = cfg_getlex_ext(input, &mut cursor);
    if token == CFG_LEX_EOF {
        return Ok(MtprotoDirectiveTokenPreview {
            kind: MtprotoDirectiveTokenKind::Eof,
            advance: cursor,
            value: 0,
        });
    }

    match token {
        t if t == i32::from(b't') => {
            let timeout_ms = parse_unsigned_from(input, &mut cursor);
            if !(10..=30000).contains(&timeout_ms) {
                return Err(MtprotoDirectiveParseError::InvalidTimeout(timeout_ms));
            }
            Ok(MtprotoDirectiveTokenPreview {
                kind: MtprotoDirectiveTokenKind::Timeout,
                advance: cursor,
                value: timeout_ms,
            })
        }
        t if t == i32::from(b'D') => {
            let target_dc = parse_signed_zero_from(input, &mut cursor)
                .ok_or(MtprotoDirectiveParseError::InvalidTargetId(i64::MIN))?;
            if !(-0x8000..0x8000).contains(&target_dc) {
                return Err(MtprotoDirectiveParseError::InvalidTargetId(target_dc));
            }
            Ok(MtprotoDirectiveTokenPreview {
                kind: MtprotoDirectiveTokenKind::DefaultCluster,
                advance: cursor,
                value: target_dc,
            })
        }
        t if t == i32::from(b'Y') => {
            let target_dc = parse_signed_zero_from(input, &mut cursor)
                .ok_or(MtprotoDirectiveParseError::InvalidTargetId(i64::MIN))?;
            if !(-0x8000..0x8000).contains(&target_dc) {
                return Err(MtprotoDirectiveParseError::InvalidTargetId(target_dc));
            }
            if cursor >= input.len() || !matches!(input[cursor], b' ' | b'\t') {
                return Err(MtprotoDirectiveParseError::SpaceExpectedAfterTargetId);
            }
            cfg_skspc_in_place(input, &mut cursor);
            Ok(MtprotoDirectiveTokenPreview {
                kind: MtprotoDirectiveTokenKind::ProxyFor,
                advance: cursor,
                value: target_dc,
            })
        }
        t if t == i32::from(b'y') => Ok(MtprotoDirectiveTokenPreview {
            kind: MtprotoDirectiveTokenKind::Proxy,
            advance: cursor,
            value: 0,
        }),
        t if t == i32::from(b'X') => {
            let new_max_connections = parse_unsigned_from(input, &mut cursor);
            if new_max_connections < min_connections || new_max_connections > 1000 {
                return Err(MtprotoDirectiveParseError::InvalidMaxConnections(
                    new_max_connections,
                ));
            }
            Ok(MtprotoDirectiveTokenPreview {
                kind: MtprotoDirectiveTokenKind::MaxConnections,
                advance: cursor,
                value: new_max_connections,
            })
        }
        t if t == i32::from(b'x') => {
            let new_min_connections = parse_unsigned_from(input, &mut cursor);
            if !(1..=max_connections).contains(&new_min_connections) {
                return Err(MtprotoDirectiveParseError::InvalidMinConnections(
                    new_min_connections,
                ));
            }
            Ok(MtprotoDirectiveTokenPreview {
                kind: MtprotoDirectiveTokenKind::MinConnections,
                advance: cursor,
                value: new_min_connections,
            })
        }
        _ => Err(MtprotoDirectiveParseError::ProxyDirectiveExpected),
    }
}

/// Parses and validates a trailing semicolon for the current directive.
pub fn cfg_expect_semicolon(
    input: &[u8],
    cursor: &mut usize,
) -> Result<(), MtprotoDirectiveParseError> {
    let sep = cfg_getlex_ext(input, cursor);
    if sep != i32::from(b';') {
        return Err(MtprotoDirectiveParseError::ExpectedSemicolon(sep));
    }
    Ok(())
}

/// Parses one directive step from `parse_config()` C control flow.
///
/// For scalar directives (`timeout`, `default`, `min_connections`,
/// `max_connections`) this includes semicolon validation and returned
/// `advance` consumes the whole directive statement.
///
/// For proxy directives (`proxy`, `proxy_for`) this returns cluster-apply
/// decision metadata and leaves `advance` at the start of `host:port` payload.
pub fn cfg_parse_directive_step(
    input: &[u8],
    min_connections: i64,
    max_connections: i64,
    cluster_ids: &[i32],
    max_clusters: usize,
) -> Result<MtprotoDirectiveStepPreview, MtprotoDirectiveParseError> {
    let token = cfg_scan_directive_token(input, min_connections, max_connections)?;
    match token.kind {
        MtprotoDirectiveTokenKind::Eof => Ok(MtprotoDirectiveStepPreview {
            kind: token.kind,
            advance: token.advance,
            value: token.value,
            cluster_apply_decision: None,
        }),
        MtprotoDirectiveTokenKind::Proxy | MtprotoDirectiveTokenKind::ProxyFor => {
            let cluster_id = if token.kind == MtprotoDirectiveTokenKind::ProxyFor {
                i32::try_from(token.value)
                    .map_err(|_| MtprotoDirectiveParseError::InvalidTargetId(token.value))?
            } else {
                0
            };
            let decision = decide_proxy_cluster_apply(cluster_ids, cluster_id, max_clusters)?;
            Ok(MtprotoDirectiveStepPreview {
                kind: token.kind,
                advance: token.advance,
                value: token.value,
                cluster_apply_decision: Some(decision),
            })
        }
        MtprotoDirectiveTokenKind::Timeout
        | MtprotoDirectiveTokenKind::DefaultCluster
        | MtprotoDirectiveTokenKind::MaxConnections
        | MtprotoDirectiveTokenKind::MinConnections => {
            let mut cursor = token.advance;
            cfg_expect_semicolon(input, &mut cursor)?;
            Ok(MtprotoDirectiveStepPreview {
                kind: token.kind,
                advance: cursor,
                value: token.value,
                cluster_apply_decision: None,
            })
        }
    }
}

/// Parses proxy target payload (`host:port;`) and computes apply-state mutation.
///
/// `input` must point to the beginning of proxy target payload (right after
/// `proxy` / `proxy_for <dc>` token parse).
pub fn cfg_parse_proxy_target_step(
    input: &[u8],
    current_targets: usize,
    max_targets: usize,
    min_connections: i64,
    max_connections: i64,
    cluster_ids: &[i32],
    target_dc: i32,
    max_clusters: usize,
    create_targets: bool,
    current_auth_tot_clusters: usize,
    last_cluster_state: Option<MtprotoClusterState>,
) -> Result<MtprotoProxyTargetStepPreview, MtprotoDirectiveParseError> {
    let cluster_apply_decision = decide_proxy_cluster_apply(cluster_ids, target_dc, max_clusters)?;

    let mut cursor = 0usize;
    let preview = cfg_parse_server_port_preview(
        input,
        &mut cursor,
        current_targets,
        max_targets,
        min_connections,
        max_connections,
    )?;
    cfg_expect_semicolon(input, &mut cursor)?;
    let (cluster_state_after, cluster_targets_action, auth_clusters_after, auth_tot_clusters_after) =
        match cluster_apply_decision.kind {
            MtprotoClusterApplyDecisionKind::CreateNew => {
                let mut state = MtprotoClusterState::EMPTY;
                if create_targets {
                    init_old_mf_cluster(&mut state, preview.target_index, 1, target_dc);
                    (
                        state,
                        MtprotoClusterTargetsAction::SetToTargetIndex,
                        cluster_ids.len().saturating_add(1),
                        current_auth_tot_clusters.saturating_add(1),
                    )
                } else {
                    state.cluster_id = target_dc;
                    (
                        state,
                        MtprotoClusterTargetsAction::Clear,
                        cluster_ids.len().saturating_add(1),
                        current_auth_tot_clusters,
                    )
                }
            }
            MtprotoClusterApplyDecisionKind::AppendLast => {
                let mut state = last_cluster_state
                    .ok_or(MtprotoDirectiveParseError::InternalClusterExtendInvariant)?;
                if create_targets
                    && !extend_old_mf_cluster(&mut state, preview.target_index, target_dc)
                {
                    return Err(MtprotoDirectiveParseError::InternalClusterExtendInvariant);
                }
                (
                    state,
                    MtprotoClusterTargetsAction::KeepExisting,
                    cluster_ids.len(),
                    current_auth_tot_clusters,
                )
            }
        };

    Ok(MtprotoProxyTargetStepPreview {
        advance: cursor,
        target_index: preview.target_index,
        target: preview.target,
        tot_targets_after: preview.target_index.saturating_add(1),
        cluster_apply_decision,
        cluster_state_after,
        cluster_targets_action,
        auth_clusters_after,
        auth_tot_clusters_after,
    })
}

/// Full parse pass for `mtproto-config` directive flow with side-effect planning.
///
/// This owns directive iteration, scalar state updates, cluster/apply decisions,
/// and finalization/default-cluster resolution. Proxy host resolution and target
/// creation side effects are left to the caller via returned `actions`.
pub fn cfg_parse_config_full_pass<const MAX_CLUSTERS: usize>(
    input: &[u8],
    defaults: MtprotoConfigDefaults,
    create_targets: bool,
    max_clusters: usize,
    max_targets: usize,
    actions: &mut [MtprotoProxyTargetPassAction],
) -> Result<MtprotoParseConfigPassResult, MtprotoDirectiveParseError> {
    if max_clusters == 0 || max_clusters > MAX_CLUSTERS {
        return Err(MtprotoDirectiveParseError::TooManyAuthClusters(0));
    }

    let preinit = preinit_config_snapshot(defaults);
    let mut min_connections = preinit.min_connections;
    let mut max_connections_state = preinit.max_connections;
    let mut timeout_seconds = preinit.timeout_seconds;
    let mut default_cluster_id = preinit.default_cluster_id;

    let mut tot_targets = preinit.tot_targets;
    let mut auth_clusters = preinit.auth_clusters;
    let mut auth_tot_clusters = 0usize;
    let mut have_proxy = false;
    let mut actions_len = 0usize;

    let mut cluster_ids = [0i32; MAX_CLUSTERS];
    let mut cluster_states = [MtprotoClusterState::EMPTY; MAX_CLUSTERS];
    let mut cursor = 0usize;

    loop {
        let step = cfg_parse_directive_step(
            &input[cursor..],
            min_connections,
            max_connections_state,
            &cluster_ids[..auth_clusters],
            max_clusters,
        )?;
        cursor = cursor.saturating_add(step.advance);

        match step.kind {
            MtprotoDirectiveTokenKind::Eof => break,
            MtprotoDirectiveTokenKind::Timeout => {
                let timeout_ms_i32 = i32::try_from(step.value)
                    .map_err(|_| MtprotoDirectiveParseError::InvalidTimeout(step.value))?;
                timeout_seconds = f64::from(timeout_ms_i32) / 1000.0;
            }
            MtprotoDirectiveTokenKind::DefaultCluster => {
                default_cluster_id = i32::try_from(step.value)
                    .map_err(|_| MtprotoDirectiveParseError::InvalidTargetId(step.value))?;
            }
            MtprotoDirectiveTokenKind::MaxConnections => {
                max_connections_state = step.value;
            }
            MtprotoDirectiveTokenKind::MinConnections => {
                min_connections = step.value;
            }
            MtprotoDirectiveTokenKind::Proxy | MtprotoDirectiveTokenKind::ProxyFor => {
                if actions_len >= actions.len() {
                    return Err(MtprotoDirectiveParseError::TooManyTargets(actions_len));
                }
                have_proxy = true;
                let target_dc = if step.kind == MtprotoDirectiveTokenKind::ProxyFor {
                    i32::try_from(step.value)
                        .map_err(|_| MtprotoDirectiveParseError::InvalidTargetId(step.value))?
                } else {
                    0
                };
                let last_cluster_state = if auth_clusters > 0 {
                    Some(cluster_states[auth_clusters - 1])
                } else {
                    None
                };
                let proxy_step = cfg_parse_proxy_target_step(
                    &input[cursor..],
                    tot_targets,
                    max_targets,
                    min_connections,
                    max_connections_state,
                    &cluster_ids[..auth_clusters],
                    target_dc,
                    max_clusters,
                    create_targets,
                    auth_tot_clusters,
                    last_cluster_state,
                )?;
                actions[actions_len] = MtprotoProxyTargetPassAction {
                    host_offset: cursor,
                    step: proxy_step,
                };
                actions_len = actions_len.saturating_add(1);
                cursor = cursor.saturating_add(proxy_step.advance);

                tot_targets = proxy_step.tot_targets_after;
                auth_clusters = proxy_step.auth_clusters_after;
                auth_tot_clusters = proxy_step.auth_tot_clusters_after;
                if proxy_step.cluster_apply_decision.cluster_index >= MAX_CLUSTERS {
                    return Err(MtprotoDirectiveParseError::InternalClusterExtendInvariant);
                }
                cluster_ids[proxy_step.cluster_apply_decision.cluster_index] =
                    proxy_step.cluster_state_after.cluster_id;
                cluster_states[proxy_step.cluster_apply_decision.cluster_index] =
                    proxy_step.cluster_state_after;
            }
        }
    }

    let default_cluster_index = finalize_parse_config_state(
        have_proxy,
        &cluster_ids[..auth_clusters],
        default_cluster_id,
    )?;
    Ok(MtprotoParseConfigPassResult {
        tot_targets,
        auth_clusters,
        auth_tot_clusters,
        min_connections,
        max_connections: max_connections_state,
        timeout_seconds,
        default_cluster_id,
        have_proxy,
        default_cluster_index,
        actions_len,
    })
}

/// Port of `mf_cluster_lookup()` index selection semantics.
#[must_use]
pub fn mf_cluster_lookup_index(
    cluster_ids: &[i32],
    cluster_id: i32,
    force_default_cluster_index: Option<usize>,
) -> Option<usize> {
    if let Some(idx) = cluster_ids.iter().position(|id| *id == cluster_id) {
        return Some(idx);
    }
    force_default_cluster_index
}

/// Cluster-apply action selected for `proxy`/`proxy_for` directive handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MtprotoClusterApplyDecisionKind {
    CreateNew = 1,
    AppendLast = 2,
}

/// Decision result for cluster selection in `parse_config()` apply flow.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MtprotoClusterApplyDecision {
    pub kind: MtprotoClusterApplyDecisionKind,
    pub cluster_index: usize,
}

/// Decides how a proxy target should be applied to clusters.
///
/// This mirrors the C flow currently used in `parse_config()`:
/// - too-many-clusters guard runs before lookup logic
/// - missing cluster means create-new at `auth_clusters`
/// - existing cluster is valid only when it is the last cluster
pub fn decide_proxy_cluster_apply(
    cluster_ids: &[i32],
    cluster_id: i32,
    max_clusters: usize,
) -> Result<MtprotoClusterApplyDecision, MtprotoDirectiveParseError> {
    if cluster_ids.len() >= max_clusters {
        return Err(MtprotoDirectiveParseError::TooManyAuthClusters(
            cluster_ids.len(),
        ));
    }

    match mf_cluster_lookup_index(cluster_ids, cluster_id, None) {
        None => Ok(MtprotoClusterApplyDecision {
            kind: MtprotoClusterApplyDecisionKind::CreateNew,
            cluster_index: cluster_ids.len(),
        }),
        Some(idx) => {
            if idx + 1 != cluster_ids.len() {
                return Err(MtprotoDirectiveParseError::ProxiesIntermixed(cluster_id));
            }
            Ok(MtprotoClusterApplyDecision {
                kind: MtprotoClusterApplyDecisionKind::AppendLast,
                cluster_index: idx,
            })
        }
    }
}

fn lookup_cluster_index<const MAX_CLUSTERS: usize, const MAX_TARGETS: usize>(
    cfg: &MtprotoConfigState<MAX_CLUSTERS, MAX_TARGETS>,
    cluster_id: i32,
) -> Option<usize> {
    let cluster_ids = cfg.auth_cluster[..cfg.auth_clusters]
        .iter()
        .map(|cluster| cluster.cluster_id);
    let mut ids_buf = [0i32; MAX_CLUSTERS];
    for (idx, id) in cluster_ids.enumerate() {
        ids_buf[idx] = id;
    }
    mf_cluster_lookup_index(&ids_buf[..cfg.auth_clusters], cluster_id, None)
}

/// Finalizes parse-loop terminal checks and default-cluster lookup.
pub fn finalize_parse_config_state(
    have_proxy: bool,
    cluster_ids: &[i32],
    default_cluster_id: i32,
) -> Result<Option<usize>, MtprotoDirectiveParseError> {
    if !have_proxy {
        return Err(MtprotoDirectiveParseError::MissingProxyDirectives);
    }
    if cluster_ids.is_empty() {
        return Err(MtprotoDirectiveParseError::NoProxyServersDefined);
    }
    Ok(mf_cluster_lookup_index(
        cluster_ids,
        default_cluster_id,
        None,
    ))
}

/// Stateless parser preview for `cfg_parse_server_port()` syntax and range checks.
pub fn cfg_parse_server_port_preview(
    input: &[u8],
    cursor: &mut usize,
    current_targets: usize,
    max_targets: usize,
    min_connections: i64,
    max_connections: i64,
) -> Result<MtprotoCfgParseServerPortPreview, MtprotoDirectiveParseError> {
    if current_targets >= max_targets {
        return Err(MtprotoDirectiveParseError::TooManyTargets(current_targets));
    }

    let begin = *cursor;
    cfg_skspc_in_place(input, cursor);
    let host_len = cfg_getword_len(input, *cursor);
    if host_len == 0 || host_len > 63 {
        return Err(MtprotoDirectiveParseError::HostnameExpected);
    }
    *cursor += host_len;

    let lex = cfg_getlex_ext(input, cursor);
    if lex != i32::from(b':') {
        return Err(MtprotoDirectiveParseError::PortNumberExpected);
    }

    let port = parse_unsigned_from(input, cursor);
    if port == 0 {
        return Err(MtprotoDirectiveParseError::PortNumberExpected);
    }
    if !(1..=65535).contains(&port) {
        return Err(MtprotoDirectiveParseError::PortOutOfRange(port));
    }

    let host_len_u8 =
        u8::try_from(host_len).map_err(|_| MtprotoDirectiveParseError::HostnameExpected)?;
    let port_u16 =
        u16::try_from(port).map_err(|_| MtprotoDirectiveParseError::PortOutOfRange(port))?;

    Ok(MtprotoCfgParseServerPortPreview {
        advance: *cursor - begin,
        target_index: current_targets,
        target: MtprotoParsedTarget {
            host_len: host_len_u8,
            port: port_u16,
            min_connections,
            max_connections,
        },
    })
}

/// Port of `cfg_parse_server_port()` syntax and range checks.
pub fn cfg_parse_server_port<const MAX_CLUSTERS: usize, const MAX_TARGETS: usize>(
    input: &[u8],
    cursor: &mut usize,
    cfg: &mut MtprotoConfigState<MAX_CLUSTERS, MAX_TARGETS>,
    max_targets: usize,
) -> Result<usize, MtprotoDirectiveParseError> {
    if cfg.tot_targets >= cfg.parsed_targets.len() {
        return Err(MtprotoDirectiveParseError::TooManyTargets(cfg.tot_targets));
    }

    let preview = cfg_parse_server_port_preview(
        input,
        cursor,
        cfg.tot_targets,
        max_targets,
        cfg.min_connections,
        cfg.max_connections,
    )?;
    let target_idx = preview.target_index;
    cfg.parsed_targets[target_idx] = Some(preview.target);
    cfg.tot_targets = target_idx.saturating_add(1);

    Ok(target_idx)
}

/// Port of `init_old_mf_cluster()`.
pub fn init_old_mf_cluster(
    cluster: &mut MtprotoClusterState,
    first_target_index: usize,
    flags: u32,
    cluster_id: i32,
) {
    cluster.flags = flags;
    cluster.targets_num = 1;
    cluster.write_targets_num = 1;
    cluster.first_target_index = Some(first_target_index);
    cluster.cluster_id = cluster_id;
}

/// Port of `extend_old_mf_cluster()` index/cluster-id invariants.
#[must_use]
pub fn extend_old_mf_cluster(
    cluster: &mut MtprotoClusterState,
    target_index: usize,
    cluster_id: i32,
) -> bool {
    if cluster.cluster_id != cluster_id {
        return false;
    }

    let Some(first) = cluster.first_target_index else {
        return false;
    };
    let expected = first + usize::try_from(cluster.targets_num).unwrap_or(usize::MAX);
    if expected != target_index {
        return false;
    }

    cluster.targets_num = cluster.targets_num.saturating_add(1);
    cluster.write_targets_num = cluster.targets_num;
    true
}

/// Port of `preinit_config()`.
pub fn preinit_config<const MAX_CLUSTERS: usize, const MAX_TARGETS: usize>(
    cfg: &mut MtprotoConfigState<MAX_CLUSTERS, MAX_TARGETS>,
    defaults: MtprotoConfigDefaults,
) {
    cfg.tot_targets = 0;
    cfg.auth_clusters = 0;
    cfg.min_connections = defaults.min_connections;
    cfg.max_connections = defaults.max_connections;
    cfg.timeout_seconds = 0.3;
    cfg.default_cluster_id = 0;
    cfg.default_cluster_index = None;
    cfg.have_proxy = false;
    for target in &mut cfg.parsed_targets {
        *target = None;
    }
}

/// Returns the scalar state produced by `preinit_config()`.
#[must_use]
pub fn preinit_config_snapshot(defaults: MtprotoConfigDefaults) -> MtprotoPreinitState {
    let mut cfg = MtprotoConfigState::<1, 1>::new();
    preinit_config(&mut cfg, defaults);
    MtprotoPreinitState {
        tot_targets: cfg.tot_targets,
        auth_clusters: cfg.auth_clusters,
        min_connections: cfg.min_connections,
        max_connections: cfg.max_connections,
        timeout_seconds: cfg.timeout_seconds,
        default_cluster_id: cfg.default_cluster_id,
        have_proxy: cfg.have_proxy,
        default_cluster_index: cfg.default_cluster_index,
    }
}

fn parse_proxy_directive<const MAX_CLUSTERS: usize, const MAX_TARGETS: usize>(
    input: &[u8],
    cursor: &mut usize,
    cfg: &mut MtprotoConfigState<MAX_CLUSTERS, MAX_TARGETS>,
    options: MtprotoDirectiveParseOptions,
    target_dc: i32,
) -> Result<(), MtprotoDirectiveParseError> {
    if cfg.auth_clusters >= MAX_CLUSTERS {
        return Err(MtprotoDirectiveParseError::TooManyAuthClusters(
            cfg.auth_clusters,
        ));
    }

    let target_idx = cfg_parse_server_port(input, cursor, cfg, options.max_targets)?;
    cfg.have_proxy = true;

    match lookup_cluster_index(cfg, target_dc) {
        None => {
            let idx = cfg.auth_clusters;
            cfg.auth_cluster[idx].cluster_id = target_dc;
            if options.create_targets {
                init_old_mf_cluster(&mut cfg.auth_cluster[idx], target_idx, 1, target_dc);
            } else {
                cfg.auth_cluster[idx].flags = 0;
                cfg.auth_cluster[idx].targets_num = 0;
                cfg.auth_cluster[idx].write_targets_num = 0;
                cfg.auth_cluster[idx].first_target_index = None;
            }
            cfg.auth_clusters += 1;
        }
        Some(idx) => {
            if idx + 1 != cfg.auth_clusters {
                return Err(MtprotoDirectiveParseError::ProxiesIntermixed(target_dc));
            }
            if options.create_targets
                && !extend_old_mf_cluster(&mut cfg.auth_cluster[idx], target_idx, target_dc)
            {
                return Err(MtprotoDirectiveParseError::InternalClusterExtendInvariant);
            }
        }
    }
    Ok(())
}

/// Port of `parse_config()` directive loop (`t`, `D`, `Y`, `y`, `X`, `x`)
/// including terminal consistency checks.
pub fn parse_config_directive_blocks<const MAX_CLUSTERS: usize, const MAX_TARGETS: usize>(
    input: &[u8],
    cfg: &mut MtprotoConfigState<MAX_CLUSTERS, MAX_TARGETS>,
    defaults: MtprotoConfigDefaults,
    options: MtprotoDirectiveParseOptions,
) -> Result<(), MtprotoDirectiveParseError> {
    preinit_config(cfg, defaults);

    let mut cursor = 0usize;
    loop {
        let token = cfg_getlex_ext(input, &mut cursor);
        if token == CFG_LEX_EOF {
            break;
        }

        match token {
            t if t == i32::from(b't') => {
                let timeout_ms = parse_unsigned_from(input, &mut cursor);
                if !(10..=30000).contains(&timeout_ms) {
                    return Err(MtprotoDirectiveParseError::InvalidTimeout(timeout_ms));
                }
                let timeout_ms_i32 = i32::try_from(timeout_ms)
                    .map_err(|_| MtprotoDirectiveParseError::InvalidTimeout(timeout_ms))?;
                cfg.timeout_seconds = f64::from(timeout_ms_i32) / 1000.0;
            }
            t if t == i32::from(b'D') => {
                let target_dc = parse_signed_zero_from(input, &mut cursor)
                    .ok_or(MtprotoDirectiveParseError::InvalidTargetId(i64::MIN))?;
                if !(-0x8000..0x8000).contains(&target_dc) {
                    return Err(MtprotoDirectiveParseError::InvalidTargetId(target_dc));
                }
                cfg.default_cluster_id = i32::try_from(target_dc)
                    .map_err(|_| MtprotoDirectiveParseError::InvalidTargetId(target_dc))?;
            }
            t if t == i32::from(b'Y') => {
                let target_dc = parse_signed_zero_from(input, &mut cursor)
                    .ok_or(MtprotoDirectiveParseError::InvalidTargetId(i64::MIN))?;
                if !(-0x8000..0x8000).contains(&target_dc) {
                    return Err(MtprotoDirectiveParseError::InvalidTargetId(target_dc));
                }
                if cursor >= input.len() || !matches!(input[cursor], b' ' | b'\t') {
                    return Err(MtprotoDirectiveParseError::SpaceExpectedAfterTargetId);
                }
                cfg_skspc_in_place(input, &mut cursor);
                let cluster_id = i32::try_from(target_dc)
                    .map_err(|_| MtprotoDirectiveParseError::InvalidTargetId(target_dc))?;
                parse_proxy_directive(input, &mut cursor, cfg, options, cluster_id)?;
            }
            t if t == i32::from(b'y') => {
                parse_proxy_directive(input, &mut cursor, cfg, options, 0)?;
            }
            t if t == i32::from(b'X') => {
                let max_connections = parse_unsigned_from(input, &mut cursor);
                if max_connections < cfg.min_connections || max_connections > 1000 {
                    return Err(MtprotoDirectiveParseError::InvalidMaxConnections(
                        max_connections,
                    ));
                }
                cfg.max_connections = max_connections;
            }
            t if t == i32::from(b'x') => {
                let min_connections = parse_unsigned_from(input, &mut cursor);
                if !(1..=cfg.max_connections).contains(&min_connections) {
                    return Err(MtprotoDirectiveParseError::InvalidMinConnections(
                        min_connections,
                    ));
                }
                cfg.min_connections = min_connections;
            }
            _ => return Err(MtprotoDirectiveParseError::ProxyDirectiveExpected),
        }

        cfg_expect_semicolon(input, &mut cursor)?;
    }

    let mut cluster_ids = [0i32; MAX_CLUSTERS];
    for idx in 0..cfg.auth_clusters {
        cluster_ids[idx] = cfg.auth_cluster[idx].cluster_id;
    }
    cfg.default_cluster_index = finalize_parse_config_state(
        cfg.have_proxy,
        &cluster_ids[..cfg.auth_clusters],
        cfg.default_cluster_id,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        cfg_expect_semicolon, cfg_getlex_ext, cfg_parse_config_full_pass, cfg_parse_directive_step,
        cfg_parse_proxy_target_step, cfg_parse_server_port, cfg_parse_server_port_preview,
        decide_proxy_cluster_apply, extend_old_mf_cluster, finalize_parse_config_state,
        init_old_mf_cluster, mf_cluster_lookup_index, parse_config_directive_blocks,
        preinit_config, preinit_config_snapshot, MtprotoClusterApplyDecision,
        MtprotoClusterApplyDecisionKind, MtprotoClusterState, MtprotoClusterTargetsAction,
        MtprotoConfigDefaults, MtprotoConfigState, MtprotoDirectiveParseError,
        MtprotoDirectiveParseOptions, MtprotoProxyTargetPassAction, CFG_LEX_EOF, CFG_LEX_INVALID,
    };

    fn lexeme(byte: u8) -> i32 {
        i32::from(byte)
    }

    #[test]
    fn parses_punctuation_lexemes() {
        for punct in [b';', b':', b'{', b'}'] {
            let input = [punct];
            let mut cursor = 0usize;
            let lex = cfg_getlex_ext(&input, &mut cursor);
            assert_eq!(lex, lexeme(punct));
            assert_eq!(cursor, 1);
        }
    }

    #[test]
    fn parses_keyword_lexemes() {
        let mut cursor = 0usize;
        assert_eq!(
            cfg_getlex_ext(b"min_connections", &mut cursor),
            lexeme(b'x')
        );
        assert_eq!(cursor, 15);

        cursor = 0;
        assert_eq!(
            cfg_getlex_ext(b"max_connections", &mut cursor),
            lexeme(b'X')
        );
        assert_eq!(cursor, 15);

        cursor = 0;
        assert_eq!(cfg_getlex_ext(b"proxy_for", &mut cursor), lexeme(b'Y'));
        assert_eq!(cursor, 9);

        cursor = 0;
        assert_eq!(cfg_getlex_ext(b"proxy", &mut cursor), lexeme(b'y'));
        assert_eq!(cursor, 5);

        cursor = 0;
        assert_eq!(cfg_getlex_ext(b"timeout", &mut cursor), lexeme(b't'));
        assert_eq!(cursor, 7);

        cursor = 0;
        assert_eq!(cfg_getlex_ext(b"default", &mut cursor), lexeme(b'D'));
        assert_eq!(cursor, 7);
    }

    #[test]
    fn prefers_proxy_for_before_proxy_prefix() {
        let mut cursor = 0usize;
        assert_eq!(cfg_getlex_ext(b"proxy_for:1", &mut cursor), lexeme(b'Y'));
        assert_eq!(cursor, 9);
    }

    #[test]
    fn keeps_c_prefix_matching_behavior() {
        let mut cursor = 0usize;
        assert_eq!(cfg_getlex_ext(b"proxyX", &mut cursor), lexeme(b'y'));
        assert_eq!(cursor, 5);

        cursor = 0;
        assert_eq!(cfg_getlex_ext(b"defaulted", &mut cursor), lexeme(b'D'));
        assert_eq!(cursor, 7);
    }

    #[test]
    fn returns_invalid_for_unknown_tokens() {
        let mut cursor = 0usize;
        assert_eq!(cfg_getlex_ext(b"cluster", &mut cursor), CFG_LEX_INVALID);
        assert_eq!(cursor, 0);

        cursor = 0;
        assert_eq!(cfg_getlex_ext(b" mmm", &mut cursor), CFG_LEX_INVALID);
        assert_eq!(cursor, 1);
    }

    #[test]
    fn returns_eof_for_end_of_input_or_nul() {
        let mut cursor = 0usize;
        assert_eq!(cfg_getlex_ext(b"", &mut cursor), CFG_LEX_EOF);
        assert_eq!(cursor, 0);

        cursor = 0;
        assert_eq!(cfg_getlex_ext(&[0], &mut cursor), CFG_LEX_EOF);
        assert_eq!(cursor, 0);
    }

    #[test]
    fn skips_cfg_comments_like_c() {
        let mut cursor = 0usize;
        assert_eq!(
            cfg_getlex_ext(b" # skip this comment\nproxy_for", &mut cursor),
            lexeme(b'Y')
        );
    }

    #[test]
    fn preinit_sets_defaults_and_resets_counters() {
        let mut cfg = MtprotoConfigState::<4>::new();
        cfg.tot_targets = 99;
        cfg.auth_clusters = 7;
        cfg.have_proxy = true;
        cfg.default_cluster_id = -10;
        cfg.timeout_seconds = 9.0;

        preinit_config(
            &mut cfg,
            MtprotoConfigDefaults {
                min_connections: 3,
                max_connections: 40,
            },
        );

        assert_eq!(cfg.tot_targets, 0);
        assert_eq!(cfg.auth_clusters, 0);
        assert_eq!(cfg.min_connections, 3);
        assert_eq!(cfg.max_connections, 40);
        assert!((cfg.timeout_seconds - 0.3).abs() < 1e-9);
        assert_eq!(cfg.default_cluster_id, 0);
        assert_eq!(cfg.default_cluster_index, None);
        assert!(!cfg.have_proxy);
    }

    #[test]
    fn preinit_snapshot_matches_mutating_preinit_scalars() {
        let defaults = MtprotoConfigDefaults {
            min_connections: 3,
            max_connections: 40,
        };
        let snapshot = preinit_config_snapshot(defaults);

        assert_eq!(snapshot.tot_targets, 0);
        assert_eq!(snapshot.auth_clusters, 0);
        assert_eq!(snapshot.min_connections, 3);
        assert_eq!(snapshot.max_connections, 40);
        assert!((snapshot.timeout_seconds - 0.3).abs() < 1e-9);
        assert_eq!(snapshot.default_cluster_id, 0);
        assert!(!snapshot.have_proxy);
        assert_eq!(snapshot.default_cluster_index, None);
    }

    #[test]
    fn parses_proxy_directives_and_defaults() {
        let mut cfg = MtprotoConfigState::<8>::new();
        let input = b"proxy host:443;";

        let res = parse_config_directive_blocks(
            input,
            &mut cfg,
            MtprotoConfigDefaults {
                min_connections: 2,
                max_connections: 64,
            },
            MtprotoDirectiveParseOptions::default(),
        );

        assert_eq!(res, Ok(()));
        assert_eq!(cfg.tot_targets, 1);
        assert_eq!(cfg.auth_clusters, 1);
        assert_eq!(cfg.auth_cluster[0].cluster_id, 0);
        assert_eq!(cfg.default_cluster_index, Some(0));
        assert_eq!(cfg.parsed_targets[0].map(|t| t.port), Some(443));
        assert_eq!(cfg.parsed_targets[0].map(|t| t.host_len), Some(4));
        assert!(cfg.have_proxy);
    }

    #[test]
    fn parses_directive_blocks_with_create_targets_mode() {
        let mut cfg = MtprotoConfigState::<8>::new();
        let input = b"min_connections 5; max_connections 10; timeout 250; default -2; proxy_for -2 dc1:443; proxy_for -2 dc2:444;";

        let res = parse_config_directive_blocks(
            input,
            &mut cfg,
            MtprotoConfigDefaults {
                min_connections: 2,
                max_connections: 64,
            },
            MtprotoDirectiveParseOptions {
                create_targets: true,
                max_targets: 16,
            },
        );

        assert_eq!(res, Ok(()));
        assert_eq!(cfg.min_connections, 5);
        assert_eq!(cfg.max_connections, 10);
        assert!((cfg.timeout_seconds - 0.25).abs() < 1e-9);
        assert_eq!(cfg.default_cluster_id, -2);
        assert_eq!(cfg.default_cluster_index, Some(0));
        assert_eq!(cfg.tot_targets, 2);
        assert_eq!(cfg.auth_clusters, 1);
        assert_eq!(cfg.auth_cluster[0].cluster_id, -2);
        assert_eq!(cfg.auth_cluster[0].flags, 1);
        assert_eq!(cfg.auth_cluster[0].first_target_index, Some(0));
        assert_eq!(cfg.auth_cluster[0].targets_num, 2);
        assert_eq!(cfg.auth_cluster[0].write_targets_num, 2);
        assert_eq!(cfg.parsed_targets[0].map(|t| t.port), Some(443));
        assert_eq!(cfg.parsed_targets[1].map(|t| t.port), Some(444));
        assert_eq!(cfg.parsed_targets[0].map(|t| t.min_connections), Some(5));
        assert_eq!(cfg.parsed_targets[0].map(|t| t.max_connections), Some(10));
    }

    #[test]
    fn rejects_intermixed_proxy_for_clusters() {
        let mut cfg = MtprotoConfigState::<8>::new();
        let input = b"proxy_for 1 dc1:443; proxy_for 2 dc2:443; proxy_for 1 dc3:443;";

        let err = parse_config_directive_blocks(
            input,
            &mut cfg,
            MtprotoConfigDefaults {
                min_connections: 2,
                max_connections: 64,
            },
            MtprotoDirectiveParseOptions::default(),
        )
        .expect_err("expected intermixed cluster parse error");

        assert_eq!(err, MtprotoDirectiveParseError::ProxiesIntermixed(1));
    }

    #[test]
    fn enforces_space_after_proxy_for_target_id() {
        let mut cfg = MtprotoConfigState::<8>::new();
        let input = b"proxy_for 1dc1:443;";

        let err = parse_config_directive_blocks(
            input,
            &mut cfg,
            MtprotoConfigDefaults {
                min_connections: 2,
                max_connections: 64,
            },
            MtprotoDirectiveParseOptions::default(),
        )
        .expect_err("expected target-id spacing parse error");

        assert_eq!(err, MtprotoDirectiveParseError::SpaceExpectedAfterTargetId);
    }

    #[test]
    fn enforces_semicolon_between_directives() {
        let mut cfg = MtprotoConfigState::<8>::new();
        let input = b"proxy host:443";

        let err = parse_config_directive_blocks(
            input,
            &mut cfg,
            MtprotoConfigDefaults {
                min_connections: 2,
                max_connections: 64,
            },
            MtprotoDirectiveParseOptions::default(),
        )
        .expect_err("expected semicolon parse error");

        assert_eq!(err, MtprotoDirectiveParseError::ExpectedSemicolon(0));
    }

    #[test]
    fn cfg_expect_semicolon_validates_separator() {
        let mut cursor = 0usize;
        cfg_expect_semicolon(b";", &mut cursor).expect("semicolon should parse");
        assert_eq!(cursor, 1);

        cursor = 0;
        let err = cfg_expect_semicolon(b":", &mut cursor).expect_err("colon must fail");
        assert_eq!(
            err,
            MtprotoDirectiveParseError::ExpectedSemicolon(i32::from(b':'))
        );
    }

    #[test]
    fn cfg_parse_directive_step_consumes_scalar_semicolon() {
        let step = cfg_parse_directive_step(b"timeout 250;", 2, 64, &[], 8).expect("step parse");
        assert_eq!(step.kind, super::MtprotoDirectiveTokenKind::Timeout);
        assert_eq!(step.value, 250);
        assert_eq!(step.advance, 12);
        assert_eq!(step.cluster_apply_decision, None);
    }

    #[test]
    fn cfg_parse_directive_step_returns_proxy_decision_without_host_parse() {
        let cluster_ids = [4, -2];
        let step = cfg_parse_directive_step(b"proxy_for -2   dc1:443;", 2, 64, &cluster_ids, 8)
            .expect("proxy step parse");
        assert_eq!(step.kind, super::MtprotoDirectiveTokenKind::ProxyFor);
        assert_eq!(step.value, -2);
        assert_eq!(step.advance, 15);
        assert_eq!(
            step.cluster_apply_decision,
            Some(MtprotoClusterApplyDecision {
                kind: MtprotoClusterApplyDecisionKind::AppendLast,
                cluster_index: 1,
            })
        );
    }

    #[test]
    fn cfg_parse_directive_step_reports_semicolon_error_for_scalar_directive() {
        let err = cfg_parse_directive_step(b"timeout 250", 2, 64, &[], 8)
            .expect_err("missing semicolon should fail");
        assert_eq!(err, MtprotoDirectiveParseError::ExpectedSemicolon(0));
    }

    #[test]
    fn cfg_parse_proxy_target_step_create_new_with_targets_returns_full_mutation() {
        let step =
            cfg_parse_proxy_target_step(b"dc1:443;", 2, 16, 5, 10, &[-2], 3, 8, true, 1, None)
                .expect("proxy step parse");

        assert_eq!(step.advance, 8);
        assert_eq!(step.target_index, 2);
        assert_eq!(step.target.host_len, 3);
        assert_eq!(step.target.port, 443);
        assert_eq!(step.tot_targets_after, 3);
        assert_eq!(
            step.cluster_apply_decision,
            MtprotoClusterApplyDecision {
                kind: MtprotoClusterApplyDecisionKind::CreateNew,
                cluster_index: 1,
            }
        );
        assert_eq!(step.cluster_state_after.cluster_id, 3);
        assert_eq!(step.cluster_state_after.flags, 1);
        assert_eq!(step.cluster_state_after.targets_num, 1);
        assert_eq!(step.cluster_state_after.write_targets_num, 1);
        assert_eq!(step.cluster_state_after.first_target_index, Some(2));
        assert_eq!(
            step.cluster_targets_action,
            MtprotoClusterTargetsAction::SetToTargetIndex
        );
        assert_eq!(step.auth_clusters_after, 2);
        assert_eq!(step.auth_tot_clusters_after, 2);
    }

    #[test]
    fn cfg_parse_proxy_target_step_appends_cluster_and_checks_contiguity() {
        let last_cluster = MtprotoClusterState {
            cluster_id: -2,
            targets_num: 2,
            write_targets_num: 2,
            flags: 1,
            first_target_index: Some(0),
        };
        let step = cfg_parse_proxy_target_step(
            b"dc3:445;",
            2,
            16,
            5,
            10,
            &[-2],
            -2,
            8,
            true,
            1,
            Some(last_cluster),
        )
        .expect("append step parse");

        assert_eq!(
            step.cluster_apply_decision.kind,
            MtprotoClusterApplyDecisionKind::AppendLast
        );
        assert_eq!(step.cluster_apply_decision.cluster_index, 0);
        assert_eq!(step.cluster_state_after.cluster_id, -2);
        assert_eq!(step.cluster_state_after.targets_num, 3);
        assert_eq!(step.cluster_state_after.write_targets_num, 3);
        assert_eq!(
            step.cluster_targets_action,
            MtprotoClusterTargetsAction::KeepExisting
        );
        assert_eq!(step.auth_clusters_after, 1);
        assert_eq!(step.auth_tot_clusters_after, 1);
    }

    #[test]
    fn cfg_parse_proxy_target_step_reports_cluster_invariant_failure() {
        let bad_last_cluster = MtprotoClusterState {
            cluster_id: -2,
            targets_num: 2,
            write_targets_num: 2,
            flags: 1,
            first_target_index: Some(1),
        };
        let err = cfg_parse_proxy_target_step(
            b"dc3:445;",
            2,
            16,
            5,
            10,
            &[-2],
            -2,
            8,
            true,
            1,
            Some(bad_last_cluster),
        )
        .expect_err("broken contiguity should fail");

        assert_eq!(
            err,
            MtprotoDirectiveParseError::InternalClusterExtendInvariant
        );
    }

    #[test]
    fn cfg_parse_config_full_pass_plans_proxy_side_effects_and_finalizes_state() {
        let input = b"min_connections 5; max_connections 10; timeout 250; default -2; proxy_for -2 dc1:443; proxy_for -2 dc2:444;";
        let mut actions = [MtprotoProxyTargetPassAction::EMPTY; 4];
        let out = cfg_parse_config_full_pass::<8>(
            input,
            MtprotoConfigDefaults {
                min_connections: 2,
                max_connections: 64,
            },
            true,
            8,
            16,
            &mut actions,
        )
        .expect("full pass should parse");

        assert_eq!(out.actions_len, 2);
        assert_eq!(out.tot_targets, 2);
        assert_eq!(out.auth_clusters, 1);
        assert_eq!(out.auth_tot_clusters, 1);
        assert_eq!(out.min_connections, 5);
        assert_eq!(out.max_connections, 10);
        assert!((out.timeout_seconds - 0.25).abs() < 1e-9);
        assert_eq!(out.default_cluster_id, -2);
        assert!(out.have_proxy);
        assert_eq!(out.default_cluster_index, Some(0));

        assert!(input[actions[0].host_offset..].starts_with(b"dc1:443;"));
        assert_eq!(actions[0].step.target.port, 443);
        assert_eq!(actions[0].step.target_index, 0);
        assert_eq!(
            actions[0].step.cluster_targets_action,
            MtprotoClusterTargetsAction::SetToTargetIndex
        );

        assert!(input[actions[1].host_offset..].starts_with(b"dc2:444;"));
        assert_eq!(actions[1].step.target.port, 444);
        assert_eq!(actions[1].step.target_index, 1);
        assert_eq!(
            actions[1].step.cluster_targets_action,
            MtprotoClusterTargetsAction::KeepExisting
        );
    }

    #[test]
    fn cfg_parse_config_full_pass_keeps_create_side_effects_out_of_syntax_mode() {
        let input = b"proxy_for 7 dc1:443;";
        let mut actions = [MtprotoProxyTargetPassAction::EMPTY; 2];
        let out = cfg_parse_config_full_pass::<8>(
            input,
            MtprotoConfigDefaults {
                min_connections: 2,
                max_connections: 64,
            },
            false,
            8,
            16,
            &mut actions,
        )
        .expect("syntax pass should parse");

        assert_eq!(out.actions_len, 1);
        assert_eq!(out.auth_clusters, 1);
        assert_eq!(out.auth_tot_clusters, 0);
        assert_eq!(actions[0].step.cluster_state_after.cluster_id, 7);
        assert_eq!(
            actions[0].step.cluster_targets_action,
            MtprotoClusterTargetsAction::Clear
        );
    }

    #[test]
    fn cfg_parse_config_full_pass_enforces_proxy_action_capacity() {
        let input = b"proxy dc1:443; proxy dc2:444;";
        let mut actions = [MtprotoProxyTargetPassAction::EMPTY; 1];
        let err = cfg_parse_config_full_pass::<8>(
            input,
            MtprotoConfigDefaults {
                min_connections: 2,
                max_connections: 64,
            },
            false,
            8,
            16,
            &mut actions,
        )
        .expect_err("capacity must be enforced");

        assert_eq!(err, MtprotoDirectiveParseError::TooManyTargets(1));
    }

    #[test]
    fn cfg_parse_config_full_pass_preserves_terminal_checks() {
        let mut actions = [MtprotoProxyTargetPassAction::EMPTY; 1];
        let err = cfg_parse_config_full_pass::<8>(
            b"timeout 100;",
            MtprotoConfigDefaults {
                min_connections: 2,
                max_connections: 64,
            },
            false,
            8,
            16,
            &mut actions,
        )
        .expect_err("missing proxies should fail");

        assert_eq!(err, MtprotoDirectiveParseError::MissingProxyDirectives);
    }

    #[test]
    fn rejects_config_without_proxy_directives() {
        let mut cfg = MtprotoConfigState::<8>::new();
        let input = b"timeout 100;";

        let err = parse_config_directive_blocks(
            input,
            &mut cfg,
            MtprotoConfigDefaults {
                min_connections: 2,
                max_connections: 64,
            },
            MtprotoDirectiveParseOptions::default(),
        )
        .expect_err("expected missing proxy parse error");

        assert_eq!(err, MtprotoDirectiveParseError::MissingProxyDirectives);
    }

    #[test]
    fn enforces_target_limit() {
        let mut cfg = MtprotoConfigState::<8>::new();
        let input = b"proxy dc1:443; proxy dc2:444;";

        let err = parse_config_directive_blocks(
            input,
            &mut cfg,
            MtprotoConfigDefaults {
                min_connections: 2,
                max_connections: 64,
            },
            MtprotoDirectiveParseOptions {
                create_targets: false,
                max_targets: 1,
            },
        )
        .expect_err("expected target-limit parse error");

        assert_eq!(err, MtprotoDirectiveParseError::TooManyTargets(1));
    }

    #[test]
    fn enforces_cluster_limit() {
        let mut cfg = MtprotoConfigState::<1>::new();
        let input = b"proxy_for 1 dc1:443; proxy_for 2 dc2:444;";

        let err = parse_config_directive_blocks(
            input,
            &mut cfg,
            MtprotoConfigDefaults {
                min_connections: 2,
                max_connections: 64,
            },
            MtprotoDirectiveParseOptions::default(),
        )
        .expect_err("expected cluster-limit parse error");

        assert_eq!(err, MtprotoDirectiveParseError::TooManyAuthClusters(1));
    }

    #[test]
    fn cfg_parse_server_port_captures_target_properties() {
        let mut cfg = MtprotoConfigState::<4>::new();
        cfg.min_connections = 7;
        cfg.max_connections = 99;
        let mut cursor = 0usize;

        let target_idx =
            cfg_parse_server_port(b"example.com:8443", &mut cursor, &mut cfg, 8).expect("parse");

        assert_eq!(target_idx, 0);
        assert_eq!(cfg.tot_targets, 1);
        let target = cfg.parsed_targets[target_idx].expect("target slot");
        assert_eq!(target.host_len, 11);
        assert_eq!(target.port, 8443);
        assert_eq!(target.min_connections, 7);
        assert_eq!(target.max_connections, 99);
    }

    #[test]
    fn cfg_parse_server_port_preview_reports_advance_and_target_index() {
        let mut cursor = 0usize;
        let preview = cfg_parse_server_port_preview(b"  host-1:443", &mut cursor, 5, 16, 2, 64)
            .expect("preview parse");
        assert_eq!(cursor, 12);
        assert_eq!(preview.advance, 12);
        assert_eq!(preview.target_index, 5);
        assert_eq!(preview.target.host_len, 6);
        assert_eq!(preview.target.port, 443);
        assert_eq!(preview.target.min_connections, 2);
        assert_eq!(preview.target.max_connections, 64);
    }

    #[test]
    fn cfg_parse_server_port_enforces_limits_and_ranges() {
        let mut cfg = MtprotoConfigState::<4>::new();
        let mut cursor = 0usize;
        let err = cfg_parse_server_port(b"h:70000", &mut cursor, &mut cfg, 8)
            .expect_err("expected out-of-range port");
        assert_eq!(err, MtprotoDirectiveParseError::PortOutOfRange(70000));

        cursor = 0;
        let err = cfg_parse_server_port(
            b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:1",
            &mut cursor,
            &mut cfg,
            8,
        )
        .expect_err("expected hostname-too-long");
        assert_eq!(err, MtprotoDirectiveParseError::HostnameExpected);
    }

    #[test]
    fn init_and_extend_cluster_follow_target_contiguity_rule() {
        let mut cluster = MtprotoClusterState {
            cluster_id: 0,
            targets_num: 0,
            write_targets_num: 0,
            flags: 0,
            first_target_index: None,
        };

        init_old_mf_cluster(&mut cluster, 3, 1, -2);
        assert_eq!(cluster.cluster_id, -2);
        assert_eq!(cluster.flags, 1);
        assert_eq!(cluster.first_target_index, Some(3));
        assert_eq!(cluster.targets_num, 1);
        assert_eq!(cluster.write_targets_num, 1);

        assert!(extend_old_mf_cluster(&mut cluster, 4, -2));
        assert_eq!(cluster.targets_num, 2);
        assert_eq!(cluster.write_targets_num, 2);

        assert!(!extend_old_mf_cluster(&mut cluster, 6, -2));
        assert!(!extend_old_mf_cluster(&mut cluster, 5, -3));
    }

    #[test]
    fn mf_cluster_lookup_index_prefers_exact_match_then_force_default() {
        let cluster_ids = [4, -2, 0, 17];
        assert_eq!(mf_cluster_lookup_index(&cluster_ids, -2, Some(3)), Some(1));
        assert_eq!(mf_cluster_lookup_index(&cluster_ids, 100, Some(3)), Some(3));
        assert_eq!(mf_cluster_lookup_index(&cluster_ids, 100, None), None);
    }

    #[test]
    fn decide_proxy_cluster_apply_selects_new_cluster_when_missing() {
        let cluster_ids = [4, -2];
        let decision =
            decide_proxy_cluster_apply(&cluster_ids, 7, 8).expect("new-cluster decision expected");
        assert_eq!(
            decision,
            MtprotoClusterApplyDecision {
                kind: MtprotoClusterApplyDecisionKind::CreateNew,
                cluster_index: 2,
            }
        );
    }

    #[test]
    fn decide_proxy_cluster_apply_selects_append_when_last_cluster_matches() {
        let cluster_ids = [4, -2];
        let decision =
            decide_proxy_cluster_apply(&cluster_ids, -2, 8).expect("append decision expected");
        assert_eq!(
            decision,
            MtprotoClusterApplyDecision {
                kind: MtprotoClusterApplyDecisionKind::AppendLast,
                cluster_index: 1,
            }
        );
    }

    #[test]
    fn decide_proxy_cluster_apply_rejects_intermixed_cluster_reuse() {
        let cluster_ids = [4, -2, 7];
        let err = decide_proxy_cluster_apply(&cluster_ids, -2, 8)
            .expect_err("intermixed cluster must be rejected");
        assert_eq!(err, MtprotoDirectiveParseError::ProxiesIntermixed(-2));
    }

    #[test]
    fn decide_proxy_cluster_apply_preserves_too_many_clusters_guard() {
        let cluster_ids = [4, -2];
        let err = decide_proxy_cluster_apply(&cluster_ids, -2, 2)
            .expect_err("max-clusters guard should fail before lookup");
        assert_eq!(err, MtprotoDirectiveParseError::TooManyAuthClusters(2));
    }

    #[test]
    fn finalize_parse_config_state_enforces_terminal_requirements() {
        let cluster_ids = [5, 7];
        let default_idx =
            finalize_parse_config_state(true, &cluster_ids, 7).expect("finalize should pass");
        assert_eq!(default_idx, Some(1));

        let err = finalize_parse_config_state(false, &cluster_ids, 7)
            .expect_err("missing proxy should fail");
        assert_eq!(err, MtprotoDirectiveParseError::MissingProxyDirectives);

        let err =
            finalize_parse_config_state(true, &[], 7).expect_err("empty cluster list should fail");
        assert_eq!(err, MtprotoDirectiveParseError::NoProxyServersDefined);
    }
}
