//! FFI export surface for crypto runtime.

use super::core::*;
use crate::*;

/// Fetches current net-crypto-aes allocation counters.
///
/// # Safety
/// Output pointers may be null; non-null pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_aes_fetch_stat(
    allocated_aes_crypto: *mut i32,
    allocated_aes_crypto_temp: *mut i32,
) -> i32 {
    if let Some(allocated_aes_crypto_ref) = unsafe { mut_ref_from_ptr(allocated_aes_crypto) } {
        *allocated_aes_crypto_ref =
            i64_to_i32_saturating(AES_ALLOCATED_CRYPTO.load(Ordering::Acquire));
    }
    if let Some(allocated_aes_crypto_temp_ref) =
        unsafe { mut_ref_from_ptr(allocated_aes_crypto_temp) }
    {
        *allocated_aes_crypto_temp_ref =
            i64_to_i32_saturating(AES_ALLOCATED_CRYPTO_TEMP.load(Ordering::Acquire));
    }
    0
}

/// Initializes per-connection AES state for CBC/CTR mode.
///
/// # Safety
/// `conn_crypto_slot` must be a writable pointer to a `void *` storage slot.
/// `key_data` must be readable for `key_data_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_aes_conn_init(
    conn_crypto_slot: *mut *mut c_void,
    key_data: *const MtproxyAesKeyData,
    key_data_len: i32,
    use_ctr_mode: i32,
) -> i32 {
    let Some(slot) = (unsafe { mut_ref_from_ptr(conn_crypto_slot) }) else {
        return -1;
    };
    let Some(key) = (unsafe { ref_from_ptr(key_data) }) else {
        return -1;
    };
    let Ok(expected_len) = i32::try_from(core::mem::size_of::<MtproxyAesKeyData>()) else {
        return -1;
    };
    if key_data_len != expected_len {
        return -1;
    }
    if !slot.is_null() {
        return -1;
    }

    let cipher_kind = if use_ctr_mode != 0 {
        AESNI_CIPHER_AES_256_CTR
    } else {
        AESNI_CIPHER_AES_256_CBC
    };
    let read_is_encrypt = if use_ctr_mode != 0 { 1 } else { 0 };
    let write_is_encrypt = 1;

    let mut read_ctx: *mut c_void = core::ptr::null_mut();
    let mut write_ctx: *mut c_void = core::ptr::null_mut();
    let read_rc = mtproxy_ffi_aesni_ctx_init(
        cipher_kind,
        key.read_key.as_ptr(),
        key.read_iv.as_ptr(),
        read_is_encrypt,
        &raw mut read_ctx,
    );
    if read_rc != 0 {
        return -1;
    }
    let write_rc = mtproxy_ffi_aesni_ctx_init(
        cipher_kind,
        key.write_key.as_ptr(),
        key.write_iv.as_ptr(),
        write_is_encrypt,
        &raw mut write_ctx,
    );
    if write_rc != 0 {
        let _ = mtproxy_ffi_aesni_ctx_free(read_ctx);
        return -1;
    }

    let ctx = MtproxyAesCryptoCtx {
        read_aeskey: read_ctx,
        write_aeskey: write_ctx,
    };
    *slot = Box::into_raw(Box::new(ctx)).cast::<c_void>();
    AES_ALLOCATED_CRYPTO.fetch_add(1, Ordering::AcqRel);
    0
}

/// Releases per-connection AES state and optional temporary crypto blob.
///
/// # Safety
/// Non-null slot pointers must be writable and contain pointers allocated via Rust FFI exports.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_aes_conn_free(
    conn_crypto_slot: *mut *mut c_void,
    conn_crypto_temp_slot: *mut *mut c_void,
) -> i32 {
    if let Some(slot_ref) = unsafe { mut_ref_from_ptr(conn_crypto_slot) } {
        let crypto_ptr = *slot_ref;
        if !crypto_ptr.is_null() {
            let ctx = Box::from_raw(crypto_ptr.cast::<MtproxyAesCryptoCtx>());
            let _ = mtproxy_ffi_aesni_ctx_free(ctx.read_aeskey);
            let _ = mtproxy_ffi_aesni_ctx_free(ctx.write_aeskey);
            *slot_ref = core::ptr::null_mut();
            atomic_dec_saturating(&AES_ALLOCATED_CRYPTO);
        }
    }

    if let Some(temp_slot_ref) = unsafe { mut_ref_from_ptr(conn_crypto_temp_slot) } {
        let temp_ptr = *temp_slot_ref;
        if !temp_ptr.is_null() {
            free(temp_ptr);
            *temp_slot_ref = core::ptr::null_mut();
            atomic_dec_saturating(&AES_ALLOCATED_CRYPTO_TEMP);
        }
    }

    0
}

/// Loads secret-file bytes and computes MD5 hex fingerprint used by C stats output.
///
/// # Safety
/// All non-null output pointers must reference writable storage matching argument sizes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_aes_load_pwd_file(
    filename: *const c_char,
    pwd_config_buf: *mut u8,
    pwd_config_capacity: i32,
    pwd_config_len_out: *mut i32,
    pwd_config_md5_out: *mut c_char,
    main_secret: *mut MtproxyAesSecret,
) -> i32 {
    let Ok(buf_capacity) = usize::try_from(pwd_config_capacity) else {
        return -1;
    };
    if buf_capacity < (MAX_PWD_CONFIG_LEN + 4) {
        return -1;
    }
    let Some(cfg_out) = (unsafe { mut_slice_from_ptr(pwd_config_buf, buf_capacity) }) else {
        return -1;
    };
    let Some(pwd_config_len_out_ref) = (unsafe { mut_ref_from_ptr(pwd_config_len_out) }) else {
        return -1;
    };
    let Some(pwd_config_md5_out_ref) =
        (unsafe { mut_ref_from_ptr(pwd_config_md5_out.cast::<[u8; 33]>()) })
    else {
        return -1;
    };
    let Some(main_secret_ref) = (unsafe { mut_ref_from_ptr(main_secret) }) else {
        return -1;
    };

    let pwd_file_path = if filename.is_null() {
        DEFAULT_PWD_FILE.to_owned()
    } else {
        let Some(filename_ref) = (unsafe { ref_from_ptr(filename) }) else {
            return -1;
        };
        CStr::from_ptr(filename_ref).to_string_lossy().into_owned()
    };

    {
        let mut state = AES_NONCE_RAND_BUF
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if !refresh_aes_nonce_seed(&mut state) {
            main_secret_ref.secret_len = 0;
            return -1;
        }
    }

    let mut file = match fs::File::open(&pwd_file_path) {
        Ok(file) => file,
        Err(_) => return i32::MIN,
    };
    let mut read_buf = vec![0u8; MAX_PWD_CONFIG_LEN + 1];
    let read_len = match file.read(&mut read_buf) {
        Ok(bytes) => bytes,
        Err(_) => return -1,
    };
    if read_len > MAX_PWD_CONFIG_LEN {
        *pwd_config_len_out_ref = 0;
        return -1;
    }

    cfg_out[..read_len].copy_from_slice(&read_buf[..read_len]);
    cfg_out[read_len..read_len + 4].fill(0);
    *pwd_config_len_out_ref = i32::try_from(read_len).unwrap_or(i32::MAX);

    if !(MIN_PWD_LEN..=MAX_PWD_LEN).contains(&read_len) {
        return -1;
    }

    if !write_md5_hex(&read_buf[..read_len], pwd_config_md5_out_ref) {
        return -1;
    }

    main_secret_ref.secret.fill(0);
    main_secret_ref.secret[..read_len].copy_from_slice(&read_buf[..read_len]);
    main_secret_ref.secret_len = i32::try_from(read_len).unwrap_or(i32::MAX);

    1
}

/// Produces a 16-byte handshake nonce equivalent to C flow based on mutable random state.
///
/// # Safety
/// `out` must point to at least 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_aes_generate_nonce(out: *mut u8) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out.cast::<[u8; 16]>()) }) else {
        return -1;
    };

    let mut rand_buf = AES_NONCE_RAND_BUF
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if rand_buf[..16].iter().all(|b| *b == 0) && !refresh_aes_nonce_seed(&mut rand_buf) {
        return -1;
    }

    let x = lrand48() as i32;
    rand_buf[16..20].copy_from_slice(&x.to_ne_bytes());
    let y = lrand48() as i32;
    rand_buf[20..24].copy_from_slice(&y.to_ne_bytes());
    rand_buf[24..32].copy_from_slice(&rdtsc_now().to_ne_bytes());

    let mut ts = Timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    if clock_gettime(CLOCK_REALTIME_ID, &raw mut ts) < 0 {
        return -1;
    }
    rand_buf[32..36].copy_from_slice(&(ts.tv_sec as i32).to_ne_bytes());
    rand_buf[36..40].copy_from_slice(&(ts.tv_nsec as i32).to_ne_bytes());

    let mut ctr = i32::from_ne_bytes([rand_buf[40], rand_buf[41], rand_buf[42], rand_buf[43]]);
    ctr = ctr.wrapping_add(1);
    rand_buf[40..44].copy_from_slice(&ctr.to_ne_bytes());

    let mut digest = [0u8; DIGEST_MD5_LEN];
    if !md5_digest_impl(&rand_buf[..44], &mut digest) {
        return -1;
    }
    out_ref.copy_from_slice(&digest);
    0
}

/// Allocates temporary crypto blob storage tracked by Rust-side stats.
///
/// # Safety
/// Returned pointer must be released by `mtproxy_ffi_crypto_free_temp`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_alloc_temp(len: i32) -> *mut c_void {
    if len < 0 {
        return core::ptr::null_mut();
    }
    let Ok(requested) = usize::try_from(len) else {
        return core::ptr::null_mut();
    };
    let alloc_len = requested.max(1);
    let ptr = malloc(alloc_len);
    if ptr.is_null() {
        return core::ptr::null_mut();
    }
    AES_ALLOCATED_CRYPTO_TEMP.fetch_add(1, Ordering::AcqRel);
    ptr
}

/// Zeroes (optionally) and frees temporary crypto blob storage.
///
/// # Safety
/// `ptr` must be null or returned by `mtproxy_ffi_crypto_alloc_temp`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_free_temp(ptr: *mut c_void, len: i32) -> i32 {
    if ptr.is_null() {
        return 0;
    }
    if len > 0 {
        let Ok(zero_len) = usize::try_from(len) else {
            return -1;
        };
        core::ptr::write_bytes(ptr.cast::<u8>(), 0, zero_len);
    }
    free(ptr);
    atomic_dec_saturating(&AES_ALLOCATED_CRYPTO_TEMP);
    0
}

/// Initializes shared DH params selector exactly once and returns C-compatible status.
///
/// # Safety
/// `out_dh_params_select` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_dh_init_params(out_dh_params_select: *mut i32) -> i32 {
    let Some(out_dh_params_select_ref) = (unsafe { mut_ref_from_ptr(out_dh_params_select) }) else {
        return -1;
    };
    let current = i64_to_i32_saturating(DH_PARAMS_SELECT_INIT.load(Ordering::Acquire));
    if current > 0 {
        *out_dh_params_select_ref = current;
        return 0;
    }

    let select = mtproxy_ffi_crypto_dh_get_params_select();
    if select <= 0 {
        return -1;
    }
    match DH_PARAMS_SELECT_INIT.compare_exchange(
        0,
        i64::from(select),
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {
            *out_dh_params_select_ref = select;
            1
        }
        Err(existing) => {
            *out_dh_params_select_ref = i64_to_i32_saturating(existing);
            0
        }
    }
}

/// Returns cumulative DH round counters used by C stats output.
///
/// # Safety
/// `out_rounds` must be writable for three 64-bit integers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_dh_fetch_tot_rounds(out_rounds: *mut i64) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out_rounds.cast::<[i64; 3]>()) }) else {
        return -1;
    };
    out_ref[0] = DH_TOT_ROUNDS_0.load(Ordering::Acquire);
    out_ref[1] = DH_TOT_ROUNDS_1.load(Ordering::Acquire);
    out_ref[2] = DH_TOT_ROUNDS_2.load(Ordering::Acquire);
    0
}

/// Performs DH first round and fills temporary DH state struct for C runtime.
///
/// # Safety
/// `g_a` and `dh_params` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_dh_first_round_stateful(
    g_a: *mut u8,
    dh_params: *mut MtproxyCryptoTempDhParams,
    dh_params_select: i32,
) -> i32 {
    let Some(dh_params_ref) = (unsafe { mut_ref_from_ptr(dh_params) }) else {
        return -1;
    };
    if dh_params_select <= 0 {
        return -1;
    }
    let rc = mtproxy_ffi_crypto_dh_first_round(g_a, dh_params_ref.a.as_mut_ptr());
    if rc != 1 {
        return -1;
    }
    dh_params_ref.dh_params_select = dh_params_select;
    dh_params_ref.magic = CRYPTO_TEMP_DH_PARAMS_MAGIC;
    DH_TOT_ROUNDS_0.fetch_add(1, Ordering::AcqRel);
    1
}

/// Performs DH second round and updates cumulative round stats on success.
///
/// # Safety
/// `g_ab`, `g_a`, and `g_b` must point to readable/writable 256-byte buffers.
#[no_mangle]
#[allow(clippy::similar_names)]
pub unsafe extern "C" fn mtproxy_ffi_crypto_dh_second_round_stateful(
    g_ab: *mut u8,
    g_a: *mut u8,
    g_b: *const u8,
) -> i32 {
    let rc = mtproxy_ffi_crypto_dh_second_round(g_ab, g_a, g_b);
    if rc > 0 {
        DH_TOT_ROUNDS_1.fetch_add(1, Ordering::AcqRel);
    }
    rc
}

/// Performs DH third round using stored temporary exponent and tracks successful rounds.
///
/// # Safety
/// `g_ab`, `g_b`, and `dh_params` must be valid pointers.
#[no_mangle]
#[allow(clippy::similar_names)]
pub unsafe extern "C" fn mtproxy_ffi_crypto_dh_third_round_stateful(
    g_ab: *mut u8,
    g_b: *const u8,
    dh_params: *const MtproxyCryptoTempDhParams,
) -> i32 {
    let Some(dh_params_ref) = (unsafe { ref_from_ptr(dh_params) }) else {
        return -1;
    };
    let rc = mtproxy_ffi_crypto_dh_third_round(g_ab, g_b, dh_params_ref.a.as_ptr());
    if rc > 0 {
        DH_TOT_ROUNDS_2.fetch_add(1, Ordering::AcqRel);
    }
    rc
}

/// Validates first bytes of peer DH value against canonical prime prefix.
///
/// # Safety
/// `data` and `prime_prefix` must point to readable slices when lengths are non-zero.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_dh_is_good_rpc_dh_bin(
    data: *const u8,
    len: usize,
    prime_prefix: *const u8,
    prime_prefix_len: usize,
) -> i32 {
    if len < 8 || prime_prefix_len < 8 {
        return -1;
    }
    let Some(data_ref) = (unsafe { slice_from_ptr(data, len) }) else {
        return -1;
    };
    let Some(prime_ref) = (unsafe { slice_from_ptr(prime_prefix, prime_prefix_len) }) else {
        return -1;
    };
    crypto_dh_is_good_rpc_dh_bin_impl(data_ref, prime_ref)
}

/// Derives AES session keys and IVs exactly like C `aes_create_keys`.
///
/// # Safety
/// All pointer arguments must reference writable/readable buffers of the documented size.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_aes_create_keys(
    out: *mut MtproxyAesKeyData,
    am_client: i32,
    nonce_server: *const u8,
    nonce_client: *const u8,
    client_timestamp: i32,
    server_ip: u32,
    server_port: u16,
    server_ipv6: *const u8,
    client_ip: u32,
    client_port: u16,
    client_ipv6: *const u8,
    secret: *const u8,
    secret_len: i32,
    temp_key: *const u8,
    temp_key_len: i32,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };
    let Some(nonce_server_ref) = (unsafe { ref_from_ptr(nonce_server.cast::<[u8; 16]>()) }) else {
        return -1;
    };
    let Some(nonce_client_ref) = (unsafe { ref_from_ptr(nonce_client.cast::<[u8; 16]>()) }) else {
        return -1;
    };
    let Some(server_ipv6_ref) = (unsafe { ref_from_ptr(server_ipv6.cast::<[u8; 16]>()) }) else {
        return -1;
    };
    let Some(client_ipv6_ref) = (unsafe { ref_from_ptr(client_ipv6.cast::<[u8; 16]>()) }) else {
        return -1;
    };
    let Ok(secret_count) = usize::try_from(secret_len) else {
        return -1;
    };
    if !(MIN_PWD_LEN..=MAX_PWD_LEN).contains(&secret_count) {
        return -1;
    }
    let Some(secret_ref) = (unsafe { slice_from_ptr(secret, secret_count) }) else {
        return -1;
    };
    let Ok(temp_count_raw) = usize::try_from(temp_key_len) else {
        return -1;
    };
    let temp_count = temp_count_raw.min(AES_CREATE_KEYS_MAX_STR_LEN);
    let Some(temp_ref) = (unsafe { slice_from_ptr(temp_key, temp_count) }) else {
        return -1;
    };

    crypto_aes_create_keys_impl(
        out_ref,
        am_client,
        nonce_server_ref,
        nonce_client_ref,
        client_timestamp,
        server_ip,
        server_port,
        server_ipv6_ref,
        client_ip,
        client_port,
        client_ipv6_ref,
        secret_ref,
        temp_ref,
    )
}

/// AES-CBC/CTR wrapper used by `crypto/aesni256.c`.
///
/// # Safety
/// `evp_ctx` must be a valid context returned by `mtproxy_ffi_aesni_ctx_init`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_aesni_crypt(
    evp_ctx: *mut c_void,
    input: *const u8,
    output: *mut u8,
    size: i32,
) -> i32 {
    if size < 0 {
        return -1;
    }
    let Ok(size_usize) = usize::try_from(size) else {
        return -1;
    };
    let Some(ctx) = (unsafe { mut_ref_from_ptr(evp_ctx.cast::<AesniCipherCtx>()) }) else {
        return -1;
    };
    let Some(input_ref) = (unsafe { slice_from_ptr(input, size_usize) }) else {
        return -1;
    };
    let Some(output_ref) = (unsafe { mut_slice_from_ptr(output, size_usize) }) else {
        return -1;
    };
    if size_usize > 0 && input_ref.as_ptr() != output_ref.as_ptr() {
        core::ptr::copy(input_ref.as_ptr(), output_ref.as_mut_ptr(), size_usize);
    }
    if ctx.crypt_in_place(output_ref) {
        0
    } else {
        -2
    }
}

/// Fills output with cryptographically strong random bytes from Rustls provider.
///
/// # Safety
/// `out` must point to writable memory for `len` bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_rand_bytes(out: *mut u8, len: i32) -> i32 {
    if len < 0 {
        return -1;
    }
    let Ok(size) = usize::try_from(len) else {
        return -1;
    };
    let Some(out_ref) = (unsafe { mut_slice_from_ptr(out, size) }) else {
        return -1;
    };
    if crypto_rand_fill(out_ref) {
        0
    } else {
        -1
    }
}

/// Generates a 32-byte public key used by TLS-obfuscated transport setup.
///
/// # Safety
/// `out` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_tls_generate_public_key(out: *mut u8) -> i32 {
    let Some(out_ref) =
        (unsafe { mut_ref_from_ptr(out.cast::<[u8; TLS_REQUEST_PUBLIC_KEY_BYTES]>()) })
    else {
        return -1;
    };
    crypto_tls_generate_public_key_impl(out_ref)
}

/// Returns current DH params selector hash used by C runtime checks.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_crypto_dh_get_params_select() -> i32 {
    DH_PARAMS_SELECT
}

/// Performs DH first round: generates random exponent `a_out` and `g_a = g^a mod p`.
///
/// # Safety
/// `g_a` and `a_out` must point to writable 256-byte buffers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crypto_dh_first_round(g_a: *mut u8, a_out: *mut u8) -> i32 {
    let Some(g_a_ref) = (unsafe { mut_ref_from_ptr(g_a.cast::<[u8; DH_KEY_BYTES]>()) }) else {
        return -1;
    };
    let Some(a_out_ref) = (unsafe { mut_ref_from_ptr(a_out.cast::<[u8; DH_KEY_BYTES]>()) }) else {
        return -1;
    };
    crypto_dh_first_round_impl(g_a_ref, a_out_ref)
}

/// Performs DH second round for server mode.
///
/// # Safety
/// `g_ab`, `g_a`, `g_b` must point to 256-byte buffers.
#[no_mangle]
#[allow(clippy::similar_names)]
pub unsafe extern "C" fn mtproxy_ffi_crypto_dh_second_round(
    g_ab: *mut u8,
    g_a: *mut u8,
    g_b: *const u8,
) -> i32 {
    let Some(g_ab_ref) = (unsafe { mut_ref_from_ptr(g_ab.cast::<[u8; DH_KEY_BYTES]>()) }) else {
        return -1;
    };
    let Some(g_a_ref) = (unsafe { mut_ref_from_ptr(g_a.cast::<[u8; DH_KEY_BYTES]>()) }) else {
        return -1;
    };
    let Some(g_b_ref) = (unsafe { ref_from_ptr(g_b.cast::<[u8; DH_KEY_BYTES]>()) }) else {
        return -1;
    };
    let verdict =
        crypto_dh_is_good_rpc_dh_bin_impl(g_b_ref, &RPC_DH_PRIME_BIN[..DH_GOOD_PREFIX_BYTES]);
    if verdict <= 0 {
        return if verdict == 0 { 0 } else { -1 };
    }
    let mut a = [0u8; DH_KEY_BYTES];
    if crypto_dh_first_round_impl(g_a_ref, &mut a) < 0 {
        return -1;
    }
    let ok = crypto_dh_modexp(Some(g_b_ref), &a, g_ab_ref);
    a.fill(0);
    if ok {
        DH_KEY_BYTES as i32
    } else {
        -1
    }
}

/// Performs DH third round for client mode.
///
/// # Safety
/// `g_ab`, `g_b`, `a` must point to 256-byte buffers.
#[no_mangle]
#[allow(clippy::similar_names)]
pub unsafe extern "C" fn mtproxy_ffi_crypto_dh_third_round(
    g_ab: *mut u8,
    g_b: *const u8,
    a: *const u8,
) -> i32 {
    let Some(g_ab_ref) = (unsafe { mut_ref_from_ptr(g_ab.cast::<[u8; DH_KEY_BYTES]>()) }) else {
        return -1;
    };
    let Some(g_b_ref) = (unsafe { ref_from_ptr(g_b.cast::<[u8; DH_KEY_BYTES]>()) }) else {
        return -1;
    };
    let Some(a_ref) = (unsafe { ref_from_ptr(a.cast::<[u8; DH_KEY_BYTES]>()) }) else {
        return -1;
    };
    let verdict =
        crypto_dh_is_good_rpc_dh_bin_impl(g_b_ref, &RPC_DH_PRIME_BIN[..DH_GOOD_PREFIX_BYTES]);
    if verdict <= 0 {
        return if verdict == 0 { 0 } else { -1 };
    }
    if crypto_dh_modexp(Some(g_b_ref), a_ref, g_ab_ref) {
        DH_KEY_BYTES as i32
    } else {
        -1
    }
}

/// Initializes AES context for AES-256-CBC/CTR with disabled padding.
///
/// # Safety
/// `key`, `iv`, and `out_ctx` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_aesni_ctx_init(
    cipher_kind: i32,
    key: *const u8,
    iv: *const u8,
    is_encrypt: i32,
    out_ctx: *mut *mut c_void,
) -> i32 {
    let Some(key_ref) = (unsafe { ref_from_ptr(key.cast::<[u8; 32]>()) }) else {
        return -1;
    };
    let Some(iv_ref) = (unsafe { ref_from_ptr(iv.cast::<[u8; 16]>()) }) else {
        return -1;
    };
    let Some(out_ctx_ref) = (unsafe { mut_ref_from_ptr(out_ctx) }) else {
        return -1;
    };
    let ctx = match cipher_kind {
        AESNI_CIPHER_AES_256_CBC => {
            if is_encrypt != 0 {
                AesniCipherCtx::Aes256CbcEncrypt(cbc::Encryptor::<Aes256>::new(
                    key_ref.into(),
                    iv_ref.into(),
                ))
            } else {
                AesniCipherCtx::Aes256CbcDecrypt(cbc::Decryptor::<Aes256>::new(
                    key_ref.into(),
                    iv_ref.into(),
                ))
            }
        }
        AESNI_CIPHER_AES_256_CTR => {
            AesniCipherCtx::Aes256Ctr(Aes256Ctr::new(key_ref.into(), iv_ref.into()))
        }
        _ => return -2,
    };
    let raw_ctx = Box::into_raw(Box::new(ctx)).cast::<c_void>();
    *out_ctx_ref = raw_ctx;
    0
}

/// Frees AES context allocated by `mtproxy_ffi_aesni_ctx_init`.
///
/// # Safety
/// `evp_ctx` must be either null or a pointer returned by `mtproxy_ffi_aesni_ctx_init`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_aesni_ctx_free(evp_ctx: *mut c_void) -> i32 {
    if evp_ctx.is_null() {
        return 0;
    }
    let _ = Box::from_raw(evp_ctx.cast::<AesniCipherCtx>());
    0
}

/// Computes CRC32 partial update compatible with C `crc32_partial`.
///
/// # Safety
/// `data` must point to at least `len` readable bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crc32_partial(data: *const u8, len: usize, crc: u32) -> u32 {
    if len == 0 {
        return crc;
    }

    let Some(bytes) = (unsafe { slice_from_ptr(data, len) }) else {
        return crc;
    };
    crc32_partial_impl(bytes, crc)
}

/// Computes CRC32C partial update compatible with C `crc32c_partial`.
///
/// # Safety
/// `data` must point to at least `len` readable bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crc32c_partial(data: *const u8, len: usize, crc: u32) -> u32 {
    if len == 0 {
        return crc;
    }

    let Some(bytes) = (unsafe { slice_from_ptr(data, len) }) else {
        return crc;
    };
    crc32c_partial_impl(bytes, crc)
}

/// Computes CRC32 combine result for concatenated blocks.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_crc32_combine(crc1: u32, crc2: u32, len2: i64) -> u32 {
    crc_combine_u32(crc1, crc2, len2, CRC32_REFLECTED_POLY)
}

/// Computes CRC32C combine result for concatenated blocks.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_crc32c_combine(crc1: u32, crc2: u32, len2: i64) -> u32 {
    crc_combine_u32(crc1, crc2, len2, CRC32C_REFLECTED_POLY)
}

/// Computes CRC64 partial update.
///
/// # Safety
/// `data` must point to at least `len` readable bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crc64_partial(data: *const u8, len: usize, crc: u64) -> u64 {
    if len == 0 {
        return crc;
    }

    let Some(bytes) = (unsafe { slice_from_ptr(data, len) }) else {
        return crc;
    };
    crc64_partial_impl(bytes, crc)
}

/// Computes CRC64 combine result for concatenated blocks.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_crc64_combine(crc1: u64, crc2: u64, len2: i64) -> u64 {
    crc_combine_u64(crc1, crc2, len2, CRC64_REFLECTED_POLY)
}

/// Feeds a single byte into reflected CRC64 state.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_crc64_feed_byte(crc: u64, b: u8) -> u64 {
    crc64_feed_byte_impl(crc, b)
}

/// Computes GF32 powers table used by combine helpers.
///
/// # Safety
/// `powers` must point to at least `size` writable `u32` entries.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_gf32_compute_powers_generic(
    powers: *mut u32,
    size: usize,
    poly: u32,
) {
    if size == 0 {
        return;
    }
    let Some(table) = (unsafe { mut_slice_from_ptr(powers, size) }) else {
        return;
    };
    gf32_compute_powers_generic_impl(table, size, poly);
}

/// Computes GF32 CLMUL-style powers table.
///
/// # Safety
/// `powers` must point to at least 252 writable `u32` entries.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_gf32_compute_powers_clmul(powers: *mut u32, poly: u32) {
    let Some(table) = (unsafe { mut_slice_from_ptr(powers, GF32_CLMUL_POWERS_LEN) }) else {
        return;
    };
    gf32_compute_powers_clmul_impl(table, poly);
}

/// Applies GF32 combine using a precomputed powers table.
///
/// # Safety
/// `powers` must point to at least 2144 readable `u32` entries.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_gf32_combine_generic(
    powers: *const u32,
    crc1: u32,
    len2: i64,
) -> u32 {
    if len2 <= 0 {
        return crc1;
    }
    let Some(table) = (unsafe { slice_from_ptr(powers, GF32_GENERIC_POWERS_MAX_LEN) }) else {
        return crc1;
    };
    gf32_combine_generic_impl(table, crc1, len2)
}

/// Applies GF32 combine using a CLMUL powers table.
///
/// # Safety
/// `powers` must point to at least 252 readable `u32` entries.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_gf32_combine_clmul(
    powers: *const u32,
    crc1: u32,
    len2: i64,
) -> u64 {
    if len2 <= 0 {
        return u64::from(crc1);
    }
    let Some(table) = (unsafe { slice_from_ptr(powers, GF32_CLMUL_POWERS_LEN) }) else {
        return u64::from(crc1);
    };
    gf32_combine_clmul_impl(table, crc1, len2)
}

/// Finds a candidate corrupted bit index by CRC32 syndrome.
#[no_mangle]
pub extern "C" fn mtproxy_ffi_crc32_find_corrupted_bit(size: i32, d: u32) -> i32 {
    crc32_find_corrupted_bit_impl(size, d)
}

/// Repairs one bit in place for the provided block.
///
/// # Safety
/// `input` must point to at least `len` writable bytes when `len > 0`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crc32_repair_bit(input: *mut u8, len: usize, k: i32) -> i32 {
    if input.is_null() {
        return -3;
    }
    let Some(bytes) = (unsafe { mut_slice_from_ptr(input, len) }) else {
        return -3;
    };
    crc32_repair_bit_impl(bytes, k)
}

/// Performs CRC32 check and single-bit repair attempt.
///
/// # Safety
/// `input` must point to at least `len` writable bytes when `len > 0`.
/// `input_crc32` must be a valid writable pointer.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_crc32_check_and_repair(
    input: *mut u8,
    len: usize,
    input_crc32: *mut u32,
) -> i32 {
    if input.is_null() || input_crc32.is_null() {
        return -1;
    }
    let Some(bytes) = (unsafe { mut_slice_from_ptr(input, len) }) else {
        return -1;
    };
    let Some(crc_ref) = (unsafe { mut_ref_from_ptr(input_crc32) }) else {
        return -1;
    };
    crc32_check_and_repair_impl(bytes, crc_ref)
}

/// Initializes process id fields equivalent to `init_common_PID`.
///
/// # Safety
/// `pid` must be a valid pointer to writable `MtproxyProcessId`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_pid_init_common(pid: *mut MtproxyProcessId) -> i32 {
    let Some(pid_ref) = (unsafe { mut_ref_from_ptr(pid) }) else {
        return -1;
    };

    if pid_ref.pid == 0 {
        let raw_pid = getpid();
        // Mirror C conversion semantics (`unsigned short` assignment): keep the
        // lower 16 bits instead of failing on systems with pid_max > 65535.
        let raw_pid_bits = u32::from_ne_bytes(raw_pid.to_ne_bytes());
        pid_ref.pid = u16::try_from(raw_pid_bits & u32::from(u16::MAX)).unwrap_or_default();
    }

    if pid_ref.utime == 0 {
        let raw_time = time(core::ptr::null_mut());
        let Ok(time32) = i32::try_from(raw_time) else {
            return -1;
        };
        pid_ref.utime = time32;
    }

    0
}

/// Initializes process id fields equivalent to `init_client_PID`.
///
/// # Safety
/// `pid` must be a valid pointer to writable `MtproxyProcessId`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_pid_init_client(pid: *mut MtproxyProcessId, ip: u32) -> i32 {
    let Some(pid_ref) = (unsafe { mut_ref_from_ptr(pid) }) else {
        return -1;
    };
    if ip != 0 && ip != PID_LOCALHOST_IP {
        pid_ref.ip = ip;
    }

    mtproxy_ffi_pid_init_common(pid)
}

/// Initializes process id fields equivalent to `init_server_PID`.
///
/// # Safety
/// `pid` must be a valid pointer to writable `MtproxyProcessId`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_pid_init_server(
    pid: *mut MtproxyProcessId,
    ip: u32,
    port: i32,
) -> i32 {
    let Some(pid_ref) = (unsafe { mut_ref_from_ptr(pid) }) else {
        return -1;
    };
    if ip != 0 && ip != PID_LOCALHOST_IP {
        pid_ref.ip = ip;
    }
    if pid_ref.port == 0 {
        let bytes = port.to_ne_bytes();
        pid_ref.port = i16::from_ne_bytes([bytes[0], bytes[1]]);
    }

    mtproxy_ffi_pid_init_common(pid)
}

/// Equivalent to C `matches_pid`.
///
/// # Safety
/// `x` and `y` must be valid pointers to readable `MtproxyProcessId`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_matches_pid(
    x: *const MtproxyProcessId,
    y: *const MtproxyProcessId,
) -> i32 {
    let Some(x_ref) = (unsafe { ref_from_ptr(x) }) else {
        return 0;
    };
    let Some(y_ref) = (unsafe { ref_from_ptr(y) }) else {
        return 0;
    };
    if x_ref == y_ref {
        return 2;
    }

    i32::from(
        (y_ref.ip == 0 || x_ref.ip == y_ref.ip)
            && (y_ref.port == 0 || x_ref.port == y_ref.port)
            && (y_ref.pid == 0 || x_ref.pid == y_ref.pid)
            && (y_ref.utime == 0 || x_ref.utime == y_ref.utime),
    )
}

/// Equivalent to C `process_id_is_newer`.
///
/// # Safety
/// `a` and `b` must be valid pointers to readable `MtproxyProcessId`.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_process_id_is_newer(
    a: *const MtproxyProcessId,
    b: *const MtproxyProcessId,
) -> i32 {
    let Some(a_ref) = (unsafe { ref_from_ptr(a) }) else {
        return 0;
    };
    let Some(b_ref) = (unsafe { ref_from_ptr(b) }) else {
        return 0;
    };
    if a_ref.ip != b_ref.ip || a_ref.port != b_ref.port {
        return 0;
    }
    if a_ref.utime < b_ref.utime {
        return 0;
    }
    if a_ref.utime > b_ref.utime {
        return 1;
    }

    let delta = (i32::from(a_ref.pid) - i32::from(b_ref.pid)) & 0x7fff;
    i32::from(delta != 0 && delta <= 0x3fff)
}

/// Fills CPUID fields equivalent to C `kdb_cpuid`.
///
/// # Safety
/// `out` must be a valid pointer to writable `MtproxyCpuid`.
#[no_mangle]
#[allow(clippy::needless_return)]
pub unsafe extern "C" fn mtproxy_ffi_cpuid_fill(out: *mut MtproxyCpuid) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(out) }) else {
        return -1;
    };

    #[cfg(target_arch = "x86_64")]
    {
        let regs = core::arch::x86_64::__cpuid(1);
        out_ref.magic = CPUID_MAGIC;
        out_ref.ebx = u32_bits_to_i32(regs.ebx);
        out_ref.ecx = u32_bits_to_i32(regs.ecx);
        out_ref.edx = u32_bits_to_i32(regs.edx);
        return 0;
    }

    #[cfg(target_arch = "x86")]
    {
        let regs = core::arch::x86::__cpuid(1);
        out_ref.magic = CPUID_MAGIC;
        out_ref.ebx = u32_bits_to_i32(regs.ebx);
        out_ref.ecx = u32_bits_to_i32(regs.ecx);
        out_ref.edx = u32_bits_to_i32(regs.edx);
        return 0;
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        let _ = out_ref;
        -2
    }
}

/// Computes MD5 digest.
///
/// # Safety
/// `output` must point to at least 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_md5(input: *const u8, len: usize, output: *mut u8) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(output.cast::<[u8; DIGEST_MD5_LEN]>()) }) else {
        return -1;
    };
    let Some(input_ref) = (unsafe { slice_from_ptr(input, len) }) else {
        return -1;
    };
    if md5_digest_impl(input_ref, out_ref) {
        0
    } else {
        -1
    }
}

/// Computes MD5 digest and writes lowercase hex bytes (no `\\0` terminator).
///
/// # Safety
/// `output` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_md5_hex(
    input: *const u8,
    len: usize,
    output: *mut c_char,
) -> i32 {
    let mut digest = [0u8; DIGEST_MD5_LEN];
    if mtproxy_ffi_md5(input, len, digest.as_mut_ptr()) < 0 {
        return -1;
    }
    let Some(out) = (unsafe { mut_slice_from_ptr(output.cast::<u8>(), DIGEST_MD5_LEN * 2) }) else {
        return -1;
    };
    for (i, &byte) in digest.iter().enumerate() {
        out[i * 2] = HEX_LOWER[usize::from(byte >> 4)];
        out[i * 2 + 1] = HEX_LOWER[usize::from(byte & 0x0f)];
    }
    0
}

/// Computes HMAC-MD5.
///
/// # Safety
/// `output` must point to at least 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_md5_hmac(
    key: *const u8,
    key_len: usize,
    input: *const u8,
    len: usize,
    output: *mut u8,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(output.cast::<[u8; DIGEST_MD5_LEN]>()) }) else {
        return -1;
    };
    let Some(key_ref) = (unsafe { slice_from_ptr(key, key_len) }) else {
        return -1;
    };
    let Some(input_ref) = (unsafe { slice_from_ptr(input, len) }) else {
        return -1;
    };
    if c_int::try_from(key_len).is_err() {
        return -1;
    }
    let Ok(mut mac) = HmacMd5::new_from_slice(key_ref) else {
        return -1;
    };
    mac.update(input_ref);
    out_ref.copy_from_slice(&mac.finalize().into_bytes());
    0
}

/// Computes SHA1 digest.
///
/// # Safety
/// `output` must point to at least 20 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sha1(input: *const u8, len: usize, output: *mut u8) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(output.cast::<[u8; DIGEST_SHA1_LEN]>()) })
    else {
        return -1;
    };
    let Some(input_ref) = (unsafe { slice_from_ptr(input, len) }) else {
        return -1;
    };
    if sha1_digest_impl(input_ref, out_ref) {
        0
    } else {
        -1
    }
}

/// Computes SHA1 digest for concatenated chunks.
///
/// # Safety
/// `output` must point to at least 20 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sha1_two_chunks(
    input1: *const u8,
    len1: usize,
    input2: *const u8,
    len2: usize,
    output: *mut u8,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(output.cast::<[u8; DIGEST_SHA1_LEN]>()) })
    else {
        return -1;
    };
    let Some(first) = (unsafe { slice_from_ptr(input1, len1) }) else {
        return -1;
    };
    let Some(second) = (unsafe { slice_from_ptr(input2, len2) }) else {
        return -1;
    };

    let mut hasher = Sha1::new();
    hasher.update(first);
    hasher.update(second);
    out_ref.copy_from_slice(&hasher.finalize());
    0
}

/// Computes SHA256 digest.
///
/// # Safety
/// `output` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sha256(input: *const u8, len: usize, output: *mut u8) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(output.cast::<[u8; DIGEST_SHA256_LEN]>()) })
    else {
        return -1;
    };
    let Some(input_ref) = (unsafe { slice_from_ptr(input, len) }) else {
        return -1;
    };
    if sha256_digest_impl(input_ref, out_ref) {
        0
    } else {
        -1
    }
}

/// Computes SHA256 digest for concatenated chunks.
///
/// # Safety
/// `output` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sha256_two_chunks(
    input1: *const u8,
    len1: usize,
    input2: *const u8,
    len2: usize,
    output: *mut u8,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(output.cast::<[u8; DIGEST_SHA256_LEN]>()) })
    else {
        return -1;
    };
    let Some(first) = (unsafe { slice_from_ptr(input1, len1) }) else {
        return -1;
    };
    let Some(second) = (unsafe { slice_from_ptr(input2, len2) }) else {
        return -1;
    };

    let mut hasher = Sha256::new();
    hasher.update(first);
    hasher.update(second);
    out_ref.copy_from_slice(&hasher.finalize());
    0
}

/// Computes HMAC-SHA256.
///
/// # Safety
/// `output` must point to at least 32 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn mtproxy_ffi_sha256_hmac(
    key: *const u8,
    key_len: usize,
    input: *const u8,
    len: usize,
    output: *mut u8,
) -> i32 {
    let Some(out_ref) = (unsafe { mut_ref_from_ptr(output.cast::<[u8; DIGEST_SHA256_LEN]>()) })
    else {
        return -1;
    };
    let Some(key_ref) = (unsafe { slice_from_ptr(key, key_len) }) else {
        return -1;
    };
    let Some(input_ref) = (unsafe { slice_from_ptr(input, len) }) else {
        return -1;
    };
    if c_int::try_from(key_len).is_err() {
        return -1;
    }
    let Ok(mut mac) = HmacSha256::new_from_slice(key_ref) else {
        return -1;
    };
    mac.update(input_ref);
    out_ref.copy_from_slice(&mac.finalize().into_bytes());
    0
}
