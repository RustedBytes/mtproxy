pub(super) use crate::ffi_util::{
    mut_ref_from_ptr, mut_slice_from_ptr, ref_from_ptr, slice_from_ptr,
};
use crate::*;

pub(super) const AES_CREATE_KEYS_MAX_STR_LEN: usize =
    16 + 16 + 4 + 4 + 2 + 6 + 4 + 2 + MAX_PWD_LEN + 16 + 16 + 4 + (16 * 2) + 256;
pub(super) const DH_GOOD_PREFIX_BYTES: usize = 8;
pub(super) const DH_MOD_MIN_LEN: usize = 241;
pub(super) const DH_MOD_MAX_LEN: usize = 256;
pub(super) const AESNI_CIPHER_AES_256_CBC: i32 = 1;
pub(crate) const AESNI_CIPHER_AES_256_CTR: i32 = 2;
pub(super) const AES_ROLE_XOR_MASK: [u8; 6] = [
    b'C' ^ b'S',
    b'L' ^ b'E',
    b'I' ^ b'R',
    b'E' ^ b'V',
    b'N' ^ b'E',
    b'T' ^ b'R',
];
pub(super) const TLS_X25519_MOD_HEX: &[u8] =
    b"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed\0";
pub(super) const TLS_X25519_POW_HEX: &[u8] =
    b"3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff6\0";
pub(super) const RPC_DH_PRIME_BIN: [u8; DH_KEY_BYTES] = [
    0x89, 0x52, 0x13, 0x1b, 0x1e, 0x3a, 0x69, 0xba, 0x5f, 0x85, 0xcf, 0x8b, 0xd2, 0x66, 0xc1, 0x2b,
    0x13, 0x83, 0x16, 0x13, 0xbd, 0x2a, 0x4e, 0xf8, 0x35, 0xa4, 0xd5, 0x3f, 0x9d, 0xbb, 0x42, 0x48,
    0x2d, 0xbd, 0x46, 0x2b, 0x31, 0xd8, 0x6c, 0x81, 0x6c, 0x59, 0x77, 0x52, 0x0f, 0x11, 0x70, 0x73,
    0x9e, 0xd2, 0xdd, 0xd6, 0xd8, 0x1b, 0x9e, 0xb6, 0x5f, 0xaa, 0xac, 0x14, 0x87, 0x53, 0xc9, 0xe4,
    0xf0, 0x72, 0xdc, 0x11, 0xa4, 0x92, 0x73, 0x06, 0x83, 0xfa, 0x00, 0x67, 0x82, 0x6b, 0x18, 0xc5,
    0x1d, 0x7e, 0xcb, 0xa5, 0x2b, 0x82, 0x60, 0x75, 0xc0, 0xb9, 0x55, 0xe5, 0xac, 0xaf, 0xdd, 0x74,
    0xc3, 0x79, 0x5f, 0xd9, 0x52, 0x0b, 0x48, 0x0f, 0x3b, 0xe3, 0xba, 0x06, 0x65, 0x33, 0x8a, 0x49,
    0x8c, 0xa5, 0xda, 0xf1, 0x01, 0x76, 0x05, 0x09, 0xa3, 0x8c, 0x49, 0xe3, 0x00, 0x74, 0x64, 0x08,
    0x77, 0x4b, 0xb3, 0xed, 0x26, 0x18, 0x1a, 0x64, 0x55, 0x76, 0x6a, 0xe9, 0x49, 0x7b, 0xb9, 0xc3,
    0xa3, 0xad, 0x5c, 0xba, 0xf7, 0x6b, 0x73, 0x84, 0x5f, 0xbb, 0x96, 0xbb, 0x6d, 0x0f, 0x68, 0x4f,
    0x95, 0xd2, 0xd3, 0x9c, 0xcb, 0xb4, 0xa9, 0x04, 0xfa, 0xb1, 0xde, 0x43, 0x49, 0xce, 0x1c, 0x20,
    0x87, 0xb6, 0xc9, 0x51, 0xed, 0x99, 0xf9, 0x52, 0xe3, 0x4f, 0xd1, 0xa3, 0xfd, 0x14, 0x83, 0x35,
    0x75, 0x41, 0x47, 0x29, 0xa3, 0x8b, 0xe8, 0x68, 0xa4, 0xf9, 0xec, 0x62, 0x3a, 0x5d, 0x24, 0x62,
    0x1a, 0xba, 0x01, 0xb2, 0x55, 0xc7, 0xe8, 0x38, 0x5d, 0x16, 0xac, 0x93, 0xb0, 0x2d, 0x2a, 0x54,
    0x0a, 0x76, 0x42, 0x98, 0x2d, 0x22, 0xad, 0xa3, 0xcc, 0xde, 0x5c, 0x8d, 0x26, 0x6f, 0xaa, 0x25,
    0xdd, 0x2d, 0xe9, 0xf6, 0xd4, 0x91, 0x04, 0x16, 0x2f, 0x68, 0x5c, 0x45, 0xfe, 0x34, 0xdd, 0xab,
];

pub(super) type Aes256Ctr = Ctr128BE<Aes256>;
pub(super) type HmacMd5 = Hmac<Md5>;
pub(super) type HmacSha256 = Hmac<Sha256>;

#[repr(C, align(16))]
pub(super) struct MtproxyAesCryptoCtx {
    pub(super) read_aeskey: *mut c_void,
    pub(super) write_aeskey: *mut c_void,
}

pub(super) enum AesniCipherCtx {
    Aes256CbcEncrypt(cbc::Encryptor<Aes256>),
    Aes256CbcDecrypt(cbc::Decryptor<Aes256>),
    Aes256Ctr(Aes256Ctr),
}

impl AesniCipherCtx {
    pub(super) fn crypt_in_place(&mut self, output: &mut [u8]) -> bool {
        if output.is_empty() {
            return true;
        }
        match self {
            Self::Aes256CbcEncrypt(cipher) => {
                if (output.len() & 15) != 0 {
                    return false;
                }
                for chunk in output.chunks_exact_mut(16) {
                    let block = cbc::cipher::Block::<Aes256>::from_mut_slice(chunk);
                    cipher.encrypt_block_mut(block);
                }
                true
            }
            Self::Aes256CbcDecrypt(cipher) => {
                if (output.len() & 15) != 0 {
                    return false;
                }
                for chunk in output.chunks_exact_mut(16) {
                    let block = cbc::cipher::Block::<Aes256>::from_mut_slice(chunk);
                    cipher.decrypt_block_mut(block);
                }
                true
            }
            Self::Aes256Ctr(cipher) => {
                cipher.apply_keystream(output);
                true
            }
        }
    }
}

pub(super) static AES_ALLOCATED_CRYPTO: AtomicI64 = AtomicI64::new(0);
pub(super) static AES_ALLOCATED_CRYPTO_TEMP: AtomicI64 = AtomicI64::new(0);
pub(super) static DH_PARAMS_SELECT_INIT: AtomicI64 = AtomicI64::new(0);
pub(super) static DH_TOT_ROUNDS_0: AtomicI64 = AtomicI64::new(0);
pub(super) static DH_TOT_ROUNDS_1: AtomicI64 = AtomicI64::new(0);
pub(super) static DH_TOT_ROUNDS_2: AtomicI64 = AtomicI64::new(0);
pub(super) static AES_NONCE_RAND_BUF: Mutex<[u8; 64]> = Mutex::new([0u8; 64]);

pub(super) fn md5_digest_impl(input: &[u8], out: &mut [u8; DIGEST_MD5_LEN]) -> bool {
    let mut hasher = Md5::new();
    hasher.update(input);
    out.copy_from_slice(&hasher.finalize());
    true
}

pub(super) fn sha1_digest_impl(input: &[u8], out: &mut [u8; DIGEST_SHA1_LEN]) -> bool {
    let mut hasher = Sha1::new();
    hasher.update(input);
    out.copy_from_slice(&hasher.finalize());
    true
}

pub(super) fn sha256_digest_impl(input: &[u8], out: &mut [u8; DIGEST_SHA256_LEN]) -> bool {
    let mut hasher = Sha256::new();
    hasher.update(input);
    out.copy_from_slice(&hasher.finalize());
    true
}

pub(super) fn i64_to_i32_saturating(value: i64) -> i32 {
    if value > i64::from(i32::MAX) {
        i32::MAX
    } else if value < i64::from(i32::MIN) {
        i32::MIN
    } else {
        value as i32
    }
}

pub(super) fn atomic_dec_saturating(counter: &AtomicI64) {
    let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
        Some(if value > 0 { value - 1 } else { 0 })
    });
}

#[inline]
pub(super) fn rdtsc_now() -> i64 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: `_rdtsc` has no memory safety preconditions and is available on x86_64.
        unsafe { core::arch::x86_64::_rdtsc() as i64 }
    }
    #[cfg(all(not(target_arch = "x86_64"), target_arch = "x86"))]
    {
        // SAFETY: `_rdtsc` has no memory safety preconditions and is available on x86.
        unsafe { core::arch::x86::_rdtsc() as i64 }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86")))]
    {
        let mut ts = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid writable `Timespec`.
        if unsafe { clock_gettime(CLOCK_MONOTONIC_ID, &raw mut ts) } < 0 {
            0
        } else {
            (ts.tv_sec as i64)
                .saturating_mul(1_000_000_000_i64)
                .saturating_add(ts.tv_nsec as i64)
        }
    }
}

pub(super) fn refresh_aes_nonce_seed(rand_buf: &mut [u8; 64]) -> bool {
    let mut seeded = false;
    if let Ok(mut urandom) = fs::File::open("/dev/urandom") {
        if urandom.read_exact(&mut rand_buf[..16]).is_ok() {
            seeded = true;
        }
    }
    if !seeded && !crypto_rand_fill(&mut rand_buf[..16]) {
        return false;
    }

    let seed_len = core::mem::size_of::<c_long>();
    let mut seed_bytes = [0u8; core::mem::size_of::<c_long>()];
    seed_bytes.copy_from_slice(&rand_buf[..seed_len]);
    let mut seed = c_long::from_ne_bytes(seed_bytes);
    // SAFETY: libc PRNG functions do not require additional pointer invariants.
    seed ^= unsafe { lrand48() };
    rand_buf[..seed_len].copy_from_slice(&seed.to_ne_bytes());
    // SAFETY: libc PRNG functions do not require additional pointer invariants.
    unsafe { srand48(seed) };
    true
}

pub(super) fn write_md5_hex(input: &[u8], out: &mut [u8; 33]) -> bool {
    let mut digest = [0u8; DIGEST_MD5_LEN];
    if !md5_digest_impl(input, &mut digest) {
        return false;
    }
    for (idx, byte) in digest.iter().copied().enumerate() {
        out[idx * 2] = HEX_LOWER[usize::from(byte >> 4)];
        out[idx * 2 + 1] = HEX_LOWER[usize::from(byte & 0x0f)];
    }
    out[32] = 0;
    true
}

pub(super) fn crypto_dh_is_good_rpc_dh_bin_impl(data: &[u8], prime_prefix: &[u8]) -> i32 {
    if data.len() < 8 || prime_prefix.len() < 8 {
        return -1;
    }
    if data[..8].iter().all(|b| *b == 0) {
        return 0;
    }
    for (&data_byte, &prefix_byte) in data.iter().zip(prime_prefix.iter()).take(8) {
        if data_byte > prefix_byte {
            return 0;
        }
        if data_byte < prefix_byte {
            return 1;
        }
    }
    0
}

#[allow(clippy::too_many_arguments)]
pub(super) fn crypto_aes_create_keys_impl(
    out: &mut MtproxyAesKeyData,
    am_client: i32,
    nonce_server: &[u8; 16],
    nonce_client: &[u8; 16],
    client_timestamp: i32,
    server_ip: u32,
    server_port: u16,
    server_ipv6: &[u8; 16],
    client_ip: u32,
    client_port: u16,
    client_ipv6: &[u8; 16],
    secret: &[u8],
    temp_key: &[u8],
) -> i32 {
    if secret.len() < MIN_PWD_LEN || secret.len() > MAX_PWD_LEN {
        return -1;
    }
    if server_ip == 0 {
        if client_ip != 0 {
            return -1;
        }
    } else if client_ip == 0 {
        return -1;
    }

    let mut material = [0u8; AES_CREATE_KEYS_MAX_STR_LEN];
    material[..16].copy_from_slice(nonce_server);
    material[16..32].copy_from_slice(nonce_client);
    material[32..36].copy_from_slice(&client_timestamp.to_ne_bytes());
    material[36..40].copy_from_slice(&server_ip.to_ne_bytes());
    material[40..42].copy_from_slice(&client_port.to_ne_bytes());
    material[42..48].copy_from_slice(if am_client != 0 { b"CLIENT" } else { b"SERVER" });
    material[48..52].copy_from_slice(&client_ip.to_ne_bytes());
    material[52..54].copy_from_slice(&server_port.to_ne_bytes());

    let secret_len = secret.len();
    material[54..54 + secret_len].copy_from_slice(secret);
    material[54 + secret_len..70 + secret_len].copy_from_slice(nonce_server);
    let mut str_len = 70 + secret_len;

    if server_ip == 0 {
        material[str_len..str_len + 16].copy_from_slice(client_ipv6);
        material[str_len + 16..str_len + 32].copy_from_slice(server_ipv6);
        str_len += 32;
    }

    material[str_len..str_len + 16].copy_from_slice(nonce_client);
    str_len += 16;

    let first_len = str_len.min(temp_key.len());
    for (dst, src) in material[..first_len]
        .iter_mut()
        .zip(temp_key.iter().take(first_len))
    {
        *dst ^= *src;
    }
    if temp_key.len() > first_len {
        material[first_len..temp_key.len()].copy_from_slice(&temp_key[first_len..]);
    }
    if str_len < temp_key.len() {
        str_len = temp_key.len();
    }

    let mut md5_out = [0u8; DIGEST_MD5_LEN];
    let mut sha1_out = [0u8; DIGEST_SHA1_LEN];
    if !md5_digest_impl(&material[1..str_len], &mut md5_out) {
        return -1;
    }
    out.write_key[..DIGEST_MD5_LEN].copy_from_slice(&md5_out);
    if !sha1_digest_impl(&material[..str_len], &mut sha1_out) {
        return -1;
    }
    out.write_key[12..32].copy_from_slice(&sha1_out);
    if !md5_digest_impl(&material[2..str_len], &mut md5_out) {
        return -1;
    }
    out.write_iv.copy_from_slice(&md5_out);

    for (i, mask) in AES_ROLE_XOR_MASK.iter().copied().enumerate() {
        material[42 + i] ^= mask;
    }

    if !md5_digest_impl(&material[1..str_len], &mut md5_out) {
        return -1;
    }
    out.read_key[..DIGEST_MD5_LEN].copy_from_slice(&md5_out);
    if !sha1_digest_impl(&material[..str_len], &mut sha1_out) {
        return -1;
    }
    out.read_key[12..32].copy_from_slice(&sha1_out);
    if !md5_digest_impl(&material[2..str_len], &mut md5_out) {
        return -1;
    }
    out.read_iv.copy_from_slice(&md5_out);

    material[..str_len].fill(0);
    1
}

#[derive(Clone)]
pub(super) struct BnOwned(BigUint);

impl BnOwned {
    fn from_bin(bytes: &[u8]) -> Self {
        Self(BigUint::from_bytes_be(bytes))
    }

    fn from_hex_nul(hex_nul: &[u8]) -> Option<Self> {
        let Some((&0, hex_bytes)) = hex_nul.split_last() else {
            return None;
        };
        let hex = core::str::from_utf8(hex_bytes).ok()?;
        let value = BigUint::parse_bytes(hex.as_bytes(), 16)?;
        Some(Self(value))
    }

    fn as_biguint(&self) -> &BigUint {
        &self.0
    }
}

pub(super) fn bn_num_bytes(value: &BnOwned) -> Option<usize> {
    let bits = value.as_biguint().bits();
    let bytes = bits.saturating_add(7) / 8;
    usize::try_from(bytes).ok()
}

pub(super) fn bn_write_be_padded(value: &BnOwned, out: &mut [u8]) -> bool {
    let bytes = value.as_biguint().to_bytes_be();
    if bytes.len() > out.len() {
        return false;
    }
    let start = out.len() - bytes.len();
    out[..start].fill(0);
    out[start..].copy_from_slice(&bytes);
    true
}

pub(super) fn mod_add(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    (a + b) % modulus
}

pub(super) fn mod_sub(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    if a >= b {
        (a - b) % modulus
    } else {
        let diff = (b - a) % modulus;
        if diff.is_zero() {
            BigUint::zero()
        } else {
            modulus - diff
        }
    }
}

pub(super) fn mod_mul(a: &BigUint, b: &BigUint, modulus: &BigUint) -> BigUint {
    (a * b) % modulus
}

pub(super) fn mod_inverse(value: &BigUint, modulus: &BigUint) -> Option<BigUint> {
    if modulus.is_zero() {
        return None;
    }
    let modulus_i = BigInt::from_biguint(Sign::Plus, modulus.clone());
    let mut t = BigInt::zero();
    let mut new_t = BigInt::one();
    let mut r = modulus_i.clone();
    let mut new_r = BigInt::from_biguint(Sign::Plus, value.clone() % modulus);

    while !new_r.is_zero() {
        let quotient = &r / &new_r;
        let next_t = &t - (&quotient * &new_t);
        let next_r = &r - (&quotient * &new_r);
        t = new_t;
        new_t = next_t;
        r = new_r;
        new_r = next_r;
    }

    if r != BigInt::one() {
        return None;
    }

    let mut normalized = t % &modulus_i;
    if normalized.sign() == Sign::Minus {
        normalized += &modulus_i;
    }
    normalized.to_biguint()
}

pub(super) fn crypto_dh_modexp(
    base_bytes: Option<&[u8; DH_KEY_BYTES]>,
    exponent: &[u8; DH_KEY_BYTES],
    out: &mut [u8; DH_KEY_BYTES],
) -> bool {
    let modulus = BnOwned::from_bin(&RPC_DH_PRIME_BIN);
    let exponent_bn = BigUint::from_bytes_be(exponent);
    let base_bn = if let Some(bytes) = base_bytes {
        BigUint::from_bytes_be(bytes)
    } else {
        BigUint::from(3u8)
    };
    let out_bn = BnOwned(base_bn.modpow(&exponent_bn, modulus.as_biguint()));
    let Some(out_len) = bn_num_bytes(&out_bn) else {
        return false;
    };
    if !(DH_MOD_MIN_LEN..=DH_MOD_MAX_LEN).contains(&out_len) {
        return false;
    }
    bn_write_be_padded(&out_bn, out)
}

pub(super) fn crypto_rand_fill(out: &mut [u8]) -> bool {
    if out.is_empty() {
        return true;
    }
    rustls_default_provider().secure_random.fill(out).is_ok()
}

pub(super) fn crypto_dh_first_round_impl(
    g_a: &mut [u8; DH_KEY_BYTES],
    a_out: &mut [u8; DH_KEY_BYTES],
) -> i32 {
    loop {
        if !crypto_rand_fill(a_out) {
            return -1;
        }
        if !crypto_dh_modexp(None, a_out, g_a) {
            return -1;
        }
        let verdict =
            crypto_dh_is_good_rpc_dh_bin_impl(g_a, &RPC_DH_PRIME_BIN[..DH_GOOD_PREFIX_BYTES]);
        if verdict == 1 {
            return 1;
        }
        if verdict < 0 {
            return -1;
        }
    }
}

pub(super) fn tls_get_y2(x: &BnOwned, modulus: &BnOwned) -> BnOwned {
    let p = modulus.as_biguint();
    let x_ref = x.as_biguint();
    let mut y = mod_add(x_ref, &BigUint::from(486_662_u32), p);
    y = mod_mul(&y, x_ref, p);
    y = mod_add(&y, &BigUint::one(), p);
    y = mod_mul(&y, x_ref, p);
    BnOwned(y)
}

pub(super) fn tls_get_double_x(x: &BnOwned, modulus: &BnOwned) -> Option<BnOwned> {
    let p = modulus.as_biguint();
    let y2 = tls_get_y2(x, modulus);
    let denominator = mod_mul(y2.as_biguint(), &BigUint::from(4u8), p);
    let x_sq = mod_mul(x.as_biguint(), x.as_biguint(), p);
    let x_sq_minus_one = mod_sub(&x_sq, &BigUint::one(), p);
    let numerator = mod_mul(&x_sq_minus_one, &x_sq_minus_one, p);
    let denominator_inv = mod_inverse(&denominator, p)?;
    Some(BnOwned(mod_mul(&numerator, &denominator_inv, p)))
}

pub(super) fn crypto_tls_generate_public_key_impl(
    out: &mut [u8; TLS_REQUEST_PUBLIC_KEY_BYTES],
) -> i32 {
    let Some(modulus) = BnOwned::from_hex_nul(TLS_X25519_MOD_HEX) else {
        return -1;
    };
    let Some(pow) = BnOwned::from_hex_nul(TLS_X25519_POW_HEX) else {
        return -1;
    };
    let mut x;
    let p = modulus.as_biguint();
    let one = BigUint::one();

    loop {
        if !crypto_rand_fill(out) {
            return -1;
        }
        out[31] &= 127;
        let mut candidate = BnOwned(BigUint::from_bytes_be(out));
        candidate = BnOwned(mod_mul(candidate.as_biguint(), candidate.as_biguint(), p));
        let y = tls_get_y2(&candidate, &modulus);
        let r = y.as_biguint().modpow(pow.as_biguint(), p);
        if r == one {
            x = candidate;
            break;
        }
    }

    for _ in 0..3 {
        let Some(next_x) = tls_get_double_x(&x, &modulus) else {
            return -1;
        };
        x = next_x;
    }

    let Some(num_size) = bn_num_bytes(&x) else {
        return -1;
    };
    if num_size > TLS_REQUEST_PUBLIC_KEY_BYTES {
        return -1;
    }
    out[..TLS_REQUEST_PUBLIC_KEY_BYTES - num_size].fill(0);
    let bytes = x.as_biguint().to_bytes_be();
    out[TLS_REQUEST_PUBLIC_KEY_BYTES - num_size..].copy_from_slice(&bytes);
    out.reverse();
    0
}

pub(crate) const CRC32_REFLECTED_POLY: u32 = 0xedb8_8320;
pub(super) const CRC32C_REFLECTED_POLY: u32 = 0x82f6_3b78;
pub(super) const CRC64_REFLECTED_POLY: u64 = 0xc96c_5795_d787_0f42;
pub(crate) const GF32_CLMUL_POWERS_LEN: usize = 252;
pub(super) const GF32_GENERIC_POWERS_MAX_LEN: usize = 32 * 67;

#[inline]
pub(super) fn crc32_partial_poly(data: &[u8], mut crc: u32, poly: u32) -> u32 {
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            if (crc & 1) != 0 {
                crc = (crc >> 1) ^ poly;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

pub(super) fn crc32_partial_impl(data: &[u8], crc: u32) -> u32 {
    crc32_partial_poly(data, crc, CRC32_REFLECTED_POLY)
}

pub(super) fn crc32c_partial_impl(data: &[u8], crc: u32) -> u32 {
    crc32_partial_poly(data, crc, CRC32C_REFLECTED_POLY)
}

#[inline]
pub(super) fn crc64_feed_byte_impl(mut crc: u64, b: u8) -> u64 {
    crc ^= u64::from(b);
    for _ in 0..8 {
        if (crc & 1) != 0 {
            crc = (crc >> 1) ^ CRC64_REFLECTED_POLY;
        } else {
            crc >>= 1;
        }
    }
    crc
}

pub(super) fn crc64_partial_impl(data: &[u8], mut crc: u64) -> u64 {
    for &byte in data {
        crc = crc64_feed_byte_impl(crc, byte);
    }
    crc
}

pub(super) fn gf2_matrix_times_u32(matrix: &[u32; 32], mut vector: u32) -> u32 {
    let mut sum = 0u32;
    let mut n = 0usize;
    while vector != 0 {
        if (vector & 1) != 0 {
            sum ^= matrix[n];
        }
        vector >>= 1;
        n += 1;
    }
    sum
}

pub(super) fn gf2_matrix_square_u32(square: &mut [u32; 32], matrix: &[u32; 32]) {
    for n in 0..32 {
        square[n] = gf2_matrix_times_u32(matrix, matrix[n]);
    }
}

pub(super) fn crc_combine_u32(mut crc1: u32, crc2: u32, len2: i64, poly: u32) -> u32 {
    if len2 <= 0 {
        return crc1;
    }

    let mut odd = [0u32; 32];
    let mut even = [0u32; 32];

    odd[0] = poly;
    let mut row = 1u32;
    for slot in odd.iter_mut().skip(1) {
        *slot = row;
        row <<= 1;
    }

    gf2_matrix_square_u32(&mut even, &odd);
    gf2_matrix_square_u32(&mut odd, &even);

    let mut n = len2 as u64;
    loop {
        gf2_matrix_square_u32(&mut even, &odd);
        if (n & 1) != 0 {
            crc1 = gf2_matrix_times_u32(&even, crc1);
        }
        n >>= 1;
        if n == 0 {
            break;
        }

        gf2_matrix_square_u32(&mut odd, &even);
        if (n & 1) != 0 {
            crc1 = gf2_matrix_times_u32(&odd, crc1);
        }
        n >>= 1;
        if n == 0 {
            break;
        }
    }

    crc1 ^ crc2
}

pub(super) fn gf2_matrix_times_u64(matrix: &[u64; 64], mut vector: u64) -> u64 {
    let mut sum = 0u64;
    let mut n = 0usize;
    while vector != 0 {
        if (vector & 1) != 0 {
            sum ^= matrix[n];
        }
        vector >>= 1;
        n += 1;
    }
    sum
}

pub(super) fn gf2_matrix_square_u64(square: &mut [u64; 64], matrix: &[u64; 64]) {
    for n in 0..64 {
        square[n] = gf2_matrix_times_u64(matrix, matrix[n]);
    }
}

pub(super) fn crc_combine_u64(mut crc1: u64, crc2: u64, len2: i64, poly: u64) -> u64 {
    if len2 <= 0 {
        return crc1;
    }

    let mut odd = [0u64; 64];
    let mut even = [0u64; 64];

    odd[0] = poly;
    let mut row = 1u64;
    for slot in odd.iter_mut().skip(1) {
        *slot = row;
        row <<= 1;
    }

    gf2_matrix_square_u64(&mut even, &odd);
    gf2_matrix_square_u64(&mut odd, &even);

    let mut n = len2 as u64;
    loop {
        gf2_matrix_square_u64(&mut even, &odd);
        if (n & 1) != 0 {
            crc1 = gf2_matrix_times_u64(&even, crc1);
        }
        n >>= 1;
        if n == 0 {
            break;
        }

        gf2_matrix_square_u64(&mut odd, &even);
        if (n & 1) != 0 {
            crc1 = gf2_matrix_times_u64(&odd, crc1);
        }
        n >>= 1;
        if n == 0 {
            break;
        }
    }

    crc1 ^ crc2
}

#[inline]
pub(super) fn gf32_mulx(a: u32, poly: u32) -> u32 {
    let mut r = a >> 1;
    if (a & 1) != 0 {
        r ^= poly;
    }
    r
}

pub(super) fn gf32_mul(a: u32, mut b: u32, poly: u32) -> u32 {
    let mut x = 0u32;
    for _ in 0..32 {
        x = gf32_mulx(x, poly);
        if (b & 1) != 0 {
            x ^= a;
        }
        b >>= 1;
    }
    x
}

pub(super) fn gf32_pow(a: u32, k: i32, poly: u32) -> u32 {
    if k == 0 {
        return 0x8000_0000;
    }
    let mut x = gf32_pow(gf32_mul(a, a, poly), k >> 1, poly);
    if (k & 1) != 0 {
        x = gf32_mul(x, a, poly);
    }
    x
}

pub(super) fn gf32_matrix_times_slice(matrix: &[u32], mut vector: u32) -> u32 {
    let mut sum = 0u32;
    let mut n = 0usize;
    while vector != 0 {
        if (vector & 1) != 0 {
            if n >= matrix.len() {
                break;
            }
            sum ^= matrix[n];
        }
        vector >>= 1;
        n += 1;
    }
    sum
}

pub(super) fn gf32_compute_powers_generic_impl(powers: &mut [u32], size: usize, poly: u32) {
    let usable = core::cmp::min(size, powers.len());
    if usable < 32 {
        return;
    }

    powers[0] = poly;
    for n in 0..31 {
        powers[n + 1] = 1u32 << n;
    }

    let mut n = 1usize;
    while (n << 5) < usable {
        let src_start = (n - 1) << 5;
        let dst_start = n << 5;
        if src_start + 32 > usable || dst_start + 32 > usable {
            break;
        }

        let mut src = [0u32; 32];
        let mut dst = [0u32; 32];
        src.copy_from_slice(&powers[src_start..src_start + 32]);
        gf2_matrix_square_u32(&mut dst, &src);
        powers[dst_start..dst_start + 32].copy_from_slice(&dst);

        n += 1;
    }
}

pub(super) fn gf32_compute_powers_clmul_impl(powers: &mut [u32], poly: u32) {
    let groups = core::cmp::min(63, powers.len() / 4);
    let mut a = 1u32 << (31 - 7);
    let b = gf32_mul(poly, poly, poly);

    for idx in 0..groups {
        let base = idx * 4;
        powers[base] = 0;
        powers[base + 1] = gf32_mul(a, b, poly);
        powers[base + 2] = 0;
        powers[base + 3] = a;
        a = gf32_mulx(gf32_mul(a, a, poly), poly);
    }
}

pub(super) fn gf32_combine_generic_impl(powers: &[u32], mut crc1: u32, mut len2: i64) -> u32 {
    if len2 <= 0 {
        return crc1;
    }

    let mut offset = 64usize;
    loop {
        offset = offset.saturating_add(32);
        if (len2 & 1) != 0 {
            if offset + 32 > powers.len() {
                break;
            }
            crc1 = gf32_matrix_times_slice(&powers[offset..offset + 32], crc1);
        }
        len2 >>= 1;
        if len2 == 0 {
            break;
        }
    }
    crc1
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq,sse2")]
pub(super) unsafe fn gf32_combine_clmul_hw_x86_64(powers: *const u32, crc1: u32, len2: u64) -> u64 {
    use core::arch::x86_64::{
        __m128i, _mm_clmulepi64_si128, _mm_cvtsi32_si128, _mm_loadu_si128, _mm_slli_si128,
        _mm_unpackhi_epi64, _mm_xor_si128,
    };

    let mut d = _mm_cvtsi32_si128(crc1 as i32);
    d = _mm_slli_si128(d, 12);

    let tz = len2.trailing_zeros() as usize;
    let mut p = powers.add(4 * tz).cast::<__m128i>();
    let mut rem = len2 >> (tz + 1);

    d = _mm_clmulepi64_si128(_mm_loadu_si128(p), d, 0x11);

    while rem != 0 {
        p = p.add(1);
        if (rem & 1) != 0 {
            let e = _mm_loadu_si128(p);
            d = _mm_xor_si128(
                _mm_clmulepi64_si128(e, d, 0x11),
                _mm_clmulepi64_si128(e, d, 0x00),
            );
        }
        rem >>= 1;
    }

    let base = powers.add(12).cast::<__m128i>();
    d = _mm_xor_si128(d, _mm_clmulepi64_si128(_mm_loadu_si128(base), d, 0x01));
    d = _mm_unpackhi_epi64(d, d);

    // SAFETY: __m128i and [u64; 2] are both 128-bit POD layouts.
    let lanes: [u64; 2] = core::mem::transmute(d);
    lanes[0]
}

pub(super) fn gf32_combine_clmul_impl(powers: &[u32], crc1: u32, len2: i64) -> u64 {
    if len2 <= 0 {
        return u64::from(crc1);
    }

    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("pclmulqdq") {
            // SAFETY: CPU feature is checked at runtime and table shape matches C contract.
            return unsafe { gf32_combine_clmul_hw_x86_64(powers.as_ptr(), crc1, len2 as u64) };
        }
    }

    u64::from(gf32_combine_generic_impl(powers, crc1, len2))
}

#[allow(clippy::many_single_char_names)]
pub(super) fn crc32_find_corrupted_bit_impl(size: i32, d: u32) -> i32 {
    let size = size.saturating_add(4);
    let n = size.saturating_mul(8);
    if n <= 0 {
        return -1;
    }

    let r = ((f64::from(n)).sqrt() + 0.5) as i32;
    if r <= 0 {
        return -1;
    }

    #[derive(Clone, Copy)]
    struct FcbTableEntry {
        p: u32,
        i: i32,
    }

    let mut table = vec![FcbTableEntry { p: 0, i: 0 }; usize::try_from(r).unwrap_or(0)];
    if table.is_empty() {
        return -1;
    }
    table[0] = FcbTableEntry {
        p: 0x8000_0000,
        i: 0,
    };
    for i in 1..r {
        let prev = table[usize::try_from(i - 1).unwrap_or(0)].p;
        table[usize::try_from(i).unwrap_or(0)] = FcbTableEntry {
            p: gf32_mulx(prev, CRC32_REFLECTED_POLY),
            i,
        };
    }
    table.sort_by(|x, y| x.p.cmp(&y.p).then(x.i.cmp(&y.i)));

    let q = gf32_pow(0xdb71_0641, r, CRC32_REFLECTED_POLY);
    let mut a = [0u32; 32];
    a[31] = q;
    for i in (0..31).rev() {
        a[i] = gf32_mulx(a[i + 1], CRC32_REFLECTED_POLY);
    }

    let max_j = n / r;
    let mut x = d;
    let mut res = -1;

    for j in 0..=max_j {
        let mut lo = -1;
        let mut hi = r;
        while hi - lo > 1 {
            let c = (lo + hi) >> 1;
            if table[usize::try_from(c).unwrap_or(0)].p <= x {
                lo = c;
            } else {
                hi = c;
            }
        }

        if lo >= 0 && table[usize::try_from(lo).unwrap_or(0)].p == x {
            res = table[usize::try_from(lo).unwrap_or(0)].i + r * j;
            break;
        }

        x = gf2_matrix_times_u32(&a, x);
    }

    res
}

pub(super) fn crc32_repair_bit_impl(input: &mut [u8], k: i32) -> i32 {
    if k < 0 {
        return -1;
    }

    let l = i32::try_from(input.len()).unwrap_or(i32::MAX);
    let idx = k >> 5;
    let mut bit = k & 31;
    let mut i = (l - 1) - (idx - 1) * 4;
    while bit >= 8 {
        i -= 1;
        bit -= 8;
    }

    if i < 0 {
        return -2;
    }
    if i >= l {
        return -3;
    }

    let j = 7 - bit;
    if let Ok(pos) = usize::try_from(i) {
        input[pos] ^= 1u8 << j;
        return 0;
    }
    -3
}

pub(super) fn compute_crc32_for_block(data: &[u8]) -> u32 {
    crc32_partial_impl(data, u32::MAX) ^ u32::MAX
}

pub(super) fn crc32_check_and_repair_impl(input: &mut [u8], input_crc32: &mut u32) -> i32 {
    let computed_crc32 = compute_crc32_for_block(input);
    let crc32_diff = computed_crc32 ^ *input_crc32;
    if crc32_diff == 0 {
        return 0;
    }

    let bit =
        crc32_find_corrupted_bit_impl(i32::try_from(input.len()).unwrap_or(i32::MAX), crc32_diff);
    let repaired = crc32_repair_bit_impl(input, bit);
    if repaired == 0 {
        debug_assert_eq!(compute_crc32_for_block(input), *input_crc32);
        return 1;
    }

    if (crc32_diff & crc32_diff.wrapping_sub(1)) == 0 {
        *input_crc32 = computed_crc32;
        return 2;
    }

    *input_crc32 = computed_crc32;
    -1
}

pub(super) fn u32_bits_to_i32(v: u32) -> i32 {
    i32::from_ne_bytes(v.to_ne_bytes())
}
