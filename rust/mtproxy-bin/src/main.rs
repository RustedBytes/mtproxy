fn main() {
    let signature = mtproxy_core::bootstrap_signature();
    let api_version = mtproxy_ffi::ffi_api_version();

    println!("{signature} (ffi_api_version={api_version})");
}
