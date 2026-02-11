fn main() {
    let signature = mtproxy_core::bootstrap_signature();
    let api_version = mtproxy_ffi::ffi_api_version();
    let remaining_c_units = mtproxy_core::step15::step15_remaining_c_units();

    println!(
        "{signature} (ffi_api_version={api_version}, step15_remaining_c_units={remaining_c_units})"
    );
}
