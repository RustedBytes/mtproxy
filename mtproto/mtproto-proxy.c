/*
    Thin compatibility shim: Rust FFI owns MTProxy runtime state and bootstrap.
*/

#include "rust/mtproxy-ffi/include/mtproxy_ffi.h"

int main(int argc, char *argv[]) {
  return mtproxy_ffi_mtproto_legacy_main(argc, argv);
}
