mod core;
pub(crate) mod ffi;

pub(crate) fn usage_or_exit() -> ! {
    core::usage();
    panic!("mtproto usage unexpectedly returned");
}
