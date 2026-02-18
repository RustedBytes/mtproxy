mod core;
pub(crate) mod ffi;

pub(crate) unsafe fn usage_or_exit() -> ! {
    unsafe { core::usage() };
    panic!("mtproto usage unexpectedly returned");
}
