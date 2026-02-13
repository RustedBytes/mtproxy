pub(crate) const RPC_INVOKE_REQ: i32 = 0x2374_df3d;
pub(crate) const RPC_REQ_RESULT: i32 = 0x63ae_da4e;

pub(crate) const TCP_RPC_PACKET_LEN_STATE_SKIP: i32 = 0;
pub(crate) const TCP_RPC_PACKET_LEN_STATE_READY: i32 = 1;
pub(crate) const TCP_RPC_PACKET_LEN_STATE_INVALID: i32 = -1;
pub(crate) const TCP_RPC_PACKET_LEN_STATE_SHORT: i32 = -2;

pub(crate) const EVT_SPEC: u32 = 1;
pub(crate) const EVT_WRITE: u32 = 2;
pub(crate) const EVT_READ: u32 = 4;
pub(crate) const EVT_LEVEL: u32 = 8;
pub(crate) const EVT_FROM_EPOLL: u32 = 0x400;

pub(crate) const EPOLLIN: u32 = 0x001;
pub(crate) const EPOLLPRI: u32 = 0x002;
pub(crate) const EPOLLOUT: u32 = 0x004;
pub(crate) const EPOLLERR: u32 = 0x008;
pub(crate) const EPOLLRDHUP: u32 = 0x2000;
pub(crate) const EPOLLET: u32 = 0x8000_0000;
