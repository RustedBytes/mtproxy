use mtproxy_core::runtime::config::tl_parse;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TlParseError {
    pub(crate) errnum: i32,
    pub(crate) message: String,
}

impl From<tl_parse::TlError> for TlParseError {
    fn from(value: tl_parse::TlError) -> Self {
        Self {
            errnum: value.errnum,
            message: value.message,
        }
    }
}

pub(crate) fn parse_query_header(data: &[u8]) -> Result<tl_parse::TlParsedHeader, TlParseError> {
    tl_parse::parse_query_header(data).map_err(Into::into)
}

pub(crate) fn parse_answer_header(data: &[u8]) -> Result<tl_parse::TlParsedHeader, TlParseError> {
    tl_parse::parse_answer_header(data).map_err(Into::into)
}
