use std::error::Error;
use std::fmt;

#[derive(Debug, Clone)]
pub enum Errors {
    UnreachableNode,
    Disconnect(u8),
    EIP8Error,
    TimeOut,
    UnreadablePayload(Vec<u8>),
    UnknownError,
}

impl fmt::Display for Errors {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Errors::UnreachableNode => write!(f, "Unreachable node"),
            Errors::Disconnect(reason) => write!(f, "node disconnected (reason {})", reason),
            Errors::EIP8Error => write!(f, "EIP8 error"),
            Errors::TimeOut => write!(f, "Time Out error"),
            Errors::UnreadablePayload(payload) => {
                write!(f, "Couldn't read payload {}", hex::encode(payload))
            }
            Errors::UnknownError => write!(f, "Unknown error"),
        }
    }
}

impl Error for Errors {}
