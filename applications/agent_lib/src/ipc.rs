use crate::Error;
use zerocopy::*;

/// Generic wire-format header for all IPC channels.
///
/// `K` is the message-kind enum (e.g. `MessageKind`, `SetupMessageKind`).
/// It must satisfy zerocopy's byte-conversion bounds so that the header
/// can be read directly from an incoming byte slice.
#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout)]
#[repr(Rust, packed)]
pub struct IpcHeader<K> {
    kind: K,
    payload_len: u32,
}

/// A framed IPC message: a typed header followed by an opaque payload.
pub struct IpcMessage<K> {
    pub(crate) header: IpcHeader<K>,
    pub(crate) payload: Vec<u8>,
}

impl<K: Copy> IpcHeader<K> {
    pub(crate) fn new(kind: K, payload_len: u32) -> Self {
        Self { kind, payload_len }
    }

    pub fn get_type(&self) -> K {
        self.kind
    }

    pub fn get_len(&self) -> u32 {
        self.payload_len
    }
}

impl<K: Copy + IntoBytes + Immutable> IpcMessage<K> {
    /// Build a message from a kind tag and a pre-serialized payload.
    pub fn new(kind: K, payload: Vec<u8>) -> Self {
        let header = IpcHeader::new(kind, payload.len() as u32);
        Self { header, payload }
    }

    /// Build a message that carries no payload (e.g. a keygen trigger).
    pub fn no_payload(kind: K) -> Self {
        Self::new(kind, Vec::new())
    }

    pub fn get_header(&self) -> &IpcHeader<K> {
        &self.header
    }

    pub fn get_payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn into_bytes(self) -> Vec<u8> {
        let mut buffer = self.header.as_bytes().to_vec();
        buffer.extend(self.payload);
        buffer
    }
}

impl<K> TryFrom<&[u8]> for IpcMessage<K>
where
    K: Copy + IntoBytes + TryFromBytes + KnownLayout + Immutable,
{
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (header, rest) =
            IpcHeader::<K>::try_read_from_prefix(value)?;
        let payload_len = header.get_len() as usize;
        let payload = rest
            .split_at_checked(payload_len)
            .ok_or(Error::MalformedMessage)?
            .0
            .to_vec();
        Ok(Self { header, payload })
    }
}
