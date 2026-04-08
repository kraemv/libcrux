use crate::Error;
use crate::ID;
use zerocopy::*;
use crate::signing_messages::*;
use crate::kex_messages::*;

#[derive(PartialEq, Eq, IntoBytes, TryFromBytes, Immutable, KnownLayout, Unaligned)]
#[repr(u8)]
pub enum MessageKind {
    EcDsaP256Sign,
    Ed25519Sign,
    Export,
    MlKem768KeyGen,
    MlKem768Decaps,
    MlKem768Encaps,
    X25519KeyGen,
    X25519Derive,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout)]
#[repr(Rust, packed)]
pub struct IPCMessageHeader {
    kind: MessageKind,
    response_len: u32,
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct ExportRequest {
    id: ID,
}

impl ExportRequest {
    pub fn new(id: ID) -> Self {
        Self { id }
    }

    pub fn get_id(&self) -> ID {
        self.id
    }
}

#[derive(IntoBytes, TryFromBytes, Immutable, KnownLayout)]
pub struct ExportResponse {
    shk: [u8; 32],
}

impl ExportResponse {
    pub fn new(shk: [u8; 32]) -> Self {
        Self{shk}
    }

    pub fn get_shk(&self) -> &[u8; 32] {
        &self.shk
    }
}

impl From<ExportRequest> for IPCRequest {
    fn from(request: ExportRequest) -> Self {
        let payload = request.get_id().to_vec();
        let response_len: u32 = payload.len().try_into().unwrap();
        let header = IPCMessageHeader {
            kind: MessageKind::EcDsaP256Sign,
            response_len,
        };
        Self { header, payload }
    }
}

impl From<ExportResponse> for IPCResponse {
    fn from(value: ExportResponse) -> Self {
        let payload = value.as_bytes().to_vec();
        let payload_len: u32 = payload
            .len()
            .try_into()
            .expect("Payload exceeded maximum length");
        let header = IPCMessageHeader::new(MessageKind::Export, payload_len);
        Self { header, payload }
    }
}

pub struct IPCRequest {
    header: IPCMessageHeader,
    payload: Vec<u8>,
}

pub struct IPCResponse {
    header: IPCMessageHeader,
    payload: Vec<u8>,
}

impl IPCMessageHeader {
    pub(crate) fn new(kind: MessageKind, response_len: u32) -> Self {
        Self { kind, response_len }
    }

    pub fn get_type(&self) -> &MessageKind {
        &self.kind
    }

    pub fn get_len(&self) -> u32 {
        self.response_len
    }
}

impl IPCRequest {
    pub fn get_type(&self) -> &IPCMessageHeader {
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

    pub fn x25519_keygen() -> Self {
        let header = IPCMessageHeader::new(MessageKind::X25519KeyGen, 0);
        Self {
            header,
            payload: Vec::new(),
        }
    }

    pub fn mlkem768_keygen() -> Self {
        let header = IPCMessageHeader::new(MessageKind::MlKem768KeyGen, 0);
        Self {
            header,
            payload: Vec::new(),
        }
    }
}

impl From<EcDsaP256SignRequest> for IPCRequest {
    fn from(request: EcDsaP256SignRequest) -> Self {
        let payload = Vec::<u8>::from(request);
        let response_len: u32 = payload.len().try_into().unwrap();
        let header = IPCMessageHeader {
            kind: MessageKind::EcDsaP256Sign,
            response_len,
        };
        Self { header, payload }
    }
}

impl From<Ed25519SignRequest> for IPCRequest {
    fn from(request: Ed25519SignRequest) -> Self {
        let payload = Vec::<u8>::from(request);
        let response_len: u32 = payload.len().try_into().unwrap();
        let header = IPCMessageHeader {
            kind: MessageKind::Ed25519Sign,
            response_len,
        };
        Self { header, payload }
    }
}

impl TryFrom<&[u8]> for IPCRequest {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (header, payload) =
            IPCMessageHeader::try_read_from_prefix(value).map_err(|_| Error::MalformedRequest)?;
        let payload_len = header.get_len() as usize;
        let payload = payload
            .split_at_checked(payload_len)
            .ok_or(Error::MalformedRequest)?
            .0
            .to_vec();
        Ok(Self { header, payload })
    }
}

impl IPCResponse {
    pub fn into_bytes(self) -> Vec<u8> {
        let mut buffer = self.header.as_bytes().to_vec();
        buffer.extend(self.payload);

        buffer
    }

    pub fn get_header(&self) -> &IPCMessageHeader {
        &self.header
    }

    pub fn get_payload(&self) -> &[u8] {
        &self.payload
    }
}

impl TryFrom<&[u8]> for IPCResponse {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let (header, payload) =
            IPCMessageHeader::try_read_from_prefix(value).map_err(|_| Error::MalformedRequest)?;
        let payload_len = header.get_len() as usize;
        let payload = payload
            .split_at_checked(payload_len)
            .ok_or(Error::MalformedRequest)?
            .0
            .to_vec();
        Ok(Self { header, payload })
    }
}

impl From<EcDsaP256SignResponse> for IPCResponse {
    fn from(value: EcDsaP256SignResponse) -> Self {
        let payload = value.as_bytes().to_vec();
        let payload_len: u32 = payload
            .len()
            .try_into()
            .expect("Payload exceeded maximum length");
        let header = IPCMessageHeader::new(MessageKind::EcDsaP256Sign, payload_len);
        Self { header, payload }
    }
}

impl From<Ed25519SignResponse> for IPCResponse {
    fn from(value: Ed25519SignResponse) -> Self {
        let payload = value.as_bytes().to_vec();
        let payload_len: u32 = payload
            .len()
            .try_into()
            .expect("Payload exceeded maximum length");
        let header = IPCMessageHeader::new(MessageKind::Ed25519Sign, payload_len);
        Self { header, payload }
    }
}

// MlKem768KeyGen
impl From<MlKem768KeyGenResponse> for IPCResponse {
    fn from(value: MlKem768KeyGenResponse) -> Self {
        let payload = value.as_bytes().to_vec();
        let payload_len: u32 = payload
            .len()
            .try_into()
            .expect("Payload exceeded maximum length");
        let header = IPCMessageHeader::new(MessageKind::MlKem768KeyGen, payload_len);
        Self { header, payload }
    }
}

// MlKem768Decaps
impl From<MlKem768DecapsRequest> for IPCRequest {
    fn from(request: MlKem768DecapsRequest) -> Self {
        let payload = request.as_bytes().to_vec();
        let response_len: u32 = payload.len().try_into().unwrap();
        let header = IPCMessageHeader {
            kind: MessageKind::MlKem768Decaps,
            response_len,
        };
        Self { header, payload }
    }
}

impl From<MlKem768DecapsResponse> for IPCResponse {
    fn from(value: MlKem768DecapsResponse) -> Self {
        let payload = value.as_bytes().to_vec();
        let payload_len: u32 = payload
            .len()
            .try_into()
            .expect("Payload exceeded maximum length");
        let header = IPCMessageHeader::new(MessageKind::MlKem768Decaps, payload_len);
        Self { header, payload }
    }
}

// MlKem768Encaps
impl From<MlKem768EncapsRequest> for IPCRequest {
    fn from(request: MlKem768EncapsRequest) -> Self {
        let payload = request.as_bytes().to_vec();
        let response_len: u32 = payload.len().try_into().unwrap();
        let header = IPCMessageHeader {
            kind: MessageKind::MlKem768Encaps,
            response_len,
        };
        Self { header, payload }
    }
}

impl From<MlKem768EncapsResponse> for IPCResponse {
    fn from(value: MlKem768EncapsResponse) -> Self {
        let payload = value.as_bytes().to_vec();
        let payload_len: u32 = payload
            .len()
            .try_into()
            .expect("Payload exceeded maximum length");
        let header = IPCMessageHeader::new(MessageKind::MlKem768Encaps, payload_len);
        Self { header, payload }
    }
}

// X25519KeyGen
impl From<X25519KeyGenResponse> for IPCResponse {
    fn from(value: X25519KeyGenResponse) -> Self {
        let payload = value.as_bytes().to_vec();
        let payload_len: u32 = payload
            .len()
            .try_into()
            .expect("Payload exceeded maximum length");
        let header = IPCMessageHeader::new(MessageKind::X25519KeyGen, payload_len);
        Self { header, payload }
    }
}

// X25519Derive
impl From<X25519DeriveRequest> for IPCRequest {
    fn from(request: X25519DeriveRequest) -> Self {
        let payload = request.as_bytes().to_vec();
        let response_len: u32 = payload.len().try_into().unwrap();
        let header = IPCMessageHeader {
            kind: MessageKind::X25519Derive,
            response_len,
        };
        Self { header, payload }
    }
}

impl From<X25519DeriveResponse> for IPCResponse {
    fn from(value: X25519DeriveResponse) -> Self {
        let payload = value.as_bytes().to_vec();
        let payload_len: u32 = payload
            .len()
            .try_into()
            .expect("Payload exceeded maximum length");
        let header = IPCMessageHeader::new(MessageKind::X25519Derive, payload_len);
        Self { header, payload }
    }
}